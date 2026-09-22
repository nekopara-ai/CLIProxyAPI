package helps

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

type codexAdaptiveRoundTripFunc func(*http.Request) (*http.Response, error)

func (f codexAdaptiveRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func adaptiveTurnTicketTestConfig() (*cliproxyauth.Auth, CodexTurnTicketConfig, *CodexTurnTicketProcess) {
	cfg := turnTicketTestConfig()
	adaptive := true
	cfg.Codex.TurnTicket.AdaptiveInjection = &adaptive
	cfg.Codex.TurnTicket.RoutingCookieTTLSeconds = 180
	cfg.Codex.TurnTicket.RoutingRefreshBeforeSeconds = 30
	cfg.Codex.TurnTicket.RoutingProbeIntervalSeconds = 15
	cfg.Codex.TurnTicket.HarvestAttempts = 1
	auth := turnTicketTestAuth("adaptive-auth")
	process := ConfigureCodexTurnTickets(func() *config.Config { return cfg }, func() []*cliproxyauth.Auth { return []*cliproxyauth.Auth{auth} })
	return auth, EffectiveCodexTurnTicketConfig(cfg), process
}

func adaptiveRoutingBundle(t *testing.T, store *CodexTurnTicketStore, auth *cliproxyauth.Auth, model string, effective CodexTurnTicketConfig, cookieValue string) *CodexTurnTicket {
	t.Helper()
	now := time.Now()
	ticket := NewCodexTurnTicket(testTurnState(t, now.Unix(), codexTurnTicketTargetLength(auth, effective)), now, time.Duration(effective.TTLSeconds)*time.Second)
	if ticket == nil {
		t.Fatal("failed to create adaptive ticket fixture")
	}
	ticket.RoutingCookies = []CodexRoutingCookie{{Name: "__cflb", Value: cookieValue, ExpiresAt: now.Add(2 * time.Minute)}}
	ticket.RoutingCapturedAt = now
	ticket.RoutingValidatedAt = now
	ticket.RoutingExpiresAt = now.Add(2 * time.Minute)
	ticket.RoutingContext = codexRoutingContext(auth, effective)
	route := store.route(auth, model, effective)
	if route.Mode != codexRouteInject || !store.publishAdaptive(auth, model, route, ticket) {
		t.Fatalf("failed to publish adaptive fixture in route %+v", route)
	}
	return ticket
}

func TestCodexAdaptiveResponseTransitionsAndInjection(t *testing.T) {
	auth, effective, process := adaptiveTurnTicketTestConfig()
	t.Cleanup(func() { ConfigureCodexTurnTickets(nil, nil) })
	model := "gpt-5.5"

	if CodexTurnTicketAllowsExecution(auth, model) {
		t.Fatal("an unclassified adaptive bucket must fail closed")
	}
	healthy := http.Header{CodexTurnStateHeader: []string{testTurnState(t, time.Now().Unix(), 292)}}
	ObserveCodexTurnTicketResponse(auth, model, http.StatusOK, healthy, http.Header{"X-Request-ID": []string{"clean"}}, false)
	if route := process.Store.route(auth, model, effective); route.Mode != codexRouteDirect {
		t.Fatalf("clean healthy response route = %+v, want direct", route)
	}
	if !CodexTurnTicketAllowsExecution(auth, model) {
		t.Fatal("direct classification did not admit business traffic")
	}
	if ApplyCodexTurnTicket(auth, model, http.Header{}) {
		t.Fatal("direct classification unexpectedly injected a bundle")
	}
	degraded := http.Header{CodexTurnStateHeader: []string{testTurnState(t, time.Now().Unix(), 312)}}
	ObserveCodexTurnTicketResponse(auth, model, http.StatusTooManyRequests, degraded, http.Header{}, false)
	if route := process.Store.route(auth, model, effective); route.Mode != codexRouteDirect {
		t.Fatalf("429 response toggled adaptive route to %+v", route)
	}

	ObserveCodexTurnTicketResponse(auth, model, http.StatusOK, degraded, http.Header{}, false)
	if route := process.Store.route(auth, model, effective); route.Mode != codexRouteInject {
		t.Fatalf("degraded response route = %+v, want inject", route)
	}
	if CodexTurnTicketAllowsExecution(auth, model) {
		t.Fatal("inject route without a validated bundle must fail closed")
	}

	// A clean request that started before the degraded response may finish later. Its
	// healthy response must not disable injection once degradation has been observed.
	ObserveCodexTurnTicketResponse(auth, model, http.StatusOK, healthy, http.Header{}, false)
	if route := process.Store.route(auth, model, effective); route.Mode != codexRouteInject {
		t.Fatalf("late clean response changed route to %+v", route)
	}

	first := adaptiveRoutingBundle(t, process.Store, auth, model, effective, "route-a")
	request := http.Header{"cookie": []string{"user_pref=dark; __cflb=spoofed; __oailb=stale"}, "x-codex-turn-state": []string{"client-state"}}
	if !ApplyCodexTurnTicket(auth, model, request) {
		t.Fatal("validated inject route did not apply its bundle")
	}
	if got := codexHeaderValue(request, CodexTurnStateHeader); got != first.State {
		t.Fatalf("injected state mismatch: len=%d", len(got))
	}
	wantCookies := map[string]string{"user_pref": "dark", "__cflb": "route-a"}
	for _, cookie := range codexRequestCookies(request) {
		want, ok := wantCookies[cookie.Name]
		if !ok || cookie.Value != want {
			t.Fatalf("unexpected injected cookie %q", cookie.Name)
		}
		delete(wantCookies, cookie.Name)
	}
	if len(wantCookies) != 0 {
		t.Fatalf("missing cookies after injection: %v", wantCookies)
	}

	ObserveCodexTurnTicketResponse(auth, model, http.StatusOK, healthy, request.Clone(), true)
	if got := process.Store.Lookup(auth.ID, model); got == nil || got.RoutingValidatedAt != first.RoutingValidatedAt {
		t.Fatal("successful injected traffic changed or renewed the fixed routing lease")
	}
	ObserveCodexTurnTicketResponse(auth, model, http.StatusOK, degraded, request.Clone(), true)
	if process.Store.Lookup(auth.ID, model) != nil || CodexTurnTicketAllowsExecution(auth, model) {
		t.Fatal("matching injected 312 did not invalidate the active bundle")
	}

	second := adaptiveRoutingBundle(t, process.Store, auth, model, effective, "route-b")
	ObserveCodexTurnTicketResponse(auth, model, http.StatusOK, degraded, request.Clone(), true)
	if got := process.Store.Lookup(auth.ID, model); got == nil || got.RoutingCookies[0].Value != second.RoutingCookies[0].Value {
		t.Fatal("late 312 from an older injected request invalidated the replacement")
	}
	snapshotJSON, err := json.Marshal(SnapshotCodexTurnTickets())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(snapshotJSON), second.State) || strings.Contains(string(snapshotJSON), "route-b") {
		t.Fatal("management snapshot leaked ticket or routing-cookie material")
	}
}

func TestCodexAdaptiveRoutingCookiesAreAllowlistedAndCaseSafe(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	cfg := turnTicketTestConfig()
	adaptive := true
	cfg.Codex.TurnTicket.AdaptiveInjection = &adaptive
	effective := EffectiveCodexTurnTicketConfig(cfg)
	header := http.Header{"Set-Cookie": []string{
		"__cflb=old; Path=/; Domain=chatgpt.com; Max-Age=3600; Secure; HttpOnly",
		"session=login-secret; Path=/; Domain=chatgpt.com; Max-Age=3600",
		"__oailb=other-domain; Path=/; Domain=example.com; Max-Age=3600",
		"__cflb=; Path=/; Domain=chatgpt.com; Max-Age=0",
		"__oailb=route-o; Path=/backend-api; Domain=chatgpt.com; Max-Age=3600",
	}}
	cookies := codexRoutingCookies(header, now, effective)
	if len(cookies) != 1 || cookies[0].Name != "__oailb" || cookies[0].Value != "route-o" {
		t.Fatalf("allowlisted cookies = %#v, want only __oailb", cookies)
	}
	if want := now.Add(180 * time.Second); !cookies[0].ExpiresAt.Equal(want) {
		t.Fatalf("local cookie lease = %s, want %s", cookies[0].ExpiresAt, want)
	}

	request := http.Header{"cOoKiE": []string{"theme=dark; __cflb=old; __oailb=old-o"}}
	setCodexRoutingCookies(request, cookies)
	got := map[string]string{}
	for _, cookie := range codexRequestCookies(request) {
		got[cookie.Name] = cookie.Value
	}
	if len(got) != 2 || got["theme"] != "dark" || got["__oailb"] != "route-o" {
		t.Fatalf("case-insensitive cookie replacement = %#v", got)
	}
}

func TestEffectiveCodexAdaptiveConfigDefaultsAndCaps(t *testing.T) {
	cfg := turnTicketTestConfig()
	adaptive := true
	cfg.Codex.TurnTicket.AdaptiveInjection = &adaptive
	cfg.Codex.TurnTicket.RoutingCookieTTLSeconds = 999
	cfg.Codex.TurnTicket.RoutingRefreshBeforeSeconds = 999
	cfg.Codex.TurnTicket.RoutingProbeIntervalSeconds = 999
	cfg.Codex.TurnTicket.HarvestAttempts = 99
	effective := EffectiveCodexTurnTicketConfig(cfg)
	if !effective.AdaptiveInjection || effective.RoutingCookieTTLSeconds != 180 || effective.RoutingRefreshBeforeSeconds != 90 || effective.RoutingProbeIntervalSeconds != 45 || effective.HarvestAttempts != 8 {
		t.Fatalf("adaptive caps = %+v", effective)
	}

	cfg.Codex.TurnTicket.RoutingCookieTTLSeconds = 0
	cfg.Codex.TurnTicket.RoutingRefreshBeforeSeconds = 0
	cfg.Codex.TurnTicket.RoutingProbeIntervalSeconds = 0
	cfg.Codex.TurnTicket.HarvestAttempts = 0
	effective = EffectiveCodexTurnTicketConfig(cfg)
	if effective.RoutingCookieTTLSeconds != 180 || effective.RoutingRefreshBeforeSeconds != 30 || effective.RoutingProbeIntervalSeconds != 15 || effective.HarvestAttempts != 3 {
		t.Fatalf("adaptive defaults = %+v", effective)
	}
}

func TestCodexAdaptiveRestartDoesNotTrustPersistedRoutingBundle(t *testing.T) {
	cfg := turnTicketTestConfig()
	adaptive := true
	cfg.Codex.TurnTicket.AdaptiveInjection = &adaptive
	effective := EffectiveCodexTurnTicketConfig(cfg)
	auth := turnTicketTestAuth("restart-auth")
	model := "gpt-5.5"
	path := filepath.Join(t.TempDir(), "tickets")
	store := NewPersistentCodexTurnTicketStore(path, 292, time.Hour)
	store.setRoute(auth, model, effective, codexRouteInject, false)
	adaptiveRoutingBundle(t, store, auth, model, effective, "persisted-route")

	restarted := NewPersistentCodexTurnTicketStore(path, 292, time.Hour)
	route, ticket := restarted.adaptiveSnapshot(auth, model, effective)
	if route.Mode != codexRouteUnknown {
		t.Fatalf("restart route = %+v, want unknown", route)
	}
	if ticket == nil || len(ticket.RoutingCookies) != 0 || restarted.adaptiveAllows(auth, model, effective, time.Now()) {
		t.Fatalf("restart trusted persisted routing bundle: ticket=%+v", ticket)
	}
}

func TestCodexAdaptiveAuthInvalidationClearsDirectRoute(t *testing.T) {
	auth, effective, process := adaptiveTurnTicketTestConfig()
	t.Cleanup(func() { ConfigureCodexTurnTickets(nil, nil) })
	model := "gpt-5.5"
	healthy := http.Header{CodexTurnStateHeader: []string{testTurnState(t, time.Now().Unix(), 292)}}
	ObserveCodexTurnTicketResponse(auth, model, http.StatusOK, healthy, http.Header{}, false)
	if process.Store.route(auth, model, effective).Mode != codexRouteDirect {
		t.Fatal("fixture did not reach direct mode")
	}
	InvalidateCodexTurnTicketsForAuth(auth.ID)
	if route := process.Store.route(auth, model, effective); route.Mode != codexRouteUnknown || CodexTurnTicketAllowsExecution(auth, model) {
		t.Fatalf("auth invalidation left route=%+v executable", route)
	}
}

func TestCodexAdaptiveCooldownCannotHideConcurrentDegradation(t *testing.T) {
	auth, effective, process := adaptiveTurnTicketTestConfig()
	t.Cleanup(func() { ConfigureCodexTurnTickets(nil, nil) })
	model := "gpt-5.5"
	direct := process.Store.setRoute(auth, model, effective, codexRouteDirect, true)
	process.Store.markAdaptiveDegraded(auth, model, effective, http.Header{}, false)
	process.Harvester.wakeAdaptive(auth.ID, model)
	process.Harvester.setAdaptiveCooldown(auth, model, effective, direct, time.Now().Add(time.Hour))
	if !process.Harvester.reserveProbeSlot(auth.ID, model, time.Now(), effective) {
		t.Fatal("a stale direct result suppressed the immediate degradation probe")
	}
}

func TestCodexAdaptiveBundleIsolationAndFixedLease(t *testing.T) {
	auth, effective, process := adaptiveTurnTicketTestConfig()
	t.Cleanup(func() { ConfigureCodexTurnTickets(nil, nil) })
	model := "gpt-5.5"
	process.Store.setRoute(auth, model, effective, codexRouteInject, true)
	ticket := adaptiveRoutingBundle(t, process.Store, auth, model, effective, "isolated-cookie")
	if !ticket.routingValid(auth, effective, ticket.RoutingExpiresAt.Add(-6*time.Second)) || ticket.routingValid(auth, effective, ticket.RoutingExpiresAt.Add(-5*time.Second)) {
		t.Fatal("routing lease did not enforce the five-second preparation margin")
	}
	for _, change := range []string{"auth", "workspace", "egress", "policy"} {
		other := auth.Clone()
		switch change {
		case "auth":
			other.ID = "other-auth"
		case "workspace":
			other.Metadata["account_id"] = "different-workspace"
		case "egress":
			other.ProxyURL = "direct"
		case "policy":
			other.Metadata[CodexTurnTicketPlanField] = "team"
		}
		if process.Store.adaptiveAllows(other, model, effective, time.Now()) || process.Injector.Apply(other, model, http.Header{}) {
			t.Fatalf("bundle crossed the %s boundary", change)
		}
	}
	if process.Injector.Apply(auth, "different-model", http.Header{}) {
		t.Fatal("bundle crossed the model boundary")
	}
	// Returned snapshots are copies: callers cannot mutate the stored cookie slice.
	copyTicket := process.Store.Lookup(auth.ID, model)
	copyTicket.RoutingCookies[0].Value = "changed-outside-store"
	if process.Store.Lookup(auth.ID, model).RoutingCookies[0].Value != "isolated-cookie" {
		t.Fatal("Lookup returned an aliased cookie slice")
	}
}

func TestCodexAdaptiveRejectsUnvalidatedCandidates(t *testing.T) {
	for _, failure := range []string{"missing-cookie", "wrong-model", "failed-sse", "degraded-validation", "reissued-ticket", "rejected-business"} {
		t.Run(failure, func(t *testing.T) {
			cfg := turnTicketTestConfig()
			cfg.Codex.TurnTicket.AdaptiveInjection = nil
			cfg.Codex.TurnTicket.HarvestAttempts = 2
			effective := EffectiveCodexTurnTicketConfig(cfg)
			auth := turnTicketTestAuth("failed-candidate")
			state := testTurnState(t, time.Now().Unix(), 292)
			degraded := testTurnState(t, time.Now().Unix(), 312)
			completed := "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"model\":\"gpt-5.5\"}}\n\n"
			original := codexTurnTicketProbeClient
			t.Cleanup(func() { codexTurnTicketProbeClient = original })
			calls, harvests := 0, 0
			codexTurnTicketProbeClient = func(_ context.Context, _ *cliproxyauth.Auth, egress string, _ time.Duration) (*http.Client, error) {
				return &http.Client{Transport: codexAdaptiveRoundTripFunc(func(req *http.Request) (*http.Response, error) {
					calls++
					header := http.Header{}
					status, body := http.StatusOK, completed
					switch {
					case calls == 1:
						header.Set(CodexTurnStateHeader, degraded)
						if failure == "rejected-business" {
							status = http.StatusTooManyRequests
						}
					case egress == effective.HarvestProxyURLs[0]:
						harvests++
						header.Set(CodexTurnStateHeader, state)
						if failure != "missing-cookie" {
							header.Add("Set-Cookie", "__cflb=candidate; Path=/; Max-Age=3600")
						}
					default:
						switch failure {
						case "wrong-model":
							body = strings.ReplaceAll(body, "gpt-5.5", "gpt-5.6-luna")
						case "failed-sse":
							body = "data: {\"type\":\"response.failed\"}\n\n"
						case "degraded-validation":
							header.Set(CodexTurnStateHeader, degraded)
						case "reissued-ticket":
							header.Set(CodexTurnStateHeader, testTurnState(t, time.Now().Add(-time.Minute).Unix(), 292))
						}
					}
					return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
				})}, nil
			}
			store := NewCodexTurnTicketStore()
			h := NewCodexTurnTicketHarvester(store, func() *config.Config { return cfg }, func() []*cliproxyauth.Auth { return []*cliproxyauth.Auth{auth} })
			h.probeAdaptive(context.Background(), auth, "gpt-5.5", effective)
			if store.Lookup(auth.ID, "gpt-5.5") != nil || store.adaptiveAllows(auth, "gpt-5.5", effective, time.Now()) {
				t.Fatal("an unvalidated candidate became executable")
			}
			if failure == "rejected-business" {
				if calls != 1 || h.reserveProbeSlot(auth.ID, "gpt-5.5", time.Now().Add(time.Minute), effective) || store.route(auth, "gpt-5.5", effective).Mode != codexRouteUnknown {
					t.Fatal("rejection toggled injection or did not preserve backoff")
				}
			} else if harvests != effective.HarvestAttempts {
				t.Fatalf("harvest attempts=%d, want bounded %d", harvests, effective.HarvestAttempts)
			}
		})
	}
}

func TestCodexRoutingCompletedModelRequiresCompleteSSE(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantModel string
		wantOK    bool
	}{
		{name: "completed", body: ": keepalive\n\nevent: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"status\":\"in_progress\"}}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"model\":\"gpt-5.5\"}}\n\ndata: [DONE]\n\n", wantModel: "gpt-5.5", wantOK: true},
		{name: "crlf", body: "event: response.completed\r\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"model\":\"gpt-5.5\"}}\r\n\r\n", wantModel: "gpt-5.5", wantOK: true},
		{name: "failed", body: "event: response.failed\ndata: {\"type\":\"response.failed\",\"response\":{\"status\":\"failed\",\"model\":\"gpt-5.5\"}}\n\n"},
		{name: "incomplete", body: "event: response.incomplete\ndata: {\"type\":\"response.incomplete\",\"response\":{\"status\":\"incomplete\",\"model\":\"gpt-5.5\"}}\n\n"},
		{name: "wrong status", body: "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"failed\",\"model\":\"gpt-5.5\"}}\n\n"},
		{name: "missing model", body: "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}\n\n"},
		{name: "mismatched event", body: "event: response.completed\ndata: {\"type\":\"response.failed\",\"response\":{\"status\":\"completed\",\"model\":\"gpt-5.5\"}}\n\n"},
		{name: "malformed", body: "event: response.completed\ndata: {\n\n"},
		{name: "truncated", body: "event: response.completed\ndata: {\"type\":\"response.completed\""},
		{name: "duplicate", body: "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"model\":\"gpt-5.5\"}}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"model\":\"gpt-5.5\"}}\n\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			model, ok := codexRoutingCompletedModel([]byte(tc.body))
			if model != tc.wantModel || ok != tc.wantOK {
				t.Fatalf("result = (%q, %v), want (%q, %v)", model, ok, tc.wantModel, tc.wantOK)
			}
		})
	}
}

func TestCodexAdaptiveProbeUsesBusinessThenValidatedFallback(t *testing.T) {
	cfg := turnTicketTestConfig()
	adaptive := true
	cfg.Codex.TurnTicket.AdaptiveInjection = &adaptive
	cfg.Codex.TurnTicket.HarvestAttempts = 1
	cfg.ProxyURL = "business-egress"
	cfg.Codex.TurnTicket.HarvestProxyURLs = []string{"harvest-egress"}
	effective := EffectiveCodexTurnTicketConfig(cfg)
	auth := turnTicketTestAuth("adaptive-probe")
	model := "gpt-5.5"
	healthyState := testTurnState(t, time.Now().Unix(), 292)
	degradedState := testTurnState(t, time.Now().Unix(), 312)
	completed := "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"model\":\"gpt-5.5\"}}\n\n"

	originalClient := codexTurnTicketProbeClient
	t.Cleanup(func() { codexTurnTicketProbeClient = originalClient })
	var mu sync.Mutex
	var egresses []string
	var validationHeader http.Header
	codexTurnTicketProbeClient = func(_ context.Context, _ *cliproxyauth.Auth, egress string, _ time.Duration) (*http.Client, error) {
		mu.Lock()
		index := len(egresses)
		egresses = append(egresses, egress)
		mu.Unlock()
		return &http.Client{Transport: codexAdaptiveRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			header := make(http.Header)
			body := ""
			switch index {
			case 0:
				header.Set(CodexTurnStateHeader, degradedState)
			case 1:
				header.Set(CodexTurnStateHeader, healthyState)
				header.Add("Set-Cookie", "__cflb=route-a; Path=/; Domain=chatgpt.com; Max-Age=3600; Secure; HttpOnly")
				header.Add("Set-Cookie", "session=must-not-propagate; Path=/; Domain=chatgpt.com; Max-Age=3600")
				body = completed
			case 2:
				validationHeader = req.Header.Clone()
				body = completed
			default:
				t.Fatalf("unexpected adaptive probe call %d", index)
			}
			return &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
		})}, nil
	}

	store := NewCodexTurnTicketStore()
	harvester := NewCodexTurnTicketHarvester(store, func() *config.Config { return cfg }, func() []*cliproxyauth.Auth { return []*cliproxyauth.Auth{auth} })
	harvester.probeAdaptive(context.Background(), auth, model, effective)
	if len(egresses) != 3 || egresses[0] != "business-egress" || egresses[1] != "harvest-egress" || egresses[2] != "business-egress" {
		t.Fatalf("probe egress order = %#v", egresses)
	}
	if codexHeaderValue(validationHeader, CodexTurnStateHeader) != healthyState {
		t.Fatal("business validation did not replay the acquired healthy ticket")
	}
	validationCookies := map[string]string{}
	for _, cookie := range codexRequestCookies(validationHeader) {
		validationCookies[cookie.Name] = cookie.Value
	}
	if len(validationCookies) != 1 || validationCookies["__cflb"] != "route-a" {
		t.Fatalf("business validation cookies = %#v", validationCookies)
	}
	route, ticket := store.adaptiveSnapshot(auth, model, effective)
	if route.Mode != codexRouteInject || !ticket.routingValid(auth, effective, time.Now()) {
		t.Fatalf("validated route = %+v ticket=%+v", route, ticket)
	}
	if names := codexRoutingCookieNames(ticket); len(names) != 1 || names[0] != "__cflb" {
		t.Fatalf("stored cookie names = %#v", names)
	}
}

func TestCodexAdaptiveProbeKeepsNaturalHealthyTrafficClean(t *testing.T) {
	cfg := turnTicketTestConfig()
	adaptive := true
	cfg.Codex.TurnTicket.AdaptiveInjection = &adaptive
	cfg.ProxyURL = "business-egress"
	cfg.Codex.TurnTicket.HarvestProxyURLs = []string{"unused-harvest"}
	effective := EffectiveCodexTurnTicketConfig(cfg)
	auth := turnTicketTestAuth("adaptive-direct")
	model := "gpt-5.5"
	healthyState := testTurnState(t, time.Now().Unix(), 292)
	completed := "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"model\":\"gpt-5.5\"}}\n\n"

	originalClient := codexTurnTicketProbeClient
	t.Cleanup(func() { codexTurnTicketProbeClient = originalClient })
	var calls int
	codexTurnTicketProbeClient = func(_ context.Context, _ *cliproxyauth.Auth, egress string, _ time.Duration) (*http.Client, error) {
		calls++
		if egress != "business-egress" {
			t.Fatalf("natural probe used egress %q", egress)
		}
		return &http.Client{Transport: codexAdaptiveRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{CodexTurnStateHeader: []string{healthyState}}, Body: io.NopCloser(strings.NewReader(completed)), Request: req}, nil
		})}, nil
	}

	store := NewCodexTurnTicketStore()
	harvester := NewCodexTurnTicketHarvester(store, func() *config.Config { return cfg }, func() []*cliproxyauth.Auth { return []*cliproxyauth.Auth{auth} })
	harvester.probeAdaptive(context.Background(), auth, model, effective)
	route, ticket := store.adaptiveSnapshot(auth, model, effective)
	if calls != 1 || route.Mode != codexRouteDirect || ticket != nil || !store.adaptiveAllows(auth, model, effective, time.Now()) {
		t.Fatalf("natural route calls=%d route=%+v ticket=%+v", calls, route, ticket)
	}
}

func TestCodexAdaptiveSlowProbeCannotOverwriteLiveDegradation(t *testing.T) {
	cfg := turnTicketTestConfig()
	adaptive := true
	cfg.Codex.TurnTicket.AdaptiveInjection = &adaptive
	cfg.ProxyURL = "business-egress"
	effective := EffectiveCodexTurnTicketConfig(cfg)
	auth := turnTicketTestAuth("adaptive-race")
	model := "gpt-5.5"
	healthyState := testTurnState(t, time.Now().Unix(), 292)
	completed := "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"model\":\"gpt-5.5\"}}\n\n"

	originalClient := codexTurnTicketProbeClient
	t.Cleanup(func() { codexTurnTicketProbeClient = originalClient })
	started := make(chan struct{})
	release := make(chan struct{})
	codexTurnTicketProbeClient = func(_ context.Context, _ *cliproxyauth.Auth, _ string, _ time.Duration) (*http.Client, error) {
		return &http.Client{Transport: codexAdaptiveRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			close(started)
			<-release
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{CodexTurnStateHeader: []string{healthyState}}, Body: io.NopCloser(strings.NewReader(completed)), Request: req}, nil
		})}, nil
	}

	store := NewCodexTurnTicketStore()
	harvester := NewCodexTurnTicketHarvester(store, func() *config.Config { return cfg }, func() []*cliproxyauth.Auth { return []*cliproxyauth.Auth{auth} })
	done := make(chan struct{})
	go func() {
		harvester.probeAdaptive(context.Background(), auth, model, effective)
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("business probe did not start")
	}
	if !store.markAdaptiveDegraded(auth, model, effective, http.Header{}, false) {
		t.Fatal("failed to record live degradation")
	}
	close(release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("business probe did not finish")
	}
	if route := store.route(auth, model, effective); route.Mode != codexRouteInject {
		t.Fatalf("slow healthy probe overwrote live degradation: %+v", route)
	}
}
