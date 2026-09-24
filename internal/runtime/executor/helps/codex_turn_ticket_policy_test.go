package helps

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"gopkg.in/yaml.v3"
)

func policyTestConfig(t *testing.T, extra string) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	text := "codex:\n  turn-ticket:\n    enabled: true\n    gateway-mint: false\n    models: [gpt-5.5]\n    harvest-attempts: 1\n    harvest-proxy-urls: [http://pool.invalid]\n" + extra
	if err := yaml.Unmarshal([]byte(text), cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestCodexPolicyFourIndependentLengths(t *testing.T) {
	cfg := policyTestConfig(t, "")
	effective := EffectiveCodexTurnTicketConfig(cfg)
	for _, plan := range []string{"pro", "team"} {
		a := turnTicketTestAuth(plan)
		a.Metadata[CodexTurnTicketPlanField] = plan
		if codexTurnTicketTargetLength(a, effective) != 780 || codexTurnTicketDegradedLength(a, effective) != 312 {
			t.Fatal("new defaults missing for " + plan)
		}
	}
	cfg = policyTestConfig(t, "    personal-healthy-length: 292\n    personal-degraded-length: 356\n    team-healthy-length: 780\n    team-degraded-length: 332\n    target-length: 900\n")
	effective = EffectiveCodexTurnTicketConfig(cfg)
	for _, tc := range []struct {
		plan              string
		healthy, degraded int
	}{{"pro", 292, 356}, {"team", 780, 332}, {"auto", 900, 356}} {
		a := turnTicketTestAuth(tc.plan)
		a.Metadata[CodexTurnTicketPlanField] = tc.plan
		if got := codexTurnTicketTargetLength(a, effective); got != tc.healthy {
			t.Fatalf("%s healthy=%d", tc.plan, got)
		}
		if got := codexTurnTicketDegradedLength(a, effective); got != tc.degraded {
			t.Fatalf("%s degraded=%d", tc.plan, got)
		}
	}
}

func TestCodexPolicyDegradedAdmissionAndHotReload(t *testing.T) {
	for _, plan := range []string{"pro", "team"} {
		t.Run(plan, func(t *testing.T) {
			cfg := policyTestConfig(t, "    fail-closed: false\n    block-on-degraded: true\n")
			a := turnTicketTestAuth(plan)
			a.Metadata[CodexTurnTicketPlanField] = plan
			p := ConfigureCodexTurnTickets(func() *config.Config { return cfg }, func() []*cliproxyauth.Auth { return []*cliproxyauth.Auth{a} })
			t.Cleanup(func() { ConfigureCodexTurnTickets(nil, nil) })
			effective := EffectiveCodexTurnTicketConfig(cfg)
			if !CodexTurnTicketAllowsExecution(a, "gpt-5.5") {
				t.Fatal("unclassified fail-open should pass")
			}
			p.Harvester.observeAdaptive(a, "gpt-5.5", 200, http.Header{CodexTurnStateHeader: []string{testTurnState(t, time.Now().Unix(), 312)}}, http.Header{}, false, effective)
			if CodexTurnTicketAllowsExecution(a, "gpt-5.5") {
				t.Fatal("degraded block must override fail-open")
			}
			no := false
			cfg.Codex.TurnTicket.BlockOnDegraded = &no
			if !CodexTurnTicketAllowsExecution(a, "gpt-5.5") {
				t.Fatal("hot switch must allow degraded mode without erasing it")
			}
			if p.Injector.Apply(a, "gpt-5.5", http.Header{}) {
				t.Fatal("fail-open fabricated injection")
			}
			yes := true
			cfg.Codex.TurnTicket.BlockOnDegraded = &yes
			ticket := adaptiveRoutingBundle(t, p.Store, a, "gpt-5.5", effective, "routing")
			if !CodexTurnTicketAllowsExecution(a, "gpt-5.5") || !p.Injector.Apply(a, "gpt-5.5", http.Header{}) {
				t.Fatal("verified bundle did not restore admission")
			}
			cfg.Codex.TurnTicket.InjectionEnabled = &no
			if CodexTurnTicketAllowsExecution(a, "gpt-5.5") {
				t.Fatal("blocked degradation cannot be protected while injection is off")
			}
			cfg.Codex.TurnTicket.InjectionEnabled = &yes
			cfg.Codex.TurnTicket.PersonalDegradedLength = 356
			cfg.Codex.TurnTicket.TeamDegradedLength = 356
			updated := EffectiveCodexTurnTicketConfig(cfg)
			if ticket.routingValid(a, updated, time.Now()) || p.Injector.Apply(a, "gpt-5.5", http.Header{}) {
				t.Fatal("old bundle survived policy reload")
			}
			if snapshot := SnapshotCodexTurnTicketForAuth(a); snapshot.TargetLength != 780 || snapshot.DegradedLength != 356 {
				t.Fatalf("stale snapshot: %+v", snapshot)
			}
			p.Harvester.parkBucket(a.ID, "gpt-5.5", time.Now().Add(time.Minute))
			p.Store.ensureAdaptiveContext(a, "gpt-5.5", updated)
			if p.Harvester.reserveProbeSlot(a.ID, "gpt-5.5", time.Now(), updated) {
				t.Fatal("policy reset bypassed rejection backoff")
			}
		})
	}
}

func TestCodexPolicyBusinessHarvestValidation(t *testing.T) {
	for _, tc := range []struct {
		name, extra           string
		status, length, calls int
		admitted              bool
	}{
		{"healthy direct", "", 200, 780, 1, true},
		{"degraded reissued accepted", "    validation-ticket-policy: healthy-or-empty\n", 200, 312, 3, true},
		{"degraded strict rejects reissue", "", 200, 312, 3, false},
		{"unknown retained", "", 200, 332, 1, false},
		{"unknown blocked", "    unknown-state-action: block\n    fail-closed: false\n", 200, 332, 1, false},
		{"unknown harvest", "    unknown-state-action: harvest\n    validation-ticket-policy: healthy-or-empty\n", 200, 332, 3, true},
		{"error retained", "", 502, 0, 1, false},
		{"error harvest", "    harvest-on-business-error: true\n    validation-ticket-policy: healthy-or-empty\n", 502, 0, 3, true},
		{"reject wins over error harvest", "    harvest-on-business-error: true\n", 429, 0, 1, false},
		{"custom reject code", "    harvest-on-business-error: true\n    reject-status-codes: [502]\n", 502, 0, 1, false},
	} {
		for _, plan := range []string{"pro", "team"} {
			t.Run(tc.name+"/"+plan, func(t *testing.T) {
				cfg := policyTestConfig(t, tc.extra)
				a := turnTicketTestAuth(plan)
				a.Metadata[CodexTurnTicketPlanField] = plan
				p := ConfigureCodexTurnTickets(func() *config.Config { return cfg }, func() []*cliproxyauth.Auth { return []*cliproxyauth.Auth{a} })
				t.Cleanup(func() { ConfigureCodexTurnTickets(nil, nil) })
				effective := EffectiveCodexTurnTicketConfig(cfg)
				original := codexTurnTicketProbeClient
				t.Cleanup(func() { codexTurnTicketProbeClient = original })
				captured := testTurnState(t, time.Now().Unix(), 780)
				reissued := testTurnState(t, time.Now().Add(-time.Second).Unix(), 780)
				calls := 0
				codexTurnTicketProbeClient = func(_ context.Context, _ *cliproxyauth.Auth, egress string, _ time.Duration) (*http.Client, error) {
					return &http.Client{Transport: codexAdaptiveRoundTripFunc(func(req *http.Request) (*http.Response, error) {
						calls++
						status := 200
						header := http.Header{}
						body := "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"model\":\"gpt-5.5\"}}\n\n"
						switch calls {
						case 1:
							status = tc.status
							if tc.length > 0 {
								header.Set(CodexTurnStateHeader, testTurnState(t, time.Now().Unix(), tc.length))
							}
							if req.Header.Get(CodexTurnStateHeader) != "" || req.Header.Get("Cookie") != "" {
								t.Fatal("first probe was injected")
							}
						case 2:
							if egress != effective.HarvestProxyURLs[0] {
								t.Fatal("wrong harvest egress")
							}
							header.Set(CodexTurnStateHeader, captured)
							header.Set("Set-Cookie", "__cflb=candidate; Path=/; Max-Age=240")
						case 3:
							if req.Header.Get(CodexTurnStateHeader) != captured || !strings.Contains(req.Header.Get("Cookie"), "__cflb=candidate") {
								t.Fatal("validation did not replay acquired bundle")
							}
							header.Set(CodexTurnStateHeader, reissued)
						default:
							t.Fatal("unexpected extra request")
						}
						return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
					})}, nil
				}
				p.Harvester.probeAdaptive(context.Background(), a, "gpt-5.5", effective)
				if calls != tc.calls {
					t.Fatalf("calls=%d want=%d", calls, tc.calls)
				}
				if got := CodexTurnTicketAllowsExecution(a, "gpt-5.5"); got != tc.admitted {
					t.Fatalf("admission=%v want=%v", got, tc.admitted)
				}
				if ticket := p.Store.Lookup(a.ID, "gpt-5.5"); ticket != nil && ticket.State != captured {
					t.Fatal("published the unvalidated reissued ticket")
				}
			})
		}
	}
}

func TestCodexPolicyCustomCookieMarginAndRestore(t *testing.T) {
	cfg := policyTestConfig(t, "    routing-cookie-names: [route_cookie]\n    routing-expiry-margin-seconds: 0\n    legacy-expiry-margin-seconds: 0\n")
	effective := EffectiveCodexTurnTicketConfig(cfg)
	now := time.Now()
	cookies := codexRoutingCookies(http.Header{"Set-Cookie": []string{"route_cookie=new; Path=/; Max-Age=200", "__cflb=ignored; Path=/; Max-Age=200"}}, now, effective)
	if len(cookies) != 1 || cookies[0].Name != "route_cookie" {
		t.Fatal("custom cookie policy ignored")
	}
	headers := http.Header{"Cookie": []string{"route_cookie=old; unrelated=keep"}}
	setCodexRoutingCookies(headers, cookies, effective)
	if strings.Contains(headers.Get("Cookie"), "old") || !strings.Contains(headers.Get("Cookie"), "unrelated=keep") {
		t.Fatal("cookie replacement incorrect")
	}
	a := turnTicketTestAuth("margin")
	ticket := NewCodexTurnTicket(testTurnState(t, now.Unix(), 780), now, time.Hour)
	ticket.RoutingCapturedAt = now
	ticket.RoutingValidatedAt = now
	ticket.RoutingExpiresAt = now.Add(time.Second)
	ticket.RoutingCookies = cookies
	ticket.RoutingContext = codexRoutingContext(a, effective)
	if !ticket.routingValid(a, effective, now) {
		t.Fatal("zero margin not honored")
	}
	effective.RoutingExpiryMarginSeconds = 5
	if ticket.routingValid(a, effective, now) {
		t.Fatal("custom margin ignored")
	}
	path := filepath.Join(t.TempDir(), "tickets")
	store := NewPersistentCodexTurnTicketStore(path, 292, time.Hour)
	store.Store(a.ID, "gpt-5.5", ticket)
	restored := NewPersistentCodexTurnTicketStore(path, 292, time.Hour)
	if restored.Lookup(a.ID, "gpt-5.5") == nil {
		t.Fatal("custom-length disk ticket was dropped by legacy length filter")
	}
	if restored.adaptiveAllows(a, "gpt-5.5", effective, now) {
		t.Fatal("disk restore activated an unclassified bundle")
	}
}

func TestCodexPolicyValidationRequirementsAndHarvestBackoff(t *testing.T) {
	for _, tc := range []struct {
		name, extra, body             string
		harvestStatus                 int
		wantBundle, wantEgressBackoff bool
	}{
		{"model mismatch strict", "", "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"model\":\"different\"}}\n\n", 200, false, false},
		{"model mismatch allowed", "    require-model-match: false\n", "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"model\":\"different\"}}\n\n", 200, true, false},
		{"header only strict", "", "", 200, false, false},
		{"header only allowed", "    require-complete-response: false\n    require-model-match: false\n", "", 200, true, false},
		{"custom acquisition rejection", "    harvest-reject-status-codes: [503]\n", "", 503, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := policyTestConfig(t, tc.extra)
			effective := EffectiveCodexTurnTicketConfig(cfg)
			a := turnTicketTestAuth(tc.name)
			store := NewCodexTurnTicketStore()
			h := NewCodexTurnTicketHarvester(store, func() *config.Config { return cfg }, func() []*cliproxyauth.Auth { return []*cliproxyauth.Auth{a} })
			original := codexTurnTicketProbeClient
			t.Cleanup(func() { codexTurnTicketProbeClient = original })
			calls := 0
			codexTurnTicketProbeClient = func(_ context.Context, _ *cliproxyauth.Auth, egress string, _ time.Duration) (*http.Client, error) {
				return &http.Client{Transport: codexAdaptiveRoundTripFunc(func(req *http.Request) (*http.Response, error) {
					calls++
					status := 200
					headers := http.Header{}
					if calls == 1 {
						headers.Set(CodexTurnStateHeader, testTurnState(t, time.Now().Unix(), 312))
					} else if egress == effective.HarvestProxyURLs[0] {
						status = tc.harvestStatus
						headers.Set(CodexTurnStateHeader, testTurnState(t, time.Now().Unix(), 780))
						headers.Set("Set-Cookie", "__cflb=route; Path=/; Max-Age=240")
					}
					return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(tc.body)), Request: req}, nil
				})}, nil
			}
			h.probeAdaptive(context.Background(), a, "gpt-5.5", effective)
			if got := store.Lookup(a.ID, "gpt-5.5") != nil; got != tc.wantBundle {
				t.Fatalf("bundle=%v want=%v", got, tc.wantBundle)
			}
			if tc.wantEgressBackoff {
				candidates, until := h.routingHarvestCandidates(a.ID, "gpt-5.5", effective, time.Now())
				if len(candidates) != 0 || !until.After(time.Now()) {
					t.Fatal("custom acquisition rejection did not park its exit")
				}
				if !h.probeSnapshot(a.ID, "gpt-5.5").ProbeBackoffUntil.IsZero() {
					t.Fatal("acquisition rejection parked business bucket")
				}
			}
		})
	}
}
