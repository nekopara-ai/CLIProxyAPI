package helps

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestCodexAdaptiveMissUpdatesProbeSnapshot(t *testing.T) {
	cfg := turnTicketTestConfig()
	cfg.Codex.TurnTicket.AdaptiveInjection = nil
	auth := turnTicketTestAuth("probe-miss")
	effective := EffectiveCodexTurnTicketConfig(cfg)
	h := NewCodexTurnTicketHarvester(NewCodexTurnTicketStore(), func() *config.Config { return cfg }, nil)
	degraded := testTurnState(t, time.Now().Unix(), 312)
	original := codexTurnTicketProbeClient
	t.Cleanup(func() { codexTurnTicketProbeClient = original })
	codexTurnTicketProbeClient = func(context.Context, *cliproxyauth.Auth, string, time.Duration) (*http.Client, error) {
		return &http.Client{Transport: codexAdaptiveRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			snapshot := h.bucketSnapshot(auth, "gpt-5.5", effective)
			if !snapshot.ProbeInFlight || snapshot.ProbePhase != "business" || snapshot.ProbeStartedAt.IsZero() {
				t.Fatalf("in-flight probe is invisible: %+v", snapshot)
			}
			return &http.Response{StatusCode: 200, Header: http.Header{CodexTurnStateHeader: []string{degraded}}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
		})}, nil
	}
	if _, err := h.routingProbe(context.Background(), auth, "gpt-5.5", "business", "direct", nil, effective); err != nil {
		t.Fatal(err)
	}
	snapshot := h.bucketSnapshot(auth, "gpt-5.5", effective)
	if snapshot.ProbeInFlight || snapshot.ProbeAttempts != 1 || snapshot.LastProbeAt.IsZero() || snapshot.LastObservedAt.IsZero() || snapshot.LastObservedLength != 312 || snapshot.LastProbePhase != "business" || snapshot.LastResult != "degraded" {
		t.Fatalf("completed 312 probe is invisible or mislabeled: %+v", snapshot)
	}
	if snapshot.LastObservedHealthy || h.store.adaptiveAllows(auth, "gpt-5.5", effective, time.Now()) {
		t.Fatal("recording a failed probe made the credential ready")
	}
}

func TestCodexAdaptiveRejectedProbeReportsBackoff(t *testing.T) {
	cfg := turnTicketTestConfig()
	cfg.Codex.TurnTicket.AdaptiveInjection = nil
	auth := turnTicketTestAuth("probe-rejected")
	effective := EffectiveCodexTurnTicketConfig(cfg)
	h := NewCodexTurnTicketHarvester(NewCodexTurnTicketStore(), func() *config.Config { return cfg }, nil)
	original := codexTurnTicketProbeClient
	t.Cleanup(func() { codexTurnTicketProbeClient = original })
	codexTurnTicketProbeClient = func(context.Context, *cliproxyauth.Auth, string, time.Duration) (*http.Client, error) {
		return &http.Client{Transport: codexAdaptiveRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 429, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
		})}, nil
	}
	h.probeAdaptive(context.Background(), auth, "gpt-5.5", effective)
	snapshot := h.bucketSnapshot(auth, "gpt-5.5", effective)
	if snapshot.LastHTTPStatus != 429 || snapshot.LastResult != "rejected" || !snapshot.ProbeBackoffUntil.After(time.Now()) || !snapshot.NextProbeAt.Equal(snapshot.ProbeBackoffUntil) {
		t.Fatalf("rejection/backoff was not exposed: %+v", snapshot)
	}
}

func TestCodexAdaptiveConfiguredLeaseRemainsUsableAfterThreeMinutes(t *testing.T) {
	for _, seconds := range []int{240, 600} {
		cfg := turnTicketTestConfig()
		cfg.Codex.TurnTicket.AdaptiveInjection = nil
		cfg.Codex.TurnTicket.RoutingCookieTTLSeconds = seconds
		cfg.Codex.TurnTicket.RoutingRefreshBeforeSeconds = 60
		effective := EffectiveCodexTurnTicketConfig(cfg)
		auth := turnTicketTestAuth("longer-lease")
		store := NewCodexTurnTicketStore()
		model := "gpt-5.5"
		observed := time.Now().Add(-210 * time.Second)
		state := testTurnState(t, observed.Unix(), 292)
		header := http.Header{"Set-Cookie": []string{"__cflb=validated-route; Path=/; Max-Age=3600"}}
		ticket := newCodexRoutingTicket(state, header, observed, effective)
		if ticket == nil || ticket.RoutingExpiresAt.Sub(observed) != time.Duration(seconds)*time.Second {
			t.Fatalf("configured %d-second lease was silently shortened", seconds)
		}
		route := store.setRoute(auth, model, effective, codexRouteInject, true)
		ticket.RoutingContext, ticket.RoutingValidatedAt = route.Context, observed.Add(time.Second)
		if !store.publishAdaptive(auth, model, route, ticket) || !store.adaptiveAllows(auth, model, effective, time.Now()) {
			t.Fatal("validated routing bundle was not admitted after 210 seconds")
		}
		headers := http.Header{}
		if !NewCodexTurnTicketInjector(store, func() *config.Config { return cfg }).Apply(auth, model, headers) || headers.Get(CodexTurnStateHeader) != state || headers.Get("Cookie") != "__cflb=validated-route" {
			t.Fatal("admitted routing bundle did not inject both ticket and cookie")
		}
		if store.adaptiveAllows(auth, model, effective, ticket.RoutingExpiresAt.Add(-4*time.Second)) {
			t.Fatal("expired lease safety margin was bypassed")
		}
	}
}

func TestCodexAdaptiveShorterHealthyCooldownTakesEffectOnReload(t *testing.T) {
	cfg := turnTicketTestConfig()
	cfg.Codex.TurnTicket.AdaptiveInjection = nil
	cfg.Codex.TurnTicket.ProbeCooldownSeconds = 2700
	auth := turnTicketTestAuth("shorter-cooldown")
	effective := EffectiveCodexTurnTicketConfig(cfg)
	store := NewCodexTurnTicketStore()
	h := NewCodexTurnTicketHarvester(store, func() *config.Config { return cfg }, nil)
	store.setRoute(auth, "gpt-5.5", effective, codexRouteDirect, true)
	h.recordObservation(auth.ID, "gpt-5.5", CodexTurnTicketObservation{ObservedAt: time.Now().Add(-301 * time.Second), Healthy: true, Result: "business_direct"})
	h.setProbeCooldown(auth.ID, "gpt-5.5", time.Now().Add(2399*time.Second))
	cfg.Codex.TurnTicket.ProbeCooldownSeconds = 300
	called := false
	original := codexTurnTicketProbeClient
	t.Cleanup(func() { codexTurnTicketProbeClient = original })
	codexTurnTicketProbeClient = func(context.Context, *cliproxyauth.Auth, string, time.Duration) (*http.Client, error) {
		return &http.Client{Transport: codexAdaptiveRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			called = true
			return &http.Response{StatusCode: 429, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
		})}, nil
	}
	h.probeAdaptive(context.Background(), auth, "gpt-5.5", effective)
	if !called {
		t.Fatal("shortened cooldown left the old 45-minute schedule in effect")
	}
	called = false
	h.probeAdaptive(context.Background(), auth, "gpt-5.5", effective)
	if called {
		t.Fatal("shortening healthy cooldown bypassed upstream rejection backoff")
	}
}
