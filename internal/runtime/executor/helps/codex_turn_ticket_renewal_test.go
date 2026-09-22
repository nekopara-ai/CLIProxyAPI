package helps

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// Reproduce a pool rejection during renewal, followed by lease expiry and recovery.
// No real clock sleeps or upstream credentials are needed.
func TestCodexAdaptiveHarvestForbiddenDoesNotParkBusinessRecovery(t *testing.T) {
	cfg := turnTicketTestConfig()
	cfg.Codex.TurnTicket.AdaptiveInjection = nil
	cfg.Codex.TurnTicket.RoutingCookieTTLSeconds = 240
	cfg.Codex.TurnTicket.RoutingRefreshBeforeSeconds = 60
	cfg.Codex.TurnTicket.HarvestProxyURLs = []string{"http://pool.example:8080"}
	effective := EffectiveCodexTurnTicketConfig(cfg)
	auth := turnTicketTestAuth("renewal-forbidden")
	model := "gpt-5.5"
	store := NewCodexTurnTicketStore()
	h := NewCodexTurnTicketHarvester(store, func() *config.Config { return cfg }, nil)
	route := store.setRoute(auth, model, effective, codexRouteInject, true)
	observed := time.Now().Add(-200 * time.Second)
	healthy := testTurnState(t, observed.Unix(), 292)
	degraded := testTurnState(t, time.Now().Unix(), 312)
	ticket := newCodexRoutingTicket(healthy, http.Header{"Set-Cookie": {"__cflb=old; Max-Age=3600"}}, observed, effective)
	ticket.RoutingContext, ticket.RoutingValidatedAt = route.Context, observed.Add(time.Second)
	store.publishAdaptive(auth, model, route, ticket)
	h.setProbeCooldown(auth.ID, model, ticket.RoutingExpiresAt.Add(-60*time.Second))
	completed := "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"model\":\"gpt-5.5\"}}\n\n"
	poolOK := false
	businessCalls, harvestCalls, validationCalls := 0, 0, 0
	original := codexTurnTicketProbeClient
	t.Cleanup(func() { codexTurnTicketProbeClient = original })
	codexTurnTicketProbeClient = func(_ context.Context, _ *cliproxyauth.Auth, egress string, _ time.Duration) (*http.Client, error) {
		return &http.Client{Transport: codexAdaptiveRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			status, body := 200, completed
			header := http.Header{}
			switch {
			case egress == effective.HarvestProxyURLs[0]:
				harvestCalls++
				if !poolOK {
					status = 403
				} else {
					header.Set(CodexTurnStateHeader, testTurnState(t, time.Now().Unix(), 292))
					header.Add("Set-Cookie", "__cflb=new; Max-Age=3600")
				}
			case req.Header.Get(CodexTurnStateHeader) != "":
				validationCalls++
				if req.Header.Get("Cookie") != "__cflb=new" {
					t.Fatal("validation did not use the fresh cookie")
				}
			default:
				businessCalls++
				header.Set(CodexTurnStateHeader, degraded)
			}
			return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
		})}, nil
	}
	h.probeAdaptive(context.Background(), auth, model, effective)
	if !h.probeSnapshot(auth.ID, model).ProbeBackoffUntil.IsZero() {
		t.Fatal("harvest 403 incorrectly parked the entire business bucket")
	}
	if businessCalls != 1 || harvestCalls != 1 || !store.adaptiveAllows(auth, model, effective, time.Now()) {
		t.Fatal("renewal rejection discarded a still-valid lease or hammered the rejected pool")
	}
	// Advance the lease without sleeping, leaving the pool's rejection active.
	ticket.RoutingExpiresAt = time.Now().Add(-time.Second)
	store.publishAdaptive(auth, model, route, ticket)
	h.setProbeCooldown(auth.ID, model, time.Now().Add(-time.Second))
	if store.adaptiveAllows(auth, model, effective, time.Now()) {
		t.Fatal("expired bundle remained eligible for traffic")
	}
	h.probeAdaptive(context.Background(), auth, model, effective)
	if businessCalls != 2 || harvestCalls != 1 {
		t.Fatal("expired lease stopped business probes or bypassed the pool backoff")
	}
	// Expire only the acquisition backoff. The next cycle must validate and recover.
	h.scheduleMu.Lock()
	for egress := range h.harvestRejectedAt[codexTurnTicketKey(auth.ID, model)] {
		h.harvestRejectedAt[codexTurnTicketKey(auth.ID, model)][egress] = time.Now().Add(-time.Hour)
	}
	h.scheduleMu.Unlock()
	h.setProbeCooldown(auth.ID, model, time.Now().Add(-time.Second))
	poolOK = true
	h.probeAdaptive(context.Background(), auth, model, effective)
	if businessCalls != 3 || harvestCalls != 2 || validationCalls != 1 || !store.adaptiveAllows(auth, model, effective, time.Now()) {
		t.Fatal("expired bucket failed to renew and rejoin scheduling")
	}
	headers := http.Header{}
	if !NewCodexTurnTicketInjector(store, func() *config.Config { return cfg }).Apply(auth, model, headers) || headers.Get("Cookie") != "__cflb=new" {
		t.Fatal("recovered bucket failed to inject the validated fresh bundle")
	}
}

func TestCodexAdaptiveAcquisitionRejectScope(t *testing.T) {
	for _, status := range []int{401, 403, 429} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			cfg := turnTicketTestConfig()
			cfg.Codex.TurnTicket.AdaptiveInjection = nil
			cfg.Codex.TurnTicket.HarvestAttempts = 3
			cfg.Codex.TurnTicket.HarvestProxyURLs = []string{"http://pool-a.example", "http://pool-b.example"}
			effective := EffectiveCodexTurnTicketConfig(cfg)
			auth := turnTicketTestAuth("reject-scope")
			h := NewCodexTurnTicketHarvester(NewCodexTurnTicketStore(), func() *config.Config { return cfg }, nil)
			degraded := testTurnState(t, time.Now().Unix(), 312)
			seen := map[string]int{}
			original := codexTurnTicketProbeClient
			t.Cleanup(func() { codexTurnTicketProbeClient = original })
			codexTurnTicketProbeClient = func(_ context.Context, _ *cliproxyauth.Auth, egress string, _ time.Duration) (*http.Client, error) {
				return &http.Client{Transport: codexAdaptiveRoundTripFunc(func(req *http.Request) (*http.Response, error) {
					code := 200
					header := http.Header{CodexTurnStateHeader: {degraded}}
					if strings.HasPrefix(egress, "http://pool-") {
						seen[egress]++
						code, header = status, http.Header{}
					}
					return &http.Response{StatusCode: code, Header: header, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
				})}, nil
			}
			h.probeAdaptive(context.Background(), auth, "gpt-5.5", effective)
			snapshot := h.probeSnapshot(auth.ID, "gpt-5.5")
			if status == 403 {
				if len(seen) != 2 || seen[effective.HarvestProxyURLs[0]] != 1 || seen[effective.HarvestProxyURLs[1]] != 1 || !snapshot.ProbeBackoffUntil.IsZero() || snapshot.HarvestBackoffUntil.IsZero() {
					t.Fatal("pool 403 was not isolated per egress")
				}
			} else if len(seen) != 1 || snapshot.ProbeBackoffUntil.IsZero() || !snapshot.HarvestBackoffUntil.IsZero() {
				t.Fatal("authentication/quota rejection rotated exits or lost bucket backoff")
			}
		})
	}
}

func TestCodexAdaptiveHarvestBackoffReloadAndIsolation(t *testing.T) {
	cfg := turnTicketTestConfig()
	cfg.Codex.TurnTicket.HarvestRejectBackoffSeconds = 60
	cfg.Codex.TurnTicket.HarvestProxyURLs = []string{"http://pool.example"}
	effective := EffectiveCodexTurnTicketConfig(cfg)
	h := NewCodexTurnTicketHarvester(NewCodexTurnTicketStore(), func() *config.Config { return cfg }, nil)
	now := time.Now()
	h.parkRoutingHarvestEgress("auth-a", "gpt-5.5", effective.HarvestProxyURLs[0], now.Add(-30*time.Second))
	if choices, until := h.routingHarvestCandidates("auth-a", "gpt-5.5", effective, now); len(choices) != 0 || !until.Equal(now.Add(30*time.Second)) {
		t.Fatal("configured harvest backoff was not honored")
	}
	for _, bucket := range [][2]string{{"auth-b", "gpt-5.5"}, {"auth-a", "gpt-6-astra"}} {
		if choices, _ := h.routingHarvestCandidates(bucket[0], bucket[1], effective, now); len(choices) != 1 {
			t.Fatal("harvest backoff crossed the auth/model boundary")
		}
	}
	cfg.Codex.TurnTicket.HarvestRejectBackoffSeconds = 15
	if choices, until := h.routingHarvestCandidates("auth-a", "gpt-5.5", EffectiveCodexTurnTicketConfig(cfg), now); len(choices) != 1 || !until.IsZero() {
		t.Fatal("shortened acquisition backoff requires a restart")
	}
}
