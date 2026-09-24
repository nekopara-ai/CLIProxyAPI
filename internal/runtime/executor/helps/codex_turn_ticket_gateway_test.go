package helps

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps/codexmint"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func gatewayFixture(t *testing.T, handler http.HandlerFunc) (*config.Config, *cliproxyauth.Auth, *CodexTurnTicketProcess) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	cfg := &config.Config{}
	cfg.Codex.TurnTicket.Enabled = true
	cfg.Codex.TurnTicket.Models = []string{"A"}
	cfg.Codex.TurnTicket.MintTransports = []string{"sse"}
	cfg.Codex.TurnTicket.MintWorkers = 1
	cfg.Codex.TurnTicket.MintMaxAttempts = 4
	a := turnTicketTestAuth("gateway-auth")
	a.ProxyURL = "direct"
	a.Attributes = map[string]string{"base_url": server.URL}
	p := ConfigureCodexTurnTickets(func() *config.Config { return cfg }, func() []*cliproxyauth.Auth { return []*cliproxyauth.Auth{a} })
	t.Cleanup(func() { p.Harvester.Stop(); ConfigureCodexTurnTickets(nil, nil) })
	return cfg, a, p
}
func gatewayTestHeaders(gateway string) http.Header {
	payload, _ := json.Marshal(map[string]any{"exp": time.Now().Add(time.Hour).Unix(), "node": "chat.gateway." + gateway + ".api.openai.com"})
	return http.Header{"Content-Type": {"text/event-stream"}, CodexTurnStateHeader: {strings.Repeat("x", 780)}, "Set-Cookie": {"__cflb=route; Path=/", "__oailb=e30." + base64.RawURLEncoding.EncodeToString(payload) + ".sig; Path=/"}}
}
func gatewayTestResponse(w http.ResponseWriter, model, gateway string) {
	for name, values := range gatewayTestHeaders(gateway) {
		for _, v := range values {
			w.Header().Add(name, v)
		}
	}
	fmt.Fprintf(w, "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_local\",\"model\":%q}}\n\n", model)
}
func TestGatewayDefaultRequiresGatewayAndCreatedBeforeInjection(t *testing.T) {
	var calls atomic.Int32
	cfg, auth, p := gatewayFixture(t, func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if r.Header.Get(CodexTurnStateHeader) != "" {
			t.Error("mint replayed old turn-state")
		}
		var body struct {
			Model        string
			Instructions string
			Reasoning    struct{ Effort string }
			Input        []json.RawMessage
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body.Instructions != "" || body.Reasoning.Effort != "low" {
			t.Error("wrong synthetic payload")
		}
		if n == 1 {
			gatewayTestResponse(w, body.Model, "unified-12")
			return
		}
		if n == 2 && r.Header.Get("Cookie") != "" {
			t.Error("off-target pair reused")
		}
		if n == 3 && !strings.Contains(r.Header.Get("Cookie"), "__oailb=") {
			t.Error("target pair not reused across models")
		}
		gatewayTestResponse(w, body.Model, "unified-88")
	})
	cfg.Codex.TurnTicket.Models = []string{"A", "B"}
	if !EffectiveCodexTurnTicketConfig(cfg).GatewayMint {
		t.Fatal("gateway is not default")
	}
	ObserveCodexTurnTicketResponse(auth, "A", 200, http.Header{CodexTurnStateHeader: {strings.Repeat("x", 780)}}, http.Header{}, false)
	if CodexTurnTicketAllowsExecution(auth, "A") {
		t.Fatal("header-only state promoted direct")
	}
	p.Harvester.probeAll(context.Background())
	if calls.Load() != 3 {
		t.Fatal("unexpected number of probes", calls.Load())
	}
	headers := http.Header{"Cookie": {"session=keep"}}
	if !ApplyCodexTurnTicket(auth, "A", headers) || !strings.Contains(headers.Get("Cookie"), "session=keep") || !CodexTurnTicketAllowsExecution(auth, "A") {
		t.Fatal("ready bundle did not inject")
	}
	p.Harvester.probeAll(context.Background())
	if calls.Load() != 3 {
		t.Fatal("warm cache probed")
	}
	snapshot := SnapshotCodexTurnTickets()
	if snapshot.PersistentStore || snapshot.HealthyTickets != 2 || !snapshot.BucketStates[0].MintStates["sse"].Ready {
		t.Fatalf("bad diagnostics: %+v", snapshot)
	}
	encoded, _ := json.Marshal(snapshot)
	if strings.Contains(string(encoded), strings.Repeat("x", 40)) || strings.Contains(string(encoded), "e30.") {
		t.Fatal("secrets in diagnostics")
	}
	cfg.Codex.TurnTicket.MintGateway = "unified-77"
	if ApplyCodexTurnTicket(auth, "A", http.Header{}) || CodexTurnTicketAllowsExecution(auth, "A") {
		t.Fatal("new gateway bypassed by cache")
	}
}
func TestGatewayModelMismatchExhaustsWithoutInjection(t *testing.T) {
	var calls atomic.Int32
	_, auth, p := gatewayFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		gatewayTestResponse(w, "wrong-model", "unified-88")
	})
	p.Harvester.probeAll(context.Background())
	if calls.Load() != 4 || ApplyCodexTurnTicket(auth, "A", http.Header{}) {
		t.Fatal("mismatch accepted or budget ignored")
	}
}
func TestGateway401StopsCredentialAndDoesNotProbeAgain(t *testing.T) {
	var calls atomic.Int32
	cfg, auth, p := gatewayFixture(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(401) })
	cfg.Codex.TurnTicket.Models = []string{"A", "B"}
	cfg.Codex.TurnTicket.MintTransports = []string{"sse", "websocket"}
	auth.Attributes["websockets"] = "true"
	p.Harvester.probeAll(context.Background())
	p.Harvester.probeAll(context.Background())
	if calls.Load() != 1 {
		t.Fatal("credential rejection retried", calls.Load())
	}
}
func TestGatewayStopsReadingAtCreatedAndClosesSyntheticRequest(t *testing.T) {
	closed := make(chan struct{})
	entered := make(chan struct{})
	_, auth, p := gatewayFixture(t, func(w http.ResponseWriter, r *http.Request) {
		gatewayTestResponse(w, "A", "unified-88")
		w.(http.Flusher).Flush()
		close(entered)
		<-r.Context().Done()
		close(closed)
	})
	done := make(chan struct{})
	go func() { p.Harvester.probeAll(context.Background()); close(done) }()
	<-entered
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("waited for completion")
	}
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("probe stream not closed")
	}
	if !ApplyCodexTurnTicket(auth, "A", http.Header{}) {
		t.Fatal("created event rejected")
	}
}
func TestGatewayStopCancelsInFlightProbe(t *testing.T) {
	entered := make(chan struct{})
	closed := make(chan struct{})
	_, _, p := gatewayFixture(t, func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done(); close(closed) })
	p.Harvester.Start(context.Background())
	<-entered
	done := make(chan struct{})
	go func() { p.Harvester.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("stop did not cancel acquisition")
	}
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("probe connection leaked")
	}
}
func TestGatewayInjectionSwitchAndManualInvalidation(t *testing.T) {
	cfg, auth, p := gatewayFixture(t, func(w http.ResponseWriter, r *http.Request) { gatewayTestResponse(w, "A", "unified-88") })
	off := false
	cfg.Codex.TurnTicket.InjectionEnabled = &off
	p.Harvester.probeAll(context.Background())
	if ApplyCodexTurnTicket(auth, "A", http.Header{}) || CodexTurnTicketAllowsExecution(auth, "A") {
		t.Fatal("disabled injection passed fail-closed")
	}
	on := true
	cfg.Codex.TurnTicket.InjectionEnabled = &on
	if !ApplyCodexTurnTicket(auth, "A", http.Header{}) {
		t.Fatal("probe-only cache was not kept")
	}
	InvalidateCodexTurnTicketsForAuth(auth.ID)
	if ApplyCodexTurnTicket(auth, "A", http.Header{}) {
		t.Fatal("manual invalidation ignored")
	}
}
func TestGatewayWebsocketMetadataAfterCreatedAndTransportIsolation(t *testing.T) {
	var calls atomic.Int32
	cfg, auth, p := gatewayFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		header := gatewayTestHeaders("unified-88")
		header.Del(CodexTurnStateHeader)
		header.Del("Content-Type")
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, header)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		var req map[string]any
		if err = conn.ReadJSON(&req); err != nil {
			t.Error(err)
			return
		}
		if req["type"] != "response.create" || req["stream"] != nil || r.Header.Get(CodexTurnStateHeader) != "" {
			t.Error("bad websocket synthetic request")
		}
		_ = conn.WriteJSON(map[string]any{"type": "response.created", "response": map[string]any{"id": "resp_ws", "model": "A"}})
		_ = conn.WriteJSON(map[string]any{"type": "codex.response.metadata", "headers": map[string]string{"x-codex-turn-state": strings.Repeat("x", 780)}})
	})
	auth.Attributes["websockets"] = "true"
	cfg.Codex.TurnTicket.MintTransports = []string{"websocket"}
	p.Harvester.probeAll(context.Background())
	if calls.Load() != 1 {
		t.Fatal("websocket did not mint", calls.Load())
	}
	if ApplyCodexTurnTicket(auth, "A", http.Header{}) {
		t.Fatal("websocket ticket used on SSE")
	}
	headers := http.Header{}
	if !ApplyCodexTurnTicket(auth, "A", headers, WithCodexMintTransport(context.Background(), "websocket")) {
		t.Fatal("metadata-after-created not accepted")
	}
	if CodexGatewayRequestAllowed(auth, "A", false) {
		t.Fatal("physical transport guard allows missing injection")
	}
}
func TestGatewayDoesNotFollowCredentialRedirect(t *testing.T) {
	var leaked atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1) }))
	defer target.Close()
	cfg, auth, p := gatewayFixture(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	})
	cfg.Codex.TurnTicket.MintMaxAttempts = 1
	p.Harvester.probeAll(context.Background())
	if leaked.Load() != 0 || ApplyCodexTurnTicket(auth, "A", http.Header{}) {
		t.Fatal("credential redirect followed")
	}
}
func TestGatewayScopeChangesWithCredentialsEgressModelPolicy(t *testing.T) {
	cfg, auth, _ := gatewayFixture(t, func(w http.ResponseWriter, r *http.Request) { io.Copy(io.Discard, r.Body) })
	e := EffectiveCodexTurnTicketConfig(cfg)
	original := codexGatewayScope(auth, e, "sse")
	if original == codexGatewayScope(auth, e, "websocket") {
		t.Fatal("transport not isolated")
	}
	auth.ProxyURL = "http://other.invalid"
	if original == codexGatewayScope(auth, e, "sse") {
		t.Fatal("business egress not isolated")
	}
	auth.ProxyURL = "direct"
	auth.Metadata["access_token"] = "rotated-token"
	if original == codexGatewayScope(auth, e, "sse") {
		t.Fatal("credential rotation not isolated")
	}
	c := codexGatewayConfig(auth, e)
	if c.TicketTTL != 240*time.Second || c.PairTTL != 3900*time.Second || c.Gateway != "unified-88" {
		t.Fatal(c)
	}
	if codexmint.NormalizeGateway(c.Gateway) != "unified-88" {
		t.Fatal("wrong target")
	}
}
