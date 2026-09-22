package executor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

const adaptiveTicketSSEBody = "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"object\":\"response\",\"status\":\"completed\",\"output\":[]}}\n\n"

func adaptiveTicketAuth(id, baseURL string) *cliproxyauth.Auth {
	return &cliproxyauth.Auth{
		ID:       id,
		Provider: "codex",
		Status:   cliproxyauth.StatusActive,
		Metadata: map[string]any{"access_token": "fixture", "auth_kind": "oauth", "account_id": "workspace-fixture"},
		Attributes: map[string]string{
			"base_url": baseURL,
		},
	}
}

func drainAdaptiveTicketStream(t *testing.T, result *cliproxyexecutor.StreamResult) {
	t.Helper()
	if result == nil {
		return
	}
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("stream error: %v", chunk.Err)
		}
	}
}

// TestCodexExecutorAdaptiveDegradedResponseModes proves the actual HTTP status and
// response headers reach the adaptive policy from every executor entry point.
func TestCodexExecutorAdaptiveDegradedResponseModes(t *testing.T) {
	degraded := integrationTurnState(t, time.Now().Unix(), 312)
	for _, mode := range []string{"stream", "nonstream", "compact"} {
		t.Run(mode, func(t *testing.T) {
			var seenState atomic.Value
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seenState.Store(r.Header.Get(helps.CodexTurnStateHeader))
				w.Header().Set(helps.CodexTurnStateHeader, degraded)
				if mode == "compact" {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"id":"resp_compact","object":"response.compaction","output":[]}`))
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte(adaptiveTicketSSEBody))
			}))
			defer server.Close()

			cfg := turnTicketIntegrationConfig("gpt-5.5")
			cfg.DisableImageGeneration = config.DisableImageGenerationAll
			process := helps.ConfigureCodexTurnTickets(func() *config.Config { return cfg }, nil)
			defer helps.ConfigureCodexTurnTickets(nil, nil)
			if process == nil {
				t.Fatal("adaptive process was not configured")
			}

			auth := adaptiveTicketAuth("adaptive-"+mode, server.URL)
			headers := http.Header{helps.CodexTurnStateHeader: []string{degraded}}
			req := cliproxyexecutor.Request{Model: "gpt-5.5", Payload: []byte(`{"model":"gpt-5.5","input":"hello"}`)}
			opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai-response"), Headers: headers}
			exec := NewCodexExecutor(cfg)
			switch mode {
			case "stream":
				opts.Stream = true
				result, err := exec.ExecuteStream(context.Background(), auth, req, opts)
				if err != nil {
					t.Fatalf("ExecuteStream() error = %v", err)
				}
				drainAdaptiveTicketStream(t, result)
			case "compact":
				opts.Alt = "responses/compact"
				if _, err := exec.Execute(context.Background(), auth, req, opts); err != nil {
					t.Fatalf("Execute(compact) error = %v", err)
				}
			default:
				if _, err := exec.Execute(context.Background(), auth, req, opts); err != nil {
					t.Fatalf("Execute() error = %v", err)
				}
			}

			if value, _ := seenState.Load().(string); len(value) != 312 {
				t.Fatalf("physical request state length = %d, want passthrough 312", len(value))
			}
			if helps.ApplyCodexTurnTicket(auth, "gpt-5.5", http.Header{}) {
				t.Fatal("adaptive route injected before a validated routing bundle existed")
			}
			snapshot := helps.SnapshotCodexTurnTicketForAuth(auth)
			if snapshot == nil || len(snapshot.ModelStates) != 1 {
				t.Fatalf("adaptive snapshot = %+v", snapshot)
			}
			state := snapshot.ModelStates[0]
			if state.RoutingMode != "inject" || state.LastHTTPStatus != http.StatusOK || state.LastObservedLength != 312 || state.TicketState != "missing" {
				t.Fatalf("adaptive state after degraded response = %+v", state)
			}
			if helps.CodexTurnTicketAllowsExecution(auth, "gpt-5.5") {
				t.Fatal("inject route without a validated routing bundle did not fail closed")
			}
		})
	}
}

// TestCodexExecutorAdaptiveObservesActualOutboundRoutingHeaders verifies the executor
// observes the physical outbound headers, not the client input or a synthetic map. A
// clean 292 only becomes "direct" when the outbound request has no turn-state and no
// routing cookie; the forwarded client turn-state must prevent that transition.
func TestCodexExecutorAdaptiveObservesActualOutboundRoutingHeaders(t *testing.T) {
	healthy := integrationTurnState(t, time.Now().Unix(), 292)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(helps.CodexTurnStateHeader, healthy)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(adaptiveTicketSSEBody))
	}))
	defer server.Close()

	cfg := turnTicketIntegrationConfig("gpt-5.5")
	cfg.DisableImageGeneration = config.DisableImageGenerationAll
	process := helps.ConfigureCodexTurnTickets(func() *config.Config { return cfg }, nil)
	defer helps.ConfigureCodexTurnTickets(nil, nil)
	if process == nil {
		t.Fatal("adaptive process was not configured")
	}

	auth := adaptiveTicketAuth("adaptive-outbound-headers", server.URL)
	headers := http.Header{helps.CodexTurnStateHeader: []string{healthy}}
	if _, err := NewCodexExecutor(cfg).Execute(context.Background(), auth, cliproxyexecutor.Request{Model: "gpt-5.5", Payload: []byte(`{"model":"gpt-5.5","input":"hello"}`)}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai-response"), Headers: headers}); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	snapshot := helps.SnapshotCodexTurnTicketForAuth(auth)
	if snapshot == nil || len(snapshot.ModelStates) != 1 {
		t.Fatalf("adaptive snapshot = %+v", snapshot)
	}
	if got := snapshot.ModelStates[0].RoutingMode; got == "direct" {
		t.Fatal("executor observed synthetic headers and incorrectly classified a turn-state request as direct")
	}
}

// TestCodexExecutorObserveIgnoresNonSuccessStatus pins the 2xx/101 guard: a rejected
// request must not transition the bucket even if the response carries a degraded token.
func TestCodexExecutorObserveIgnoresNonSuccessStatus(t *testing.T) {
	degraded := integrationTurnState(t, time.Now().Unix(), 312)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(helps.CodexTurnStateHeader, degraded)
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"fixture rejection"}}`))
	}))
	defer server.Close()

	cfg := turnTicketIntegrationConfig("gpt-5.5")
	cfg.DisableImageGeneration = config.DisableImageGenerationAll
	process := helps.ConfigureCodexTurnTickets(func() *config.Config { return cfg }, nil)
	defer helps.ConfigureCodexTurnTickets(nil, nil)
	if process == nil {
		t.Fatal("adaptive process was not configured")
	}
	auth := adaptiveTicketAuth("adaptive-429", server.URL)
	_, err := NewCodexExecutor(cfg).Execute(context.Background(), auth, cliproxyexecutor.Request{Model: "gpt-5.5", Payload: []byte(`{"model":"gpt-5.5","input":"hello"}`)}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai-response")})
	if err == nil {
		t.Fatal("Execute() error = nil, want upstream rejection")
	}
	snapshot := helps.SnapshotCodexTurnTicketForAuth(auth)
	if snapshot == nil || len(snapshot.ModelStates) != 1 {
		t.Fatalf("adaptive snapshot = %+v", snapshot)
	}
	if got := snapshot.ModelStates[0].RoutingMode; got == "inject" {
		t.Fatal("non-success response transitioned the adaptive route")
	}
}

// TestCodexWebsocketExecutorAdaptiveHandshakeObservation exercises the physical 101
// handshake path. The adaptive core must see the handshake status, the response headers,
// and the headers that were actually sent on the socket.
func TestCodexWebsocketExecutorAdaptiveHandshakeObservation(t *testing.T) {
	degraded := integrationTurnState(t, time.Now().Unix(), 312)
	var seenState atomic.Value
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenState.Store(r.Header.Get(helps.CodexTurnStateHeader))
		conn, errUpgrade := upgrader.Upgrade(w, r, http.Header{helps.CodexTurnStateHeader: []string{degraded}})
		if errUpgrade != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		if _, _, errRead := conn.ReadMessage(); errRead != nil {
			return
		}
		_ = conn.WriteMessage(websocket.TextMessage, []byte(ticketUsageTerminal))
	}))
	defer server.Close()

	cfg := turnTicketIntegrationConfig("gpt-5.5")
	cfg.DisableImageGeneration = config.DisableImageGenerationAll
	process := helps.ConfigureCodexTurnTickets(func() *config.Config { return cfg }, nil)
	defer helps.ConfigureCodexTurnTickets(nil, nil)
	if process == nil {
		t.Fatal("adaptive process was not configured")
	}

	auth := adaptiveTicketAuth("adaptive-websocket-handshake", server.URL)
	headers := http.Header{helps.CodexTurnStateHeader: []string{degraded}}
	_, err := NewCodexWebsocketsExecutor(cfg).Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "gpt-5.5",
		Payload: []byte(`{"model":"gpt-5.5","input":"hello"}`),
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("openai-response"),
		Headers:      headers,
	})
	if err != nil {
		t.Fatalf("WebSocket Execute() error = %v", err)
	}
	if got, _ := seenState.Load().(string); got != degraded {
		t.Fatalf("physical websocket handshake state length = %d, want passthrough 312", len(got))
	}
	snapshot := helps.SnapshotCodexTurnTicketForAuth(auth)
	if snapshot == nil || len(snapshot.ModelStates) != 1 {
		t.Fatalf("adaptive snapshot = %+v", snapshot)
	}
	state := snapshot.ModelStates[0]
	if state.RoutingMode != "inject" || state.LastHTTPStatus != http.StatusSwitchingProtocols || state.LastObservedLength != 312 {
		t.Fatalf("adaptive websocket handshake state = %+v", state)
	}
}

// TestCodexWebsocketExecutorFailedUpgradeDoesNotObserve proves an HTTP 200 without a
// WebSocket upgrade is not accepted as a 101 handshake. The core allows 2xx for HTTP,
// but the WebSocket path must require a real successful upgrade.
func TestCodexWebsocketExecutorFailedUpgradeDoesNotObserve(t *testing.T) {
	degraded := integrationTurnState(t, time.Now().Unix(), 312)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(helps.CodexTurnStateHeader, degraded)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not a websocket upgrade"))
	}))
	defer server.Close()

	cfg := turnTicketIntegrationConfig("gpt-5.5")
	cfg.DisableImageGeneration = config.DisableImageGenerationAll
	process := helps.ConfigureCodexTurnTickets(func() *config.Config { return cfg }, nil)
	defer helps.ConfigureCodexTurnTickets(nil, nil)
	if process == nil {
		t.Fatal("adaptive process was not configured")
	}

	auth := adaptiveTicketAuth("adaptive-websocket-failed-upgrade", server.URL)
	_, err := NewCodexWebsocketsExecutor(cfg).Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "gpt-5.5",
		Payload: []byte(`{"model":"gpt-5.5","input":"hello"}`),
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("openai-response"),
	})
	if err == nil {
		t.Fatal("WebSocket Execute() error = nil, want failed upgrade")
	}
	snapshot := helps.SnapshotCodexTurnTicketForAuth(auth)
	if snapshot == nil || len(snapshot.ModelStates) != 1 {
		t.Fatalf("adaptive snapshot = %+v", snapshot)
	}
	if got := snapshot.ModelStates[0].RoutingMode; got == "inject" {
		t.Fatal("failed WebSocket upgrade transitioned adaptive route")
	}
}
