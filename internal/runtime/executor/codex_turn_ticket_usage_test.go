package executor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	coreusage "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

func ticketUsageCapture(t *testing.T) (context.Context, *multiProviderUsageCapture) {
	t.Helper()
	capture := &multiProviderUsageCapture{alias: t.Name(), records: make(chan coreusage.Record, 8)}
	coreusage.RegisterNamedPlugin(t.Name(), capture)
	t.Cleanup(func() { coreusage.RegisterNamedPlugin(t.Name(), multiProviderNoopUsagePlugin{}) })
	return coreusage.WithRequestedModelAlias(context.Background(), t.Name()), capture
}

const ticketUsageTerminal = `{"type":"response.completed","response":{"id":"resp_ticket","object":"response","status":"completed","output":[{"id":"msg_ticket","type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"ok"}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`

func TestCodexHTTPUsageRecordsActualRequestTicketWithoutResponseTicket(t *testing.T) {
	for _, mode := range []string{"stream", "nonstream", "compact", "failure"} {
		for _, source := range []string{"cache", "passthrough", "none", "injection_off_passthrough", "injection_off_none"} {
			t.Run(mode+"/"+source, func(t *testing.T) {
				ctx, capture := ticketUsageCapture(t)
				healthy := integrationTurnState(t, time.Now().Unix(), 292)
				degraded := integrationTurnState(t, time.Now().Unix(), 312)
				var seen atomic.Int64
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					seen.Store(int64(len(r.Header.Get(helps.CodexTurnStateHeader))))
					if mode == "failure" {
						w.WriteHeader(http.StatusBadRequest)
						_, _ = w.Write([]byte(`{"error":{"message":"fixture rejection"}}`))
						return
					}
					if mode == "compact" {
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write([]byte(`{"id":"resp_compact","object":"response.compaction","output":[],"usage":{"input_tokens":1,"output_tokens":1}}`))
						return
					}
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = fmt.Fprintf(w, "data: %s\n\n", ticketUsageTerminal)
				}))
				defer server.Close()
				cfg := turnTicketLegacyIntegrationConfig("gpt-5.5")
				cfg.DisableImageGeneration = config.DisableImageGenerationAll
				injectionOff := strings.HasPrefix(source, "injection_off_")
				wantSource := strings.TrimPrefix(source, "injection_off_")
				if injectionOff {
					off := false
					cfg.Codex.TurnTicket.InjectionEnabled = &off
				}
				process := helps.ConfigureCodexTurnTickets(func() *config.Config { return cfg }, nil)
				defer helps.ConfigureCodexTurnTickets(nil, nil)
				if source == "cache" || injectionOff {
					process.Store.Store("ticket-auth", "gpt-5.5", helps.NewCodexTurnTicket(healthy, time.Now(), time.Hour))
				}
				auth := &cliproxyauth.Auth{ID: "ticket-auth", Index: "ticket-index", Provider: "codex", Attributes: map[string]string{"api_key": "fixture", "base_url": server.URL}, ProxyURL: "direct"}
				headers := http.Header{}
				wantLength := 0
				if wantSource != "none" {
					headers.Set(helps.CodexTurnStateHeader, degraded)
					wantLength = 312
				}
				if source == "cache" {
					wantLength = 292
				}
				opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai-response"), Headers: headers}
				req := cliproxyexecutor.Request{Model: "gpt-5.5", Payload: []byte(`{"model":"gpt-5.5","input":"hello"}`)}
				exec := NewCodexExecutor(cfg)
				var err error
				if mode == "stream" {
					var result *cliproxyexecutor.StreamResult
					result, err = exec.ExecuteStream(ctx, auth, req, opts)
					if err == nil {
						for chunk := range result.Chunks {
							if chunk.Err != nil {
								t.Fatal(chunk.Err)
							}
						}
					}
				} else {
					if mode == "compact" {
						opts.Alt = "responses/compact"
					}
					_, err = exec.Execute(ctx, auth, req, opts)
				}
				if (err != nil) != (mode == "failure") {
					t.Fatalf("unexpected execution error: %v", err)
				}
				record := capture.await(t)
				if record.CodexTurnState == nil || record.CodexTurnState.RequestLength != wantLength || record.CodexTurnState.RequestSource != wantSource {
					t.Fatalf("record ticket = %+v", record.CodexTurnState)
				}
				if int(seen.Load()) != wantLength || record.AuthIndex != "ticket-index" || record.CodexTurnState.RequestScope != "" {
					t.Fatal("actual header/credential/scope attribution mismatch")
				}
				if record.ResponseHeaders.Get(helps.CodexTurnStateHeader) != "" {
					t.Fatal("request ticket leaked into response headers")
				}
			})
		}
	}
}

func TestCodexWebsocketUsageKeepsPhysicalHandshakeTicketOnReuse(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprint(stream), func(t *testing.T) {
			ctx, capture := ticketUsageCapture(t)
			var handshakes atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handshakes.Add(1)
				if len(r.Header.Get(helps.CodexTurnStateHeader)) != 312 {
					t.Error("initial handshake did not use passthrough ticket")
				}
				conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
				if err != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				for {
					if _, _, err := conn.ReadMessage(); err != nil {
						return
					}
					if err := conn.WriteMessage(websocket.TextMessage, []byte(ticketUsageTerminal)); err != nil {
						return
					}
				}
			}))
			defer server.Close()
			cfg := turnTicketLegacyIntegrationConfig("gpt-5.5")
			cfg.DisableImageGeneration = config.DisableImageGenerationAll
			process := helps.ConfigureCodexTurnTickets(func() *config.Config { return cfg }, nil)
			defer helps.ConfigureCodexTurnTickets(nil, nil)
			exec := NewCodexWebsocketsExecutor(cfg)
			defer exec.CloseExecutionSession(t.Name())
			auth := &cliproxyauth.Auth{ID: "ws-ticket-auth", Index: "ws-ticket-index", Provider: "codex", Attributes: map[string]string{"api_key": "fixture", "base_url": server.URL}, ProxyURL: "direct"}
			headers := http.Header{helps.CodexTurnStateHeader: []string{strings.Repeat("d", 312)}}
			opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai-response"), Headers: headers, Metadata: map[string]any{cliproxyexecutor.ExecutionSessionMetadataKey: t.Name()}}
			for attempt := 0; attempt < 2; attempt++ {
				if attempt == 1 {
					// The second request constructs a cache-injected header, but reuses
					// the connection that actually sent a passthrough 312 at handshake.
					process.Store.Store(auth.ID, "gpt-5.5", helps.NewCodexTurnTicket(integrationTurnState(t, time.Now().Unix(), 292), time.Now(), time.Hour))
				}
				req := cliproxyexecutor.Request{Model: "gpt-5.5", Payload: []byte(`{"model":"gpt-5.5","input":"hello"}`)}
				if stream {
					result, err := exec.ExecuteStream(ctx, auth, req, opts)
					if err != nil {
						t.Fatal(err)
					}
					for chunk := range result.Chunks {
						if chunk.Err != nil {
							t.Fatal(chunk.Err)
						}
					}
				} else if _, err := exec.Execute(ctx, auth, req, opts); err != nil {
					t.Fatal(err)
				}
				record := capture.await(t)
				if record.CodexTurnState == nil || *record.CodexTurnState != (coreusage.CodexTurnStateObservation{RequestLength: 312, RequestSource: "passthrough", RequestScope: "websocket_handshake"}) {
					t.Fatalf("attempt %d falsely reported unsent cache header: %+v", attempt, record.CodexTurnState)
				}
			}
			if handshakes.Load() != 1 {
				t.Fatalf("expected one reused handshake, got %d", handshakes.Load())
			}
		})
	}
}

func TestCodexWebsocketUsageConnectionChangesAndFailedHandshake(t *testing.T) {
	for _, scenario := range []string{"replacement", "unknown_connection", "rejected_handshake", "dial_failure", "retired_connection"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, capture := ticketUsageCapture(t)
			reporter := helps.NewUsageReporter(ctx, "codex", "gpt-5.5", nil)
			original := &websocket.Conn{}
			replacement := &websocket.Conn{}
			sess := &codexWebsocketSession{conn: original}
			headers := http.Header{helps.CodexTurnStateHeader: []string{strings.Repeat("d", 312)}}
			recordCodexWebsocketTurnState(reporter, sess, original, &http.Response{StatusCode: 101}, headers, false)
			var want *coreusage.CodexTurnStateObservation
			switch scenario {
			case "replacement":
				sess.conn = replacement
				headers.Set(helps.CodexTurnStateHeader, strings.Repeat("h", 292))
				recordCodexWebsocketTurnState(reporter, sess, replacement, &http.Response{StatusCode: 101}, headers, true)
				// Reading the replacement again must retain its own observation.
				recordCodexWebsocketTurnState(reporter, sess, replacement, nil, nil, false)
				want = &coreusage.CodexTurnStateObservation{RequestLength: 292, RequestSource: "cache", RequestScope: "websocket_handshake"}
			case "unknown_connection":
				sess.conn = replacement
				recordCodexWebsocketTurnState(reporter, sess, replacement, nil, headers, true)
			case "rejected_handshake":
				sess.conn = nil
				recordCodexWebsocketTurnState(reporter, sess, nil, &http.Response{StatusCode: 403}, nil, false)
				want = &coreusage.CodexTurnStateObservation{RequestLength: 0, RequestSource: "none", RequestScope: "websocket_handshake"}
			case "dial_failure":
				sess.conn = nil
				recordCodexWebsocketTurnState(reporter, sess, nil, nil, headers, true)
			case "retired_connection":
				sess.conn = replacement
				recordCodexWebsocketTurnState(reporter, sess, original, nil, headers, true)
			}
			reporter.Publish(ctx, coreusage.Detail{InputTokens: 1, TotalTokens: 1})
			got := capture.await(t).CodexTurnState
			if (got == nil) != (want == nil) || (got != nil && *got != *want) {
				t.Fatalf("observation = %+v, want %+v", got, want)
			}
		})
	}
}

func TestCodexWebsocketInjectionOffKeepsCachedTicketOutOfHandshake(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprint(stream), func(t *testing.T) {
			ctx, capture := ticketUsageCapture(t)
			var handshakes atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handshakes.Add(1)
				if len(r.Header.Get(helps.CodexTurnStateHeader)) != 312 {
					t.Error("initial handshake did not use passthrough ticket")
				}
				conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
				if err != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				for {
					if _, _, err := conn.ReadMessage(); err != nil {
						return
					}
					if err := conn.WriteMessage(websocket.TextMessage, []byte(ticketUsageTerminal)); err != nil {
						return
					}
				}
			}))
			defer server.Close()
			cfg := turnTicketLegacyIntegrationConfig("gpt-5.5")
			cfg.DisableImageGeneration = config.DisableImageGenerationAll
			off := false
			cfg.Codex.TurnTicket.InjectionEnabled = &off
			process := helps.ConfigureCodexTurnTickets(func() *config.Config { return cfg }, nil)
			defer helps.ConfigureCodexTurnTickets(nil, nil)
			exec := NewCodexWebsocketsExecutor(cfg)
			defer exec.CloseExecutionSession(t.Name())
			auth := &cliproxyauth.Auth{ID: "ws-ticket-auth", Index: "ws-ticket-index", Provider: "codex", Attributes: map[string]string{"api_key": "fixture", "base_url": server.URL}, ProxyURL: "direct"}
			process.Store.Store(auth.ID, "gpt-5.5", helps.NewCodexTurnTicket(integrationTurnState(t, time.Now().Unix(), 292), time.Now(), time.Hour))
			headers := http.Header{helps.CodexTurnStateHeader: []string{strings.Repeat("d", 312)}}
			opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai-response"), Headers: headers, Metadata: map[string]any{cliproxyexecutor.ExecutionSessionMetadataKey: t.Name()}}
			for attempt := 0; attempt < 2; attempt++ {
				req := cliproxyexecutor.Request{Model: "gpt-5.5", Payload: []byte(`{"model":"gpt-5.5","input":"hello"}`)}
				if stream {
					result, err := exec.ExecuteStream(ctx, auth, req, opts)
					if err != nil {
						t.Fatal(err)
					}
					for chunk := range result.Chunks {
						if chunk.Err != nil {
							t.Fatal(chunk.Err)
						}
					}
				} else if _, err := exec.Execute(ctx, auth, req, opts); err != nil {
					t.Fatal(err)
				}
				record := capture.await(t)
				if record.CodexTurnState == nil || *record.CodexTurnState != (coreusage.CodexTurnStateObservation{RequestLength: 312, RequestSource: "passthrough", RequestScope: "websocket_handshake"}) {
					t.Fatalf("attempt %d falsely reported unsent cache header: %+v", attempt, record.CodexTurnState)
				}
			}
			if handshakes.Load() != 1 {
				t.Fatalf("expected one reused handshake, got %d", handshakes.Load())
			}
		})
	}
}
