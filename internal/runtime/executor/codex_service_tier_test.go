package executor

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

type codexTierUsageCapture struct {
	authID  string
	records chan usage.Record
}

func (p *codexTierUsageCapture) HandleUsage(_ context.Context, record usage.Record) {
	if record.AuthID == p.authID {
		select {
		case p.records <- record:
		default:
		}
	}
}

func TestCodexExecutorsReportAutoAfterServiceTierFilter(t *testing.T) {
	for _, transport := range []string{"http", "websocket"} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%t", transport, stream), func(t *testing.T) {
				outbound := make(chan []byte, 1)
				completed := []byte(`{"type":"response.completed","response":{"id":"resp_tier","object":"response","status":"completed","model":"gpt-6-astra","service_tier":"default","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if transport == "websocket" {
						upgrader := websocket.Upgrader{}
						conn, err := upgrader.Upgrade(w, r, nil)
						if err != nil {
							t.Errorf("upgrade: %v", err)
							return
						}
						defer func() { _ = conn.Close() }()
						_, body, errRead := conn.ReadMessage()
						if errRead != nil {
							t.Errorf("read request: %v", errRead)
							return
						}
						outbound <- body
						if errWrite := conn.WriteMessage(websocket.TextMessage, completed); errWrite != nil {
							t.Errorf("write response: %v", errWrite)
						}
						return
					}
					body, errRead := io.ReadAll(r.Body)
					if errRead != nil {
						t.Errorf("read request: %v", errRead)
						return
					}
					outbound <- body
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = fmt.Fprintf(w, "event: response.completed\ndata: %s\n\n", completed)
				}))
				defer server.Close()
				cfg := &config.Config{
					SDKConfig: config.SDKConfig{DisableImageGeneration: config.DisableImageGenerationAll},
					Payload: config.PayloadConfig{Filter: []config.PayloadFilterRule{{
						Models: []config.PayloadModelRule{{Name: "*", Protocol: "codex"}},
						Params: []string{"service_tier"},
					}}},
				}
				auth := &cliproxyauth.Auth{ID: t.Name(), Provider: "codex", Attributes: map[string]string{
					"api_key": "tier-test-key", "base_url": server.URL,
				}}
				capture := &codexTierUsageCapture{authID: auth.ID, records: make(chan usage.Record, 1)}
				usage.RegisterPlugin(capture)
				req := cliproxyexecutor.Request{Model: "gpt-6-astra", Payload: []byte(`{"model":"gpt-6-astra","service_tier":"priority","input":[{"role":"user","content":"OK"}]}`)}
				opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai-response")}
				ctx := usage.WithServiceTier(context.Background(), "priority")
				var exec interface {
					Execute(context.Context, *cliproxyauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error)
					ExecuteStream(context.Context, *cliproxyauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error)
				}
				if transport == "websocket" {
					ws := NewCodexWebsocketsExecutor(cfg)
					ws.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
					defer ws.CloseExecutionSession(cliproxyauth.CloseAllExecutionSessionsID)
					exec = ws
				} else {
					exec = NewCodexExecutor(cfg)
				}
				if stream {
					result, err := exec.ExecuteStream(ctx, auth, req, opts)
					if err != nil {
						t.Fatalf("ExecuteStream: %v", err)
					}
					for chunk := range result.Chunks {
						if chunk.Err != nil {
							t.Fatalf("stream: %v", chunk.Err)
						}
					}
				} else if _, err := exec.Execute(ctx, auth, req, opts); err != nil {
					t.Fatalf("Execute: %v", err)
				}
				select {
				case body := <-outbound:
					if gjson.GetBytes(body, "service_tier").Exists() {
						t.Fatal("service_tier reached upstream after filter")
					}
				case <-time.After(2 * time.Second):
					t.Fatal("upstream did not receive a request")
				}
				select {
				case record := <-capture.records:
					if record.Failed || record.ServiceTier != "priority" || record.EffectiveServiceTier != "auto" || record.ResponseServiceTier != "default" {
						t.Fatalf("usage tiers = %q/%q/%q, failed=%t", record.ServiceTier, record.EffectiveServiceTier, record.ResponseServiceTier, record.Failed)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("usage record was not published")
				}
			})
		}
	}
}
