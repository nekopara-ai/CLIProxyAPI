package executor

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
)

// Record the actual HTTP/WS wire body: testing the helper alone cannot prove
// that a transport uses it after payload overrides or on a compaction request.
func TestCodexWebSearchHistoryAcrossTransports(t *testing.T) {
	for _, transport := range []string{"http", "http-stream", "websocket", "websocket-stream"} {
		for _, lite := range []string{"", "header", "metadata"} {
			for _, apiKey := range []bool{false, true} {
				for _, override := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/lite=%s/api-key=%t/override=%t", transport, lite, apiKey, override), func(t *testing.T) {
						captured := make(chan []byte, 1)
						created := `{"type":"response.created","response":{"id":"resp_search_history","status":"in_progress","output":[]}}`
						completed := `{"type":"response.completed","response":{"id":"resp_search_history","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ok"}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`
						wsTransport := transport == "websocket" || transport == "websocket-stream"
						server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							if wsTransport {
								upgrader := websocket.Upgrader{}
								conn, err := upgrader.Upgrade(w, r, nil)
								if err != nil {
									t.Error(err)
									return
								}
								defer func() { _ = conn.Close() }()
								_, body, errRead := conn.ReadMessage()
								if errRead != nil {
									t.Error(errRead)
									return
								}
								captured <- body
								for _, event := range []string{created, completed} {
									if errWrite := conn.WriteMessage(websocket.TextMessage, []byte(event)); errWrite != nil {
										t.Error(errWrite)
									}
								}
								return
							}
							body, errRead := io.ReadAll(r.Body)
							if errRead != nil {
								t.Error(errRead)
								return
							}
							captured <- body
							w.Header().Set("Content-Type", "text/event-stream")
							_, _ = fmt.Fprintf(w, "data: %s\n\ndata: %s\n\n", created, completed)
						}))
						defer server.Close()
						history := `[{"type":"message","role":"user","content":[{"type":"input_text","text":"Find docs"}]},{"type":"web_search_call","id":"ws_test","status":"completed","action":{"type":"search","query":"asyncio","sources":[{"type":"url","url":"https://docs.python.org/3/library/asyncio.html"}]}},{"type":"compaction_trigger"}]`
						payload := []byte(`{"model":"gpt-6.1-sol","input":` + history + `,"tools":[],"tool_choice":"auto","instructions":"Summarize."`)
						headers := http.Header{}
						if lite == "header" {
							headers.Set(codexResponsesLiteHeader, "true")
						} else if lite == "metadata" {
							payload = append(payload, []byte(`,"client_metadata":{"ws_request_header_x_openai_internal_codex_responses_lite":"true"}`)...)
						}
						payload = append(payload, '}')
						auth := &cliproxyauth.Auth{ID: t.Name(), Provider: "codex", Attributes: map[string]string{"base_url": server.URL}, Metadata: map[string]any{"type": "codex", "access_token": "synthetic-oauth", "account_id": "synthetic-account"}}
						if apiKey {
							auth.Attributes["api_key"] = "synthetic-api-key"
						}
						cfg := &config.Config{Codex: config.CodexConfig{DisableCodexCloaking: true}}
						cfg.DisableImageGeneration = config.DisableImageGenerationAll
						if override {
							// Simulate an operator rule clearing caller-supplied tools.
							payload = bytes.Replace(payload, []byte(`"tools":[]`), []byte(`"tools":[{"type":"function","name":"exec","parameters":{"type":"object"}}]`), 1)
							cfg.Payload.Override = []config.PayloadRule{{
								Models: []config.PayloadModelRule{{Name: "gpt-*", Protocol: "codex"}},
								Params: map[string]any{"tools": []any{}, "tool_choice": "auto"},
							}}
						}
						httpExec := NewCodexExecutor(cfg)
						wsExec := NewCodexWebsocketsExecutor(cfg)
						defer wsExec.CloseExecutionSession(cliproxyauth.CloseAllExecutionSessionsID)
						req := cliproxyexecutor.Request{Model: "gpt-6.1-sol", Payload: payload}
						opts := cliproxyexecutor.Options{SourceFormat: translator.FormatCodex, ResponseFormat: translator.FormatCodex, Headers: headers}
						if transport == "http-stream" || transport == "websocket-stream" {
							execute := httpExec.ExecuteStream
							if wsTransport {
								execute = wsExec.ExecuteStream
							}
							result, err := execute(context.Background(), auth, req, opts)
							if err != nil {
								t.Fatal(err)
							}
							var all []byte
							for chunk := range result.Chunks {
								if chunk.Err != nil {
									t.Fatal(chunk.Err)
								}
								all = append(all, chunk.Payload...)
							}
							if !bytes.Contains(all, []byte("response.completed")) {
								t.Fatal("no completed response")
							}
						} else {
							execute := httpExec.Execute
							if wsTransport {
								execute = wsExec.Execute
							}
							if _, err := execute(context.Background(), auth, req, opts); err != nil {
								t.Fatal(err)
							}
						}
						select {
						case body := <-captured:
							if gjson.GetBytes(body, `input.#(type=="web_search_call").action.sources.0.url`).String() != "https://docs.python.org/3/library/asyncio.html" {
								t.Fatalf("lost search action/sources: %s", body)
							}
							items := gjson.GetBytes(body, "input").Array()
							if items[len(items)-1].Get("type").String() != "compaction_trigger" {
								t.Fatal("trigger no longer last")
							}
							searchPath := `tools.#(type=="web_search")`
							if lite != "" {
								searchPath = `input.#(type=="additional_tools").tools.#(type=="web_search")`
							}
							search := gjson.GetBytes(body, searchPath)
							if apiKey {
								if search.Exists() || gjson.GetBytes(body, "tool_choice").String() != "auto" {
									t.Fatalf("API-key request changed: %s", body)
								}
							} else if !search.Exists() || search.Get("external_web_access").Type != gjson.False || gjson.GetBytes(body, "tool_choice").String() != "none" {
								t.Fatalf("OAuth wire body lacks compatibility rewrite: %s", body)
							}
						default:
							t.Fatal("upstream never received request")
						}
					})
				}
			}
		}
	}
}

func TestCodexWebSearchHistoryCompactBuilderUnchanged(t *testing.T) {
	exec := NewCodexExecutor(&config.Config{})
	body := []byte(`{"input":[{"type":"web_search_call","id":"ws_test"}],"tools":[]}`)
	auth := &cliproxyauth.Auth{Metadata: map[string]any{"type": "codex", "access_token": "synthetic"}}
	req := cliproxyexecutor.Request{Payload: body}
	_, got, _, err := exec.cacheHelper(context.Background(), translator.FormatCodex, "http://example.invalid/responses/compact", auth, req, body, body)
	if err != nil {
		t.Fatal(err)
	}
	if gjson.GetBytes(got, "tools").Raw != "[]" || gjson.GetBytes(got, "tool_choice").Exists() {
		t.Fatalf("dedicated compact shape was rewritten: %s", got)
	}
}
