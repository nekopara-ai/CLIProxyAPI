package executor

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

const thinkingToolChoiceError = `{"error":{"param":null,"type":"invalid_request_error","code":"invalid_request_error","message":"Upstream request failed: [invalid_request_error] Thinking mode does not support this tool_choice"}}`

func TestOpenAICompatThinkingToolChoiceFallback(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, scenario := range []struct {
			name         string
			choice       string
			status       int
			errorBody    string
			alwaysReject bool
			wantCalls    int32
			wantError    bool
		}{
			{"required", `"required"`, 400, thinkingToolChoiceError, false, 2, false},
			{"named", `{"type":"function","function":{"name":"lookup"}}`, 400, thinkingToolChoiceError, false, 2, false},
			{"none", `"none"`, 400, thinkingToolChoiceError, false, 2, false},
			{"retry capped", `"required"`, 400, thinkingToolChoiceError, true, 2, true},
			{"unrelated 400", `"required"`, 400, `{"error":{"message":"invalid tool schema"}}`, false, 1, true},
			{"429", `"required"`, 429, thinkingToolChoiceError, false, 1, true},
			{"auto", `"auto"`, 400, thinkingToolChoiceError, false, 1, true},
			{"successful thinking", `"required"`, 200, "", false, 1, false},
		} {
			t.Run(fmt.Sprintf("stream=%v/%s", stream, scenario.name), func(t *testing.T) {
				var calls atomic.Int32
				var firstBody []byte
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, errRead := io.ReadAll(r.Body)
					if errRead != nil {
						t.Error(errRead)
					}
					attempt := calls.Add(1)
					if r.URL.Path != "/chat/completions" || r.Header.Get("Authorization") != "Bearer test-key" {
						t.Errorf("request routing or authentication changed")
					}
					if r.ContentLength != int64(len(body)) {
						t.Errorf("ContentLength = %d, body length = %d", r.ContentLength, len(body))
					}
					if attempt == 1 {
						firstBody = body
						if gjson.GetBytes(body, "thinking.type").String() == "disabled" {
							t.Error("thinking disabled before upstream rejection")
						}
					} else {
						if gjson.GetBytes(body, "thinking.type").String() != "disabled" || gjson.GetBytes(body, "reasoning_effort").Exists() {
							t.Errorf("thinking not disabled in fallback: %s", body)
						}
						for _, path := range []string{"model", "messages", "tools", "tool_choice", "stream", "stream_options", "max_tokens"} {
							if gjson.GetBytes(body, path).Raw != gjson.GetBytes(firstBody, path).Raw {
								t.Errorf("fallback changed %s", path)
							}
						}
					}
					if scenario.status != 200 && (attempt == 1 || scenario.alwaysReject) {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(scenario.status)
						_, _ = io.WriteString(w, scenario.errorBody)
						return
					}
					if stream {
						w.Header().Set("Content-Type", "text/event-stream")
						_, _ = io.WriteString(w, "data: {\"id\":\"chatcmpl-test\",\"object\":\"chat.completion.chunk\",\"model\":\"test-model\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
					} else {
						w.Header().Set("Content-Type", "application/json")
						_, _ = io.WriteString(w, `{"id":"chatcmpl-test","object":"chat.completion","model":"test-model","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
					}
				}))
				defer server.Close()
				executor := NewOpenAICompatExecutor("openai-compatibility", &config.Config{})
				auth := &cliproxyauth.Auth{Provider: "openai-compatibility", Attributes: map[string]string{"base_url": server.URL, "api_key": "test-key"}}
				payload := []byte(fmt.Sprintf(`{"model":"test-model","messages":[{"role":"user","content":"lookup"}],"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object","properties":{}}}}],"tool_choice":%s,"thinking":{"type":"enabled"},"reasoning_effort":"high","max_tokens":32,"stream":%v}`, scenario.choice, stream))
				req := cliproxyexecutor.Request{Model: "test-model", Payload: payload}
				opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAI, Stream: stream}
				var err error
				if stream {
					var result *cliproxyexecutor.StreamResult
					result, err = executor.ExecuteStream(context.Background(), auth, req, opts)
					if err == nil {
						var received bool
						for chunk := range result.Chunks {
							if chunk.Err != nil {
								t.Errorf("stream error: %v", chunk.Err)
							}
							received = received || len(chunk.Payload) > 0
						}
						if !received {
							t.Error("no stream response after fallback")
						}
					}
				} else {
					var result cliproxyexecutor.Response
					result, err = executor.Execute(context.Background(), auth, req, opts)
					if err == nil && gjson.GetBytes(result.Payload, "choices.0.message.content").String() != "ok" {
						t.Errorf("unexpected response: %s", result.Payload)
					}
				}
				if (err != nil) != scenario.wantError {
					t.Errorf("error = %v, wantError = %v", err, scenario.wantError)
				}
				if calls.Load() != scenario.wantCalls {
					t.Errorf("upstream calls = %d, want %d", calls.Load(), scenario.wantCalls)
				}
			})
		}
	}
}
