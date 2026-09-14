package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

// Exercise the actual executor used by both Chat and Responses, including
// aliases shared by V4.1 and older V4 deployments. Public names must not
// override the identity of the deployment selected for this request.
func TestOpenAICompatExecutorDeepSeekV41EffortAliases(t *testing.T) {
	aliases := []string{"deepseek-v4.1-flash", "deepseek-latest-flash", "codex-auto-review", "gpt-5.6-luna", "gpt-5.6-terra"}
	levels := []string{"none", "minimal", "low", "medium", "high", "xhigh", "max", "ultra"}
	for _, upstreamModel := range []string{"deepseek-flash", "deepseek-v4-flash"} {
		for _, alias := range aliases {
			for _, format := range []string{"openai", "openai-response"} {
				for _, stream := range []bool{false, true} {
					for _, effort := range levels {
						t.Run(fmt.Sprintf("%s/%s/%s/stream=%t/%s", upstreamModel, alias, format, stream, effort), func(t *testing.T) {
							captured := make(chan []byte, 1)
							server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
								body, _ := io.ReadAll(r.Body)
								captured <- body
								if stream {
									w.Header().Set("Content-Type", "text/event-stream")
									fmt.Fprint(w, "data: {\"id\":\"chatcmpl-test\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"OK\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
								} else {
									w.Header().Set("Content-Type", "application/json")
									fmt.Fprint(w, `{"id":"chatcmpl-test","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}]}`)
								}
							}))
							defer server.Close()
							body := map[string]any{"model": alias, "stream": stream}
							if format == "openai" {
								body["messages"] = []map[string]string{{"role": "user", "content": "Reply OK"}}
								body["reasoning_effort"] = effort
							} else {
								body["input"] = "Reply OK"
								body["reasoning"] = map[string]string{"effort": effort}
							}
							payload, err := json.Marshal(body)
							if err != nil {
								t.Fatal(err)
							}
							request := cliproxyexecutor.Request{Model: upstreamModel, Payload: payload, Metadata: map[string]any{
								"cliproxy.resolved_api_key_model_info": &registry.ModelInfo{ID: upstreamModel, Type: "openai-compatibility", Thinking: &registry.ThinkingSupport{ZeroAllowed: true, Levels: levels}},
							}}
							opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString(format), OriginalRequest: payload, Stream: stream}
							auth := &cliproxyauth.Auth{Provider: "openai-compatibility", Attributes: map[string]string{"base_url": server.URL, "api_key": "test-key"}}
							executor := NewOpenAICompatExecutor("openai-compatibility", &config.Config{})
							if stream {
								result, err := executor.ExecuteStream(context.Background(), auth, request, opts)
								if err != nil {
									t.Fatal(err)
								}
								for chunk := range result.Chunks {
									if chunk.Err != nil {
										t.Fatal(chunk.Err)
									}
								}
							} else if _, err := executor.Execute(context.Background(), auth, request, opts); err != nil {
								t.Fatal(err)
							}
							var outbound []byte
							select {
							case outbound = <-captured:
							default:
								t.Fatal("upstream request was not made")
							}
							wantType, wantEffort := "enabled", effort
							switch effort {
							case "none":
								wantType, wantEffort = "disabled", ""
							case "minimal":
								wantEffort = "low"
							case "medium":
								wantEffort = "high"
							case "ultra":
								wantEffort = "max"
							case "xhigh":
								if upstreamModel == "deepseek-v4-flash" {
									wantEffort = "high"
								}
							}
							if got := gjson.GetBytes(outbound, "thinking.type").String(); got != wantType {
								t.Fatalf("thinking.type=%q, want %q", got, wantType)
							}
							got := gjson.GetBytes(outbound, "reasoning_effort")
							if got.String() != wantEffort || (wantEffort == "" && got.Exists()) {
								t.Fatalf("reasoning_effort=%s, want %q", got.Raw, wantEffort)
							}
						})
					}
				}
			}
		}
	}
}
