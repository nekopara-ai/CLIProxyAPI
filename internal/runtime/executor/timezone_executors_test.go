package executor

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	_ "github.com/router-for-me/CLIProxyAPI/v7/internal/translator"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

const timezoneExecutorEnvText = "<environment_context>\n  <cwd>/repo</cwd>\n  <current_date>2026-09-15</current_date>\n  <timezone>Asia/Shanghai</timezone>\n</environment_context>"

// timezoneExecutorExpectedDates returns the dates the rewrite may legitimately
// emit. Two values are returned so a run that crosses local midnight between the
// executor call and the assertion does not flake.
func timezoneExecutorExpectedDates(t *testing.T) []string {
	t.Helper()
	location, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatalf("load location: %v", err)
	}
	now := time.Now().In(location)
	return []string{now.Format("2006-01-02"), now.AddDate(0, 0, -1).Format("2006-01-02")}
}

func timezoneExecutorDateMatches(t *testing.T, got string) bool {
	t.Helper()
	for _, want := range timezoneExecutorExpectedDates(t) {
		if got == want {
			return true
		}
	}
	return false
}

func timezoneExecutorXMLTag(text, name string) string {
	open := "<" + name + ">"
	close := "</" + name + ">"
	from := -1
	for i := 0; i+len(open) <= len(text); i++ {
		if text[i:i+len(open)] == open {
			from = i + len(open)
			break
		}
	}
	if from < 0 {
		return ""
	}
	for i := from; i+len(close) <= len(text); i++ {
		if text[i:i+len(close)] == close {
			return text[from:i]
		}
	}
	return ""
}

// The user-visible gap: requests served by the OpenAI-compatible executor must
// carry the configured timezone, even though that executor never called
// ApplyTimezoneOverride directly.
func TestOpenAICompatExecutorAppliesTimezoneOverride(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			captured := make(chan []byte, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				captured <- body
				if stream {
					w.Header().Set("Content-Type", "text/event-stream")
					fmt.Fprint(w, "data: {\"id\":\"chatcmpl-tz\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"OK\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
					return
				}
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"id":"chatcmpl-tz","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}]}`)
			}))
			defer server.Close()

			payload := []byte(`{"model":"deepseek-v4.1-flash","messages":[{"role":"user","content":"` + timezoneExecutorEnvText + `"}],"tools":[{"type":"web_search","user_location":{"type":"approximate","city":"Shanghai","timezone":"Asia/Shanghai"}}]}`)
			request := cliproxyexecutor.Request{Model: "deepseek-v4.1-flash", Payload: payload}
			opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai"), OriginalRequest: payload, Stream: stream}
			auth := &cliproxyauth.Auth{Provider: "openai-compatibility", Attributes: map[string]string{"base_url": server.URL, "api_key": "test-key"}}
			exec := NewOpenAICompatExecutor("openai-compatibility", &config.Config{TimezoneOverride: "America/New_York"})

			if stream {
				result, err := exec.ExecuteStream(context.Background(), auth, request, opts)
				if err != nil {
					t.Fatalf("ExecuteStream() error = %v", err)
				}
				for chunk := range result.Chunks {
					if chunk.Err != nil {
						t.Fatalf("stream chunk error = %v", chunk.Err)
					}
				}
			} else if _, err := exec.Execute(context.Background(), auth, request, opts); err != nil {
				t.Fatalf("Execute() error = %v", err)
			}

			var outbound []byte
			select {
			case outbound = <-captured:
			default:
				t.Fatal("upstream request was not made")
			}
			if got := gjson.GetBytes(outbound, "messages.0.content").String(); timezoneExecutorXMLTag(got, "timezone") != "America/New_York" {
				t.Fatalf("environment timezone not rewritten; content=%q body=%s", got, outbound)
			}
			if content := gjson.GetBytes(outbound, "messages.0.content").String(); !timezoneExecutorDateMatches(t, timezoneExecutorXMLTag(content, "current_date")) {
				t.Fatalf("environment current_date not rewritten; content=%q body=%s", content, outbound)
			}
			if got := gjson.GetBytes(outbound, "tools.0.user_location.timezone").String(); got != "America/New_York" {
				t.Fatalf("user_location.timezone = %q, want America/New_York; body=%s", got, outbound)
			}
		})
	}
}

// The xAI executor also bypassed the direct rewrite call sites.
func TestXAIExecutorAppliesTimezoneOverride(t *testing.T) {
	captured := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		captured <- body
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_tz\",\"object\":\"response\",\"created_at\":0,\"status\":\"completed\",\"model\":\"grok-4.6\",\"output\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1,\"total_tokens\":2}}}\n\n"))
	}))
	defer server.Close()

	payload := []byte(`{"model":"grok-4.6","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"` + timezoneExecutorEnvText + `"}]}],"stream":true}`)
	exec := NewXAIExecutor(&config.Config{TimezoneOverride: "America/New_York"})
	auth := &cliproxyauth.Auth{
		ID:         "xai-auth",
		Provider:   "xai",
		Attributes: map[string]string{"base_url": server.URL, "auth_kind": "oauth"},
		Metadata:   map[string]any{"access_token": "xai-token"},
	}
	_, err := exec.Execute(context.Background(), auth, cliproxyexecutor.Request{Model: "grok-4.6", Payload: payload}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	var outbound []byte
	select {
	case outbound = <-captured:
	default:
		t.Fatal("upstream request was not made")
	}
	text := gjson.GetBytes(outbound, "input.0.content.0.text").String()
	if timezoneExecutorXMLTag(text, "timezone") != "America/New_York" {
		t.Fatalf("xai environment timezone not rewritten; text=%q body=%s", text, outbound)
	}
	if !timezoneExecutorDateMatches(t, timezoneExecutorXMLTag(text, "current_date")) {
		t.Fatalf("xai environment current_date not rewritten; text=%q body=%s", text, outbound)
	}
}
