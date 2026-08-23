package executor

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

const (
	codexWebsocketIncompleteOutputItem = `{"type":"response.output_item.done","output_index":0,"item":{"id":"msg_1","type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"partial answer"}]}}`
	codexWebsocketIncompleteTerminal   = `{"type":"response.incomplete","response":{"id":"resp_1","status":"incomplete","incomplete_details":{"reason":"max_output_tokens"},"output":[],"usage":{"input_tokens":10,"output_tokens":5,"total_tokens":15}}}`
	codexWebsocketIncompleteWithOutput = `{"type":"response.incomplete","response":{"id":"resp_1","status":"incomplete","incomplete_details":{"reason":"max_output_tokens"},"output":[{"id":"msg_1","type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"partial answer"}]}],"usage":{"input_tokens":10,"output_tokens":5,"total_tokens":15}}}`
)

func newCodexIncompleteWebsocketServer(t *testing.T, frames ...string) *httptest.Server {
	t.Helper()

	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, errUpgrade := upgrader.Upgrade(w, r, nil)
		if errUpgrade != nil {
			t.Errorf("upgrade websocket: %v", errUpgrade)
			return
		}
		defer func() {
			if errClose := conn.Close(); errClose != nil {
				t.Errorf("close websocket: %v", errClose)
			}
		}()

		if _, _, errRead := conn.ReadMessage(); errRead != nil {
			t.Errorf("read websocket request: %v", errRead)
			return
		}
		for _, frame := range frames {
			if errWrite := conn.WriteMessage(websocket.TextMessage, []byte(frame)); errWrite != nil {
				t.Errorf("write websocket frame: %v", errWrite)
				return
			}
		}
	}))
}

func codexIncompleteWebsocketAuth(baseURL string) *cliproxyauth.Auth {
	return &cliproxyauth.Auth{
		Provider: "codex",
		Attributes: map[string]string{
			"api_key":  "test-key",
			"base_url": baseURL,
		},
	}
}

func codexIncompleteWebsocketRequest(sourceFormat sdktranslator.Format) (cliproxyexecutor.Request, cliproxyexecutor.Options) {
	return cliproxyexecutor.Request{
			Model:   "gpt-5.6-terra",
			Payload: []byte(`{"model":"gpt-5.6-terra","messages":[{"role":"user","content":"hello"}]}`),
		}, cliproxyexecutor.Options{
			SourceFormat: sourceFormat,
			Stream:       true,
		}
}

func TestCodexWebsocketsExecuteIncompleteIsSuccessfulTerminal(t *testing.T) {
	server := newCodexIncompleteWebsocketServer(t, codexWebsocketIncompleteOutputItem, codexWebsocketIncompleteTerminal)
	defer server.Close()

	exec := NewCodexWebsocketsExecutor(&config.Config{SDKConfig: config.SDKConfig{DisableImageGeneration: config.DisableImageGenerationAll}})
	req, opts := codexIncompleteWebsocketRequest(sdktranslator.FromString("claude"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, errExecute := exec.Execute(ctx, codexIncompleteWebsocketAuth(server.URL), req, opts)
	if errExecute != nil {
		t.Fatalf("Execute() returned an EOF/terminal error after response.incomplete: %v", errExecute)
	}
	if got := gjson.GetBytes(resp.Payload, "content.0.text").String(); got != "partial answer" {
		t.Fatalf("content.0.text = %q, want partial answer; payload=%s", got, resp.Payload)
	}
	if got := gjson.GetBytes(resp.Payload, "stop_reason").String(); got != "max_tokens" {
		t.Fatalf("stop_reason = %q, want max_tokens; payload=%s", got, resp.Payload)
	}
	if got := gjson.GetBytes(resp.Payload, "usage.input_tokens").Int(); got != 10 {
		t.Fatalf("usage.input_tokens = %d, want 10; payload=%s", got, resp.Payload)
	}
	if got := gjson.GetBytes(resp.Payload, "usage.output_tokens").Int(); got != 5 {
		t.Fatalf("usage.output_tokens = %d, want 5; payload=%s", got, resp.Payload)
	}
}

func TestCodexWebsocketsExecuteStreamIncompleteIsSuccessfulTerminal(t *testing.T) {
	tests := []struct {
		name                string
		bootstrapBuffering  bool
		downstreamWebsocket bool
	}{
		{name: "unbuffered translated stream"},
		{name: "buffered translated stream", bootstrapBuffering: true},
		{name: "buffered downstream websocket", bootstrapBuffering: true, downstreamWebsocket: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := newCodexIncompleteWebsocketServer(t, codexWebsocketIncompleteWithOutput)
			defer server.Close()

			exec := NewCodexWebsocketsExecutor(&config.Config{
				SDKConfig: config.SDKConfig{DisableImageGeneration: config.DisableImageGenerationAll},
				Codex:     config.CodexConfig{StreamBootstrapBuffering: tc.bootstrapBuffering},
			})
			req, opts := codexIncompleteWebsocketRequest(sdktranslator.FromString("openai-response"))

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if tc.downstreamWebsocket {
				ctx = cliproxyexecutor.WithDownstreamWebsocket(ctx)
			}

			result, errExecute := exec.ExecuteStream(ctx, codexIncompleteWebsocketAuth(server.URL), req, opts)
			if errExecute != nil {
				t.Fatalf("ExecuteStream() returned an EOF/terminal error after response.incomplete: %v", errExecute)
			}
			if result == nil {
				t.Fatal("ExecuteStream() returned a nil result")
			}

			var payload bytes.Buffer
			for chunk := range result.Chunks {
				if chunk.Err != nil {
					t.Fatalf("stream returned an EOF/terminal chunk error after response.incomplete: %v", chunk.Err)
				}
				payload.Write(chunk.Payload)
			}
			stream := payload.String()
			for _, want := range []string{
				`"type":"response.incomplete"`,
				`"text":"partial answer"`,
				`"input_tokens":10`,
				`"output_tokens":5`,
			} {
				if !strings.Contains(stream, want) {
					t.Fatalf("stream is missing %s: %s", want, stream)
				}
			}
		})
	}
}
