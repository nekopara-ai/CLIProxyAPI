package executor

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

func TestCodexEncryptedInputNeverReachesUpstream(t *testing.T) {
	for _, transport := range []string{"http", "sse", "compact", "websocket", "websocket-stream"} {
		for _, item := range []string{
			`{"type":"compaction","encrypted_content":"gAAAA... (litellm_truncated)"}`,
			`{"type":"function_call_output","call_id":"call_test","output":[{"type":"encrypted_content","encrypted_content":"invalid!"}]}`,
			`{"type":"custom_tool_call_output","call_id":"call_test","encrypted_content":null,"output":"keep"}`,
		} {
			t.Run(transport+"/"+gjson.Get(item, "type").String(), func(t *testing.T) {
				var calls atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					calls.Add(1)
					w.WriteHeader(http.StatusBadGateway)
				}))
				defer server.Close()
				cfg := &config.Config{}
				auth := newCodexSignatureTestAuth(server.URL)
				req := cliproxyexecutor.Request{Model: "gpt-5.4", Payload: []byte(`{"model":"gpt-5.4","input":[` + item + `]}`)}
				opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse}
				var err error
				switch transport {
				case "http":
					_, err = NewCodexExecutor(cfg).Execute(context.Background(), auth, req, opts)
				case "compact":
					opts.Alt = "responses/compact"
					_, err = NewCodexExecutor(cfg).Execute(context.Background(), auth, req, opts)
				case "sse":
					_, err = NewCodexExecutor(cfg).ExecuteStream(context.Background(), auth, req, opts)
				case "websocket":
					_, err = NewCodexWebsocketsExecutor(cfg).Execute(context.Background(), auth, req, opts)
				case "websocket-stream":
					_, err = NewCodexWebsocketsExecutor(cfg).ExecuteStream(context.Background(), auth, req, opts)
				}
				var status interface{ StatusCode() int }
				var scoped cliproxyexecutor.RequestScopedError
				if !errors.As(err, &status) || status.StatusCode() != 400 || !errors.As(err, &scoped) || !scoped.IsRequestScoped() {
					t.Fatalf("expected local request-scoped 400, got %v", err)
				}
				if gjson.Get(err.Error(), "error.code").String() != "invalid_encrypted_content" {
					t.Fatalf("unexpected error: %v", err)
				}
				if calls.Load() != 0 {
					t.Fatalf("upstream received %d requests", calls.Load())
				}
			})
		}
	}
}

func TestCodexEncryptedInputPreservedAtUpstream(t *testing.T) {
	valid := validCodexReasoningEncryptedContentForTest()
	input := `[{"type":"compaction","encrypted_content":"` + valid + `"},{"type":"function_call_output","call_id":"call_test","output":[{"type":"encrypted_content","encrypted_content":"` + valid + `"}]}]`
	for _, transport := range []string{"http", "sse", "compact", "websocket", "websocket-stream"} {
		t.Run(transport, func(t *testing.T) {
			captured := make(chan []byte, 1)
			completed := []byte(`{"type":"response.completed","response":{"id":"resp_guard","object":"response","status":"completed","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if websocket.IsWebSocketUpgrade(r) {
					upgrader := websocket.Upgrader{}
					conn, errUpgrade := upgrader.Upgrade(w, r, nil)
					if errUpgrade != nil {
						t.Error(errUpgrade)
						return
					}
					defer func() { _ = conn.Close() }()
					_, body, errRead := conn.ReadMessage()
					if errRead != nil {
						t.Error(errRead)
						return
					}
					captured <- body
					if errWrite := conn.WriteMessage(websocket.TextMessage, completed); errWrite != nil {
						t.Error(errWrite)
					}
					return
				}
				body, errRead := io.ReadAll(r.Body)
				if errRead != nil {
					t.Error(errRead)
					return
				}
				captured <- body
				if transport == "compact" {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"id":"resp_guard","object":"response.compaction","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`))
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write(append(append([]byte("data: "), completed...), '\n', '\n'))
			}))
			defer server.Close()
			cfg := &config.Config{}
			auth := newCodexSignatureTestAuth(server.URL)
			req := cliproxyexecutor.Request{Model: "gpt-5.4", Payload: []byte(`{"model":"gpt-5.4","input":` + input + `}`)}
			opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse}
			var err error
			var stream *cliproxyexecutor.StreamResult
			switch transport {
			case "http":
				_, err = NewCodexExecutor(cfg).Execute(context.Background(), auth, req, opts)
			case "compact":
				opts.Alt = "responses/compact"
				_, err = NewCodexExecutor(cfg).Execute(context.Background(), auth, req, opts)
			case "sse":
				stream, err = NewCodexExecutor(cfg).ExecuteStream(context.Background(), auth, req, opts)
			case "websocket":
				_, err = NewCodexWebsocketsExecutor(cfg).Execute(context.Background(), auth, req, opts)
			case "websocket-stream":
				stream, err = NewCodexWebsocketsExecutor(cfg).ExecuteStream(context.Background(), auth, req, opts)
			}
			if err != nil {
				t.Fatal(err)
			}
			if stream != nil {
				for chunk := range stream.Chunks {
					if chunk.Err != nil {
						t.Fatal(chunk.Err)
					}
				}
			}
			select {
			case body := <-captured:
				if got := gjson.GetBytes(body, "input").Raw; got != input {
					t.Fatalf("input changed: %s", got)
				}
			default:
				t.Fatal("valid context did not reach upstream")
			}
		})
	}
}
