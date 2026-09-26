package cliproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/fingerprint"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
)

func TestFingerprintProbeUsesOwnProxyAndCredentialWithoutTools(t *testing.T) {
	var calls atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := int(calls.Add(1)) - 1
		if r.URL.Host != "fingerprint.invalid" {
			t.Error("unexpected upstream target")
		}
		if r.Header.Get("Authorization") != "Bearer synthetic" {
			t.Error("wrong credential")
		}
		if r.Header.Get("Cookie") != "" || r.Header.Get("X-Codex-Turn-State") != "" {
			t.Error("ticket material injected")
		}
		body, _ := io.ReadAll(r.Body)
		if len(gjson.GetBytes(body, "tools").Array()) != 0 || gjson.GetBytes(body, "tool_choice").String() != "none" {
			t.Error("tools were enabled")
		}
		if i >= len(fingerprint.Prompts) || gjson.GetBytes(body, "input.0.content.0.text").String() != fingerprint.Prompts[i] {
			t.Error("prompt changed")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"test\",\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"87, 213\"}]}]}}\n\n")
	}))
	defer proxy.Close()
	cfg := &config.Config{}
	cfg.ProxyURL = "http://global-proxy.invalid:1"
	s := &Service{cfg: cfg, coreManager: coreauth.NewManager(nil, nil, nil)}
	s.coreManager.RegisterExecutor(runtimeexecutor.NewCodexExecutor(cfg))
	a := &coreauth.Auth{ID: "synthetic", Provider: "codex", ProxyURL: proxy.URL, Attributes: map[string]string{"base_url": "http://fingerprint.invalid", "api_key": "synthetic"}}
	for _, prompt := range fingerprint.Prompts {
		text, err := s.probeFingerprint(context.Background(), a, "gpt-6-sol", prompt)
		if err != nil || text != "87, 213" {
			t.Fatalf("probe = %q, %v", text, err)
		}
	}
	if calls.Load() != 3 {
		t.Fatal("missing probes")
	}
}

func TestFingerprintProbeTerminalDoesNotWaitForEOF(t *testing.T) {
	for _, tc := range []struct {
		name, event string
		wantError   bool
	}{
		{"completed", `{"type":"response.completed","response":{"id":"test","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"87, 213"}]}]}}`, false},
		{"incomplete", `{"type":"response.incomplete","response":{"id":"test","status":"incomplete","output":[]}}`, true},
		{"failed", `{"type":"response.failed","response":{"id":"test","status":"failed","error":{"code":"server_error","message":"synthetic"}}}`, true},
		{"tool_call", `{"type":"response.output_item.added","item":{"type":"function_call","name":"not_allowed"}}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			release := make(chan struct{})
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = fmt.Fprintf(w, "data: %s\n\n", tc.event)
				w.(http.Flusher).Flush()
				<-release
			}))
			defer proxy.Close()
			defer close(release)
			cfg := &config.Config{}
			s := &Service{cfg: cfg, coreManager: coreauth.NewManager(nil, nil, nil)}
			s.coreManager.RegisterExecutor(runtimeexecutor.NewCodexExecutor(cfg))
			a := &coreauth.Auth{ID: "synthetic", Provider: "codex", ProxyURL: proxy.URL, Attributes: map[string]string{"base_url": "http://fingerprint.invalid", "api_key": "synthetic"}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				text, err := s.probeFingerprint(ctx, a, "gpt-6-sol", fingerprint.Prompts[0])
				if err == nil && text != "87, 213" {
					err = fmt.Errorf("unexpected answer %q", text)
				}
				done <- err
			}()
			select {
			case err := <-done:
				if (err != nil) != tc.wantError {
					t.Fatalf("error = %v, wantError = %t", err, tc.wantError)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("terminal event incorrectly waits for upstream EOF")
			}
		})
	}
}

func TestFingerprintResponseTextRejectsInvalidCompletion(t *testing.T) {
	for _, raw := range []string{
		`{"status":"incomplete","output":[]}`,
		`{"status":"completed","error":{"message":"synthetic"}}`,
		`{"status":"completed","output":[{"type":"function_call"}]}`,
	} {
		if _, err := fingerprintResponseText(gjson.Parse(raw)); err == nil {
			t.Fatalf("invalid completion accepted: %s", raw)
		}
	}
	payload, _ := json.Marshal(map[string]any{"status": "completed", "output": []any{map[string]any{"type": "message", "content": []any{map[string]any{"type": "output_text", "text": string(make([]byte, (1<<20)+1))}}}}})
	if _, err := fingerprintResponseText(gjson.ParseBytes(payload)); err == nil {
		t.Fatal("oversized answer accepted")
	}
}
