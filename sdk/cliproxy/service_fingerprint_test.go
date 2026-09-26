package cliproxy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/fingerprint"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
	"github.com/tidwall/gjson"
)

type fingerprintUsageCapture struct {
	authID  string
	records chan usage.Record
}

func (c *fingerprintUsageCapture) HandleUsage(_ context.Context, r usage.Record) {
	if r.AuthID == c.authID {
		select {
		case c.records <- r:
		default:
		}
	}
}

func TestFingerprintProbeUsesOwnProxyAndCredentialWithoutTools(t *testing.T) {
	// Service lifecycle tests stop the process-global usage dispatcher permanently.
	// Isolate this end-to-end accounting assertion rather than depending on test order.
	if os.Getenv("CPA_FINGERPRINT_USAGE_ISOLATED") != "1" {
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(binary, "-test.run=^"+t.Name()+"$")
		cmd.Env = append(os.Environ(), "CPA_FINGERPRINT_USAGE_ISOLATED=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated probe: %v\n%s", err, output)
		}
		return
	}
	capture := &fingerprintUsageCapture{authID: t.Name(), records: make(chan usage.Record, 3)}
	usage.RegisterNamedPlugin(t.Name(), capture)
	t.Cleanup(func() { usage.RegisterNamedPlugin(t.Name(), &fingerprintUsageCapture{}) })
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
	cfg.APIKeys = []string{"synthetic-business-client", "synthetic-system-client"}
	cfg.InternalRequestAPIKeySHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte(cfg.APIKeys[1])))
	s := &Service{cfg: cfg, coreManager: coreauth.NewManager(nil, nil, nil)}
	s.coreManager.RegisterExecutor(runtimeexecutor.NewCodexExecutor(cfg))
	a := &coreauth.Auth{ID: t.Name(), Provider: "codex", ProxyURL: proxy.URL, Attributes: map[string]string{"base_url": "http://fingerprint.invalid"}, Metadata: map[string]any{"email": "selected@example.invalid", "access_token": "synthetic"}}
	if _, err := s.coreManager.Register(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	for _, prompt := range fingerprint.Prompts {
		text, err := s.probeFingerprint(context.Background(), a, "gpt-6-sol", prompt)
		if err != nil || text != "87, 213" {
			t.Fatalf("probe = %q, %v", text, err)
		}
		select {
		case r := <-capture.records:
			if r.APIKey != cfg.APIKeys[1] || r.Source != "selected@example.invalid" || r.AuthID != a.ID || r.Model != "gpt-6-sol" {
				t.Fatalf("synthetic probe identity: key_match=%t source=%q auth_match=%t model=%q", r.APIKey == cfg.APIKeys[1], r.Source, r.AuthID == a.ID, r.Model)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("probe usage was not published")
		}
	}
	if calls.Load() != 3 {
		t.Fatal("missing probes")
	}
}

func TestFingerprintProbeRejectsRevokedInternalCallerBeforeDispatch(t *testing.T) {
	cfg := &config.Config{InternalRequestAPIKeySHA256: fmt.Sprintf("%x", sha256.Sum256([]byte("revoked-system")))}
	cfg.APIKeys = []string{"business-client"}
	s := &Service{cfg: cfg}
	// No manager or executor is installed: resolving an invalid reference must stop first.
	_, err := s.probeFingerprint(context.Background(), &coreauth.Auth{Provider: "codex"}, "gpt-6-sol", "synthetic")
	if err == nil || err.Error() != "internal-request-api-key-sha256 does not match a configured api-keys entry" {
		t.Fatalf("unexpected error: %v", err)
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
			if _, err := s.coreManager.Register(context.Background(), a); err != nil {
				t.Fatal(err)
			}
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

func TestFingerprintQuotaAdmissionAndFailureFeedback(t *testing.T) {
	for _, path := range []string{"http", "sse"} {
		t.Run(path, func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("X-Codex-Primary-Used-Percent", "100")
				if path == "http" {
					w.WriteHeader(429)
					_, _ = fmt.Fprint(w, `{"error":{"type":"usage_limit_reached","resets_in_seconds":18000}}`)
				} else {
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = fmt.Fprint(w, "data: {\"type\":\"response.failed\",\"response\":{\"error\":{\"type\":\"usage_limit_reached\",\"resets_in_seconds\":18000}}}\n\n")
				}
			}))
			defer upstream.Close()
			cfg := &config.Config{}
			s := &Service{cfg: cfg, coreManager: coreauth.NewManager(nil, nil, nil)}
			s.coreManager.RegisterExecutor(runtimeexecutor.NewCodexExecutor(cfg))
			a := &coreauth.Auth{ID: t.Name(), Provider: "codex", ProxyURL: upstream.URL, Attributes: map[string]string{"base_url": "http://fingerprint.invalid", "api_key": "synthetic"}}
			if _, err := s.coreManager.Register(context.Background(), a); err != nil {
				t.Fatal(err)
			}
			before := time.Now()
			_, err := s.probeFingerprint(context.Background(), a, "gpt-6-sol", "synthetic")
			var status interface{ StatusCode() int }
			if !errors.As(err, &status) || status.StatusCode() != 429 {
				t.Fatalf("lost typed quota error: %v", err)
			}
			current, _ := s.coreManager.GetByID(a.ID)
			if current.Quota.Reason != "credential_quota" || current.Quota.NextRecoverAt.Before(before.Add(5*time.Hour)) || current.Quota.Signals["X-Codex-Primary-Used-Percent"] != "100" {
				t.Fatalf("quota not fed to business scheduler: %+v", current.Quota)
			}
			// The originally selected stale auth cannot bypass the final admission check.
			_, err = s.probeFingerprint(context.Background(), a, "gpt-6-astra", "synthetic")
			var deferred *coreauth.DiagnosticUnavailable
			if !errors.As(err, &deferred) || deferred.Reason != "quota" || calls.Load() != 1 {
				t.Fatal("stale auth dispatched during quota")
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
