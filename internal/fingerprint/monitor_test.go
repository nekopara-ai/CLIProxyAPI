package fingerprint

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func ptr[T any](v T) *T { return &v }

type harness struct {
	m       *Monitor
	cfg     *config.Config
	a       *coreauth.Auth
	now     time.Time
	calls   int
	answers map[string][]Answer
	index   map[string]int
	hook    func()
}

func setup(t *testing.T) *harness {
	t.Helper()
	h := &harness{now: time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC), answers: map[string][]Answer{}, index: map[string]int{}}
	h.cfg = &config.Config{AuthDir: t.TempDir(), Fingerprint: config.FingerprintConfig{FingerprintPolicy: config.FingerprintPolicy{Enabled: ptr(true), Models: []string{"gpt-6-sol", "gpt-6-astra"}, QuestionRetries: ptr(0)}, StartupDelaySeconds: 1}}
	h.a = &coreauth.Auth{ID: "test", FileName: "account.json", Provider: "codex", Metadata: map[string]any{"account_id": "synthetic"}}
	for _, c := range parityCases(t) {
		h.answers[c.Prediction] = c.Answers
	}
	h.m = New(func() *config.Config { return h.cfg }, func() []*coreauth.Auth { return []*coreauth.Auth{h.a} }, func(_ context.Context, a *coreauth.Auth, model, prompt string) (string, error) {
		if a.ID != h.a.ID || a.ProxyURL != h.a.ProxyURL {
			t.Error("wrong credential or proxy")
		}
		h.calls++
		if h.hook != nil {
			h.hook()
		}
		answers := h.answers[model]
		i := h.index[model] % 3
		h.index[model]++
		if len(answers) == 0 {
			return "", errors.New("upstream failed")
		}
		if prompt != Prompts[i] {
			t.Error("wrong prompt order")
		}
		return answers[i].Text, nil
	})
	h.m.now = func() time.Time { return h.now }
	h.m.started = h.now.Add(-time.Hour)
	return h
}
func (h *harness) cycle() { h.m.tick(context.Background()); h.m.wg.Wait() }
func TestMonitorMismatchBlocksEntireCredentialAndRecovers(t *testing.T) {
	h := setup(t)
	good := h.answers["gpt-6-astra"]
	if good == nil {
		good = h.answers["gpt-6-sol"]
		h.cfg.Fingerprint.ExpectedModels = map[string]string{"gpt-6-astra": "gpt-6-sol"}
	}
	h.answers["gpt-6-astra"] = h.answers["gpt-5.6-luna"]
	h.cycle()
	s := h.m.Snapshot(h.a)
	if !s.Blocked || s.TriggerModel != "gpt-6-astra" || h.m.Allowed(h.a, "unrelated-business-model") || h.a.Disabled {
		t.Fatalf("bad block %+v", s)
	}
	n := h.calls
	h.cycle()
	if n != h.calls {
		t.Fatal("cooldown ignored")
	}
	// Restart must preserve block and request accounting.
	restarted := New(h.m.cfg, h.m.auths, h.m.probe)
	if restarted.Allowed(h.a, "") {
		t.Fatal("restart bypassed cooldown")
	}
	if restarted.Snapshot(h.a).RequestsToday != n {
		t.Fatal("budget not durable")
	}
	h.now = h.now.Add(time.Hour)
	h.answers["gpt-6-astra"] = nil
	h.cycle()
	if h.m.Allowed(h.a, "") {
		t.Fatal("upstream error restored credential")
	}
	h.now = h.now.Add(time.Hour)
	h.answers["gpt-6-astra"] = good
	h.index = map[string]int{}
	h.cycle()
	if !h.m.Allowed(h.a, "") {
		t.Fatalf("all passed but still blocked: %+v", h.m.Snapshot(h.a))
	}
}
func TestMonitorManualDisableAndStaleResult(t *testing.T) {
	h := setup(t)
	h.cfg.Fingerprint.Models = []string{"gpt-6-sol"}
	h.a.Disabled = true
	h.cycle()
	if h.calls != 0 || h.m.Allowed(h.a, "") {
		t.Fatal("manual disable ignored")
	}
	h.a.Disabled = false
	h.hook = func() { h.a.Disabled = true }
	h.cycle()
	s := h.m.Snapshot(h.a)
	if !s.LastRunAt.IsZero() || s.Blocked {
		t.Fatal("stale result committed")
	}
}
func TestMonitorErrorsMissingAndBudget(t *testing.T) {
	h := setup(t)
	h.cfg.Fingerprint.Models = []string{"gpt-6-sol"}
	h.cfg.Fingerprint.DailyRequestLimit = ptr(3)
	h.answers["gpt-6-sol"] = []Answer{{"", 300}, {"no", 310}, {"", 304}}
	h.cycle()
	s := h.m.Snapshot(h.a)
	if s.Results[0].Status != "insufficient" || s.Results[0].Probability != nil || s.Blocked {
		t.Fatalf("%+v", s)
	}
	h.now = h.now.Add(time.Hour)
	h.cycle()
	if h.calls != 3 || h.m.Snapshot(h.a).Blocked {
		t.Fatal("budget not enforced or error disabled")
	}
	h.now = h.now.Add(24 * time.Hour)
	h.cycle()
	if h.calls != 6 {
		t.Fatal("UTC budget did not reset")
	}
}
func TestMonitorStateCorruptionFailsClosedWithoutTraffic(t *testing.T) {
	h := setup(t)
	_ = os.WriteFile(h.m.stateFile, []byte("broken"), 0600)
	h.m = New(h.m.cfg, h.m.auths, h.m.probe)
	h.cycle()
	if h.m.Allowed(h.a, "") || h.calls != 0 {
		t.Fatal("corrupt state fail-open")
	}
	h.cfg.Fingerprint.Enabled = ptr(false)
	if !h.m.Allowed(h.a, "") {
		t.Fatal("master disable not honored")
	}
}
func TestMonitorUnwritableStateFailsClosed(t *testing.T) {
	h := setup(t)
	h.m.stateFile = filepath.Join(h.cfg.AuthDir, "not-directory", "state")
	_ = os.WriteFile(filepath.Dir(h.m.stateFile), []byte("x"), 0600)
	h.cycle()
	if h.calls != 0 || h.m.Allowed(h.a, "") {
		t.Fatal("probe made without durable budget")
	}
}
func TestMonitorPolicyInheritanceAndInvalidConfiguration(t *testing.T) {
	h := setup(t)
	h.cfg.CredentialPolicies = map[string]config.CredentialPolicy{"account.json": {Fingerprint: config.FingerprintPolicy{CooldownSeconds: ptr(10)}}}
	h.a.Metadata["fingerprint"] = map[string]any{"cooldown-seconds": 20}
	p, err := policyFor(h.cfg, h.a)
	if err != nil || *p.CooldownSeconds != 20 {
		t.Fatal(p, err)
	}
	h.a.Metadata["fingerprint"] = map[string]any{"models": []string{}}
	if h.m.Allowed(h.a, "") {
		t.Fatal("invalid configuration allowed")
	}
}
func TestMonitorOffByDefaultAndNoUnknownModelTraffic(t *testing.T) {
	h := setup(t)
	h.cfg.Fingerprint.Enabled = nil
	h.cycle()
	if h.calls != 0 {
		t.Fatal("off by default")
	}
	h.cfg.Fingerprint.Enabled = ptr(true)
	h.cfg.Fingerprint.Models = []string{"not-in-bank"}
	h.cycle()
	if h.calls != 0 || h.m.Snapshot(h.a).Blocked {
		t.Fatal("unsupported bank model probed or disabled")
	}
}
func TestMonitorCooldownEditing(t *testing.T) {
	h := setup(t)
	h.cfg.Fingerprint.Models = []string{"gpt-6-astra"}
	h.answers["gpt-6-astra"] = h.answers["gpt-5.6-luna"]
	h.cycle()
	h.cfg.Fingerprint.CooldownSeconds = ptr(5)
	h.now = h.now.Add(4 * time.Second)
	h.cycle()
	if h.calls != 3 {
		t.Fatal("premature retry")
	}
	h.now = h.now.Add(time.Second)
	h.cycle()
	if h.calls != 6 {
		t.Fatal("cooldown update ignored")
	}
}
func TestSharedAuthFileDoesNotShareCooldown(t *testing.T) {
	h := setup(t)
	h.cfg.Fingerprint.Models = []string{"gpt-6-astra"}
	h.answers["gpt-6-astra"] = h.answers["gpt-5.6-luna"]
	h.cycle()
	other := *h.a
	other.ID = "second-member"
	other.Metadata = map[string]any{"account_id": "different"}
	if !h.m.Allowed(&other, "") {
		t.Fatal("cooldown leaked to another member of source file")
	}
}
func TestLowConfidenceDoesNotBlock(t *testing.T) {
	h := setup(t)
	h.cfg.Fingerprint.Models = []string{"gpt-6-sol"}
	h.cfg.Fingerprint.Confidence = ptr(1.0)
	h.answers["gpt-6-sol"] = h.answers["gpt-5.6-luna"]
	h.cycle()
	s := h.m.Snapshot(h.a)
	if s.Blocked || s.Results[0].Status != "inconclusive" {
		t.Fatalf("low confidence blocked: %+v", s)
	}
}

type statusFailure int

func (e statusFailure) Error() string   { return "synthetic HTTP error" }
func (e statusFailure) StatusCode() int { return int(e) }
func TestRateLimitStopsCycleWithoutDisabling(t *testing.T) {
	h := setup(t)
	h.cfg.Fingerprint.QuestionRetries = ptr(2)
	h.m.probe = func(context.Context, *coreauth.Auth, string, string) (string, error) {
		h.calls++
		return "", statusFailure(429)
	}
	h.cycle()
	s := h.m.Snapshot(h.a)
	if h.calls != 1 || s.Blocked || s.Results[0].Error != "upstream_http_429" {
		t.Fatal("rate limit retried or mislabeled")
	}
}
func TestMismatchBlocksBeforeRemainingModelsFinish(t *testing.T) {
	h := setup(t)
	h.cfg.Fingerprint.Models = []string{"gpt-6-astra", "gpt-6-sol"}
	h.answers["gpt-6-astra"] = h.answers["gpt-5.6-luna"]
	original := h.m.probe
	entered := make(chan struct{})
	release := make(chan struct{})
	once := false
	h.m.probe = func(ctx context.Context, a *coreauth.Auth, model, prompt string) (string, error) {
		if model == "gpt-6-sol" && !once {
			once = true
			close(entered)
			<-release
		}
		return original(ctx, a, model, prompt)
	}
	h.m.tick(context.Background())
	<-entered
	if h.m.Allowed(h.a, "any") {
		t.Error("did not block immediately")
	}
	close(release)
	h.m.wg.Wait()
}
