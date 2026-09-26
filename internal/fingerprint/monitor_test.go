package fingerprint

import (
	"context"
	"encoding/json"
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
func TestMonitorMismatchBlocksOnlyItsModelAndRecovers(t *testing.T) {
	h := setup(t)
	good := h.answers["gpt-6-astra"]
	if good == nil {
		good = h.answers["gpt-6-sol"]
		h.cfg.Fingerprint.ExpectedModels = map[string]string{"gpt-6-astra": "gpt-6-sol"}
	}
	h.answers["gpt-6-astra"] = h.answers["gpt-5.6-luna"]
	h.cycle()
	s := h.m.Snapshot(h.a)
	if !s.Blocked || s.TriggerModel != "gpt-6-astra" || h.m.Allowed(h.a, "gpt-6-astra") || !h.m.Allowed(h.a, "gpt-6-sol") || !h.m.Allowed(h.a, "unrelated-business-model") || h.a.Disabled {
		t.Fatalf("bad block %+v", s)
	}
	n := h.calls
	h.cycle()
	if n != h.calls {
		t.Fatal("cooldown ignored")
	}
	// Restart must preserve block and request accounting.
	restarted := New(h.m.cfg, h.m.auths, h.m.probe)
	if restarted.Allowed(h.a, "gpt-6-astra") || !restarted.Allowed(h.a, "gpt-6-sol") {
		t.Fatal("restart bypassed cooldown")
	}
	if restarted.Snapshot(h.a).RequestsToday != n {
		t.Fatal("budget not durable")
	}
	h.now = h.now.Add(time.Hour)
	h.answers["gpt-6-astra"] = nil
	h.cycle()
	if h.m.Allowed(h.a, "gpt-6-astra") {
		t.Fatal("upstream error restored credential")
	}
	h.now = h.now.Add(time.Hour)
	h.answers["gpt-6-astra"] = good
	h.index = map[string]int{}
	h.cycle()
	if !h.m.Allowed(h.a, "gpt-6-astra") {
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
	if h.m.Allowed(h.a, "gpt-6-sol") || !h.m.Allowed(h.a, "not-monitored") || h.calls != 0 {
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
	if h.calls != 0 || h.m.Allowed(h.a, "gpt-6-sol") || !h.m.Allowed(h.a, "not-monitored") {
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
	h.a.Metadata["fingerprint"] = map[string]any{"confidence": .1}
	if h.m.Allowed(h.a, "gpt-6-sol") || !h.m.Allowed(h.a, "not-monitored") {
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
		return "", quotaFailure{credential: true}
	}
	h.cycle()
	s := h.m.Snapshot(h.a)
	if h.calls != 1 || s.Blocked || len(s.Results) != 0 || s.ModelStates["gpt-6-sol"].Wait == nil || s.History[0].Results[0].Status != "deferred" {
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
	if h.m.Allowed(h.a, "gpt-6-astra") || !h.m.Allowed(h.a, "gpt-6-sol") {
		t.Error("did not block immediately")
	}
	close(release)
	h.m.wg.Wait()
}

func TestMonitorUnsupportedProvidersNeverProbeOrGate(t *testing.T) {
	for _, provider := range []string{"opencode", "openai-compatibility", "claude", "xai", ""} {
		t.Run(provider, func(t *testing.T) {
			h := setup(t)
			h.a.Provider = provider
			h.cycle()
			if h.calls != 0 || len(h.m.states) != 0 {
				t.Fatal("unsupported credential consumed probes or budget")
			}
			// Old persisted errors or a shared storage error must not block other providers.
			h.m.states[authKey(h.a)] = &State{Identity: identity(h.a), Blocked: true}
			h.m.storageError = "synthetic storage failure"
			s := h.m.Snapshot(h.a)
			if s.Supported || s.Enabled || s.State != nil || s.ConfigurationError != "" || !h.m.Allowed(h.a, "any") {
				t.Fatal("unsupported provider inherited fingerprint state")
			}
			h.a.Disabled = true
			if h.m.Allowed(h.a, "any") {
				t.Fatal("manual disabled provider allowed")
			}
		})
	}
}

func TestMonitorResultPolicyRemainsAuditableAcrossThresholdChanges(t *testing.T) {
	h := setup(t)
	h.cycle()
	s := h.m.Snapshot(h.a)
	if s.ResultsStale || s.ResultPolicy == nil || *s.ResultPolicy.Confidence != .95 || s.Results[0].Confidence != .95 {
		t.Fatalf("missing result policy: %+v", s)
	}
	h.cfg.Fingerprint.Confidence = ptr(.5)
	s = h.m.Snapshot(h.a)
	if !s.ResultsStale || *s.Effective.Confidence != .5 || *s.ResultPolicy.Confidence != .95 || *s.History[0].Policy.Confidence != .95 {
		t.Fatal("old result was silently relabeled using the new threshold")
	}
	h.cycle()
	s = h.m.Snapshot(h.a)
	if s.ResultsStale || *s.ResultPolicy.Confidence != .5 || s.Results[0].Confidence != .5 || *s.History[0].Policy.Confidence != .95 {
		t.Fatal("fresh result policy/history is incorrect")
	}
	// Version-1 state without recorded policy stays explicitly historical until retested.
	h.m.states[authKey(h.a)].ModelStates = nil
	migrateModelStates(h.m.states[authKey(h.a)])
	if !h.m.Snapshot(h.a).ResultsStale {
		t.Fatal("legacy result reported as current")
	}
	h.cycle()
	if h.m.Snapshot(h.a).ResultsStale {
		t.Fatal("legacy results were not refreshed")
	}
}

func TestMonitorCancelsObsoleteProbeWithAllWorkersOccupied(t *testing.T) {
	for _, change := range []string{"manual_disable", "master_disable", "policy", "removed"} {
		t.Run(change, func(t *testing.T) {
			h := setup(t)
			entered := make(chan struct{})
			h.m.probe = func(ctx context.Context, _ *coreauth.Auth, _, _ string) (string, error) {
				RecordActivity(ctx, 123)
				close(entered)
				<-ctx.Done()
				return "", ctx.Err()
			}
			h.m.tick(context.Background())
			<-entered
			s := h.m.Snapshot(h.a)
			if s.Progress == nil || s.Progress.Model != "gpt-6-sol" || s.Progress.Question != 1 || s.Progress.Attempt != 1 || s.Progress.TotalQuestions != 6 || s.Progress.ReceivedBytes != 123 || s.Progress.LastEventAt.IsZero() || !s.NextRunAt.IsZero() {
				t.Fatalf("missing live progress: %+v", s.Progress)
			}
			switch change {
			case "manual_disable":
				h.a.Disabled = true
			case "master_disable":
				h.cfg.Fingerprint.Enabled = ptr(false)
			case "policy":
				h.cfg.Fingerprint.Confidence = ptr(.5)
			case "removed":
				h.m.auths = func() []*coreauth.Auth { return nil }
			}
			h.m.tick(context.Background())
			h.m.wg.Wait()
			s = h.m.Snapshot(h.a)
			if s.Running || s.Progress != nil || !s.LastRunAt.IsZero() || len(s.History) > 0 || s.Blocked || s.RequestsToday != 1 {
				t.Fatal("cancelled run changed eligibility, committed a result or leaked work")
			}
		})
	}
}

func TestModelCooldownAndRecoveryAreIndependent(t *testing.T) {
	h := setup(t)
	good := h.answers["gpt-6-sol"]
	h.cfg.Fingerprint.ExpectedModels = map[string]string{"gpt-6-astra": "gpt-6-sol"}
	h.answers["gpt-6-sol"], h.answers["gpt-6-astra"] = h.answers["gpt-5.6-luna"], h.answers["gpt-5.6-luna"]
	h.cycle()
	if h.m.Allowed(h.a, "gpt-6-sol") || h.m.Allowed(h.a, "gpt-6-astra(high)") || !h.m.Allowed(h.a, "gpt-5.6-sol") {
		t.Fatal("wrong model scope")
	}
	h.now = h.now.Add(31 * time.Minute)
	h.answers["gpt-6-sol"], h.answers["gpt-6-astra"] = good, nil
	h.cycle()
	if !h.m.Allowed(h.a, "gpt-6-sol") || h.m.Allowed(h.a, "gpt-6-astra") {
		t.Fatal("one model's error prevented another model's recovery")
	}
	s := h.m.Snapshot(h.a)
	if s.ModelStates["gpt-6-sol"].Blocked || !s.ModelStates["gpt-6-astra"].Blocked || h.a.Disabled {
		t.Fatal("incorrect per-model block or manual flag changed")
	}
	before := h.calls
	h.now = h.now.Add(6 * time.Minute)
	h.answers["gpt-6-astra"] = good
	h.index["gpt-6-astra"] = 0
	h.cycle()
	if h.calls-before != 3 || !h.m.Allowed(h.a, "gpt-6-astra") {
		t.Fatal("recovery should probe only the due model, not its healthy sibling")
	}
}

func TestUnmonitoredAndOtherCredentialsBypassModelBlock(t *testing.T) {
	h := setup(t)
	h.answers["gpt-6-astra"] = h.answers["gpt-5.6-luna"]
	h.cycle()
	other := *h.a
	other.ID = "another-account"
	if !h.m.Allowed(&other, "gpt-6-astra") || !h.m.Allowed(h.a, "gpt-5.6-sol") || !h.m.Allowed(h.a, "") {
		t.Fatal("model block leaked to another model/account or management availability")
	}
	h.cfg.Fingerprint.Models = []string{"gpt-6-sol"}
	if !h.m.Allowed(h.a, "gpt-6-astra") || h.m.Snapshot(h.a).Blocked {
		t.Fatal("removed model is still gated")
	}
	h.cfg.Fingerprint.Models = []string{"gpt-6-sol", "gpt-6-astra"}
	if h.m.Allowed(h.a, "gpt-6-astra") {
		t.Fatal("temporarily removing monitoring erased the durable block")
	}
}

func TestLegacyCredentialBlockMigratesOnlyToRecordedModels(t *testing.T) {
	h := setup(t)
	legacy := &State{Identity: identity(h.a), Blocked: true, TriggerModel: "gpt-6-astra", LastMismatchAt: h.now,
		CooldownUntil: h.now.Add(30 * time.Minute), NextRunAt: h.now.Add(30 * time.Minute), RequestsToday: 19,
		Results: []ModelResult{{Model: "gpt-6-sol", Status: "match"}, {Model: "gpt-6-astra", Status: "mismatch"}}}
	raw, _ := json.Marshal(map[string]any{"version": 1, "states": map[string]*State{authKey(h.a): legacy}})
	if err := os.WriteFile(h.m.stateFile, raw, 0600); err != nil {
		t.Fatal(err)
	}
	m := New(h.m.cfg, h.m.auths, h.m.probe)
	if m.Allowed(h.a, "gpt-6-astra") || !m.Allowed(h.a, "gpt-6-sol") || !m.Allowed(h.a, "unmonitored") {
		t.Fatal("legacy blanket exclusion was not narrowed")
	}
	if s := m.Snapshot(h.a); s.RequestsToday != 19 || !s.ResultsStale || !s.ModelStates["gpt-6-astra"].CooldownUntil.Equal(legacy.CooldownUntil) {
		t.Fatal("migration lost accounting, cooldown or unknown-policy marker")
	}
}

func TestModelVariantsCannotBypassBlockAndPolicyDisableStillBypasses(t *testing.T) {
	h := setup(t)
	h.cfg.Fingerprint.Models = []string{"gpt-6-astra", "gpt-6-astra(high)", "gpt-6-sol"}
	h.m.states[authKey(h.a)] = &State{Identity: identity(h.a), ModelStates: map[string]*ModelState{
		"gpt-6-astra":       {Blocked: false},
		"gpt-6-astra(high)": {Blocked: true},
	}}
	for _, model := range []string{"gpt-6-astra", "gpt-6-astra(low)", "GPT-6-ASTRA(high)"} {
		if h.m.Allowed(h.a, model) {
			t.Fatalf("reasoning or case variant bypassed block: %s", model)
		}
	}
	if !h.m.Allowed(h.a, "gpt-6-sol") || !h.m.Allowed(h.a, "gpt-5.6-sol") {
		t.Fatal("variant block leaked to unrelated models")
	}
	h.a.Metadata["fingerprint"] = map[string]any{"enabled": false}
	if !h.m.Allowed(h.a, "gpt-6-astra") {
		t.Fatal("credential policy disable did not bypass fingerprint block")
	}
	h.a.Disabled = true
	if h.m.Allowed(h.a, "gpt-6-astra") || h.m.Allowed(h.a, "gpt-5.6-sol") {
		t.Fatal("fingerprint bypass overrode manual credential disable")
	}
}
