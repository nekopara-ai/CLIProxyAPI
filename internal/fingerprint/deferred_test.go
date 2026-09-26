package fingerprint

import (
	"context"
	"fmt"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

type quotaFailure struct {
	delay      time.Duration
	credential bool
}

func (e quotaFailure) Error() string              { return "synthetic quota" }
func (e quotaFailure) StatusCode() int            { return 429 }
func (e quotaFailure) RetryAfter() *time.Duration { return &e.delay }
func (e quotaFailure) IsCredentialScoped() bool   { return e.credential }

func TestKnownQuotaSkipsWithoutBudgetAndSurvivesRestart(t *testing.T) {
	h := setup(t)
	h.answers["gpt-6-astra"] = h.answers["gpt-6-sol"]
	h.cfg.Fingerprint.ExpectedModels = map[string]string{"gpt-6-astra": "gpt-6-sol"}
	deadline := h.now.Add(5 * time.Hour)
	h.a.Quota = coreauth.QuotaState{Exceeded: true, Reason: "credential_quota", NextRecoverAt: deadline}
	h.cycle()
	s := h.m.Snapshot(h.a)
	if h.calls != 0 || s.RequestsToday != 0 || len(s.History) != 0 || !s.NextRunAt.Equal(deadline) {
		t.Fatalf("known quota dispatched or recorded a verdict: %+v", s)
	}
	for _, model := range h.cfg.Fingerprint.Models {
		if s.ModelStates[model].Wait == nil || s.ModelStates[model].Result != nil || !h.m.Allowed(h.a, model) {
			t.Fatal("quota became a fingerprint failure")
		}
	}
	// Simulate a restart that lost the manager's in-memory quota and a policy edit.
	h.a.Quota = coreauth.QuotaState{}
	h.cfg.Fingerprint.Confidence = ptr(.8)
	h.m = New(h.m.cfg, h.m.auths, h.m.probe)
	h.m.now = func() time.Time { return h.now }
	h.now = deadline.Add(-time.Nanosecond)
	h.cycle()
	if h.calls != 0 {
		t.Fatal("restart/policy edit bypassed quota")
	}
	h.now = deadline
	h.cycle()
	if h.calls != 6 || h.m.Snapshot(h.a).ModelStates["gpt-6-sol"].Wait != nil {
		t.Fatal("quota did not expire")
	}
}

func TestModelQuotaDoesNotSuppressHealthySibling(t *testing.T) {
	h := setup(t)
	h.answers["gpt-6-astra"] = h.answers["gpt-6-sol"]
	h.cfg.Fingerprint.ExpectedModels = map[string]string{"gpt-6-astra": "gpt-6-sol"}
	h.a.ModelStates = map[string]*coreauth.ModelState{"gpt-6-sol(high)": {
		Unavailable: true, Quota: coreauth.QuotaState{Exceeded: true, NextRecoverAt: h.now.Add(5 * time.Hour)},
	}}
	h.cycle()
	s := h.m.Snapshot(h.a)
	if h.calls != 3 || s.RequestsToday != 3 || s.ModelStates["gpt-6-sol"].Wait == nil || s.ModelStates["gpt-6-astra"].Result == nil {
		t.Fatal("model scope/canonical matching broken")
	}
}

func TestQuotaCheckedBeforeEachQuestionAndRetry(t *testing.T) {
	for _, retry := range []bool{false, true} {
		t.Run(fmt.Sprint(retry), func(t *testing.T) {
			h := setup(t)
			h.answers["gpt-6-astra"] = h.answers["gpt-6-sol"]
			h.cfg.Fingerprint.ExpectedModels = map[string]string{"gpt-6-astra": "gpt-6-sol"}
			h.cfg.Fingerprint.QuestionRetries = ptr(2)
			h.hook = func() {
				h.a.Quota = coreauth.QuotaState{Exceeded: true, Reason: "credential_quota", NextRecoverAt: h.now.Add(5 * time.Hour)}
			}
			if retry {
				h.answers["gpt-6-sol"] = []Answer{{"invalid", 300}}
			}
			h.cycle()
			s := h.m.Snapshot(h.a)
			if h.calls != 1 || s.RequestsToday != 1 || s.Blocked || len(s.Results) != 0 || s.History[0].Results[0].Status != "deferred" {
				t.Fatalf("mid-cycle quota ignored: %+v", s)
			}
		})
	}
}

func TestQuotaFailurePreservesVerdictAndLongerMismatchCooldown(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		t.Run(fmt.Sprint(mismatch), func(t *testing.T) {
			h := setup(t)
			h.answers["gpt-6-astra"] = h.answers["gpt-6-sol"]
			h.cfg.Fingerprint.ExpectedModels = map[string]string{"gpt-6-astra": "gpt-6-sol"}
			h.cfg.Fingerprint.Models = []string{"gpt-6-sol"}
			if mismatch {
				h.answers["gpt-6-sol"] = h.answers["gpt-5.6-luna"]
			}
			h.cycle()
			before := h.m.Snapshot(h.a).ModelStates["gpt-6-sol"]
			h.now = before.NextRunAt
			h.m.probe = func(context.Context, *coreauth.Auth, string, string) (string, error) {
				h.calls++
				return "", fmt.Errorf("wrapped: %w", quotaFailure{5 * time.Hour, true})
			}
			h.cycle()
			s := h.m.Snapshot(h.a)
			ms := s.ModelStates["gpt-6-sol"]
			if ms.Result.Status != before.Result.Status || ms.Result.FinishedAt != before.Result.FinishedAt || ms.Blocked != mismatch || ms.Failures != before.Failures || !ms.NextRunAt.Equal(h.now.Add(5*time.Hour)) {
				t.Fatalf("quota destroyed prior classification: %+v", ms)
			}
			// Editing the fingerprint cooldown must not shorten the quota wait.
			h.cfg.Fingerprint.CooldownSeconds = ptr(1)
			h.cycle()
			if h.calls != 4 {
				t.Fatal("quota immediately retried")
			}
		})
	}
}

func TestDispatchAdmissionRefundAndNoHealthyWorkerStarvation(t *testing.T) {
	h := setup(t)
	h.answers["gpt-6-astra"] = h.answers["gpt-6-sol"]
	h.cfg.Fingerprint.ExpectedModels = map[string]string{"gpt-6-astra": "gpt-6-sol"}
	h.cfg.Fingerprint.Models = []string{"gpt-6-sol"}
	other := h.a.Clone()
	other.ID = "healthy"
	h.a.Quota = coreauth.QuotaState{Exceeded: true, Reason: "credential_quota", NextRecoverAt: h.now.Add(time.Hour)}
	h.m.auths = func() []*coreauth.Auth { return []*coreauth.Auth{h.a, other} }
	h.m.probe = func(_ context.Context, a *coreauth.Auth, _, _ string) (string, error) {
		h.calls++
		if a.ID != other.ID {
			t.Error("blocked credential occupied worker")
		}
		return "", &coreauth.DiagnosticUnavailable{Reason: "quota", Scope: "credential", RetryAt: h.now.Add(5 * time.Hour)}
	}
	h.cycle()
	if h.calls != 1 || h.m.Snapshot(other).RequestsToday != 0 || h.m.Snapshot(other).ModelStates["gpt-6-sol"].Wait == nil {
		t.Fatal("admission rejection was billed or blocked worker starved healthy auth")
	}
}

func TestModelScoped429AllowsSiblingAndUnknownResetUsesConfiguredRetry(t *testing.T) {
	h := setup(t)
	h.answers["gpt-6-astra"] = h.answers["gpt-6-sol"]
	h.cfg.Fingerprint.ExpectedModels = map[string]string{"gpt-6-astra": "gpt-6-sol"}
	h.cfg.Fingerprint.RetrySeconds, h.cfg.Fingerprint.MaxRetrySeconds = ptr(10800), ptr(10800)
	original := h.m.probe
	h.m.probe = func(ctx context.Context, a *coreauth.Auth, model, prompt string) (string, error) {
		if model == "gpt-6-sol" {
			h.calls++
			return "", quotaFailure{}
		}
		return original(ctx, a, model, prompt)
	}
	h.cycle()
	s := h.m.Snapshot(h.a)
	if h.calls != 4 || s.ModelStates["gpt-6-astra"].Result == nil || !s.ModelStates["gpt-6-sol"].NextRunAt.Equal(h.now.Add(3*time.Hour)) {
		t.Fatal("model 429 overblocked or ignored retry configuration")
	}
}

func TestKnownQuotaCapturedBetweenScheduledRuns(t *testing.T) {
	h := setup(t)
	h.cfg.Fingerprint.Models = []string{"gpt-6-sol"}
	h.cycle()
	deadline := h.now.Add(5 * time.Hour)
	h.a.Quota = coreauth.QuotaState{Exceeded: true, Reason: "credential_quota", NextRecoverAt: deadline}
	h.cycle()
	restarted := New(h.m.cfg, h.m.auths, h.m.probe)
	ms := restarted.Snapshot(h.a).ModelStates["gpt-6-sol"]
	if h.calls != 3 || ms.Wait == nil || !ms.Wait.RetryAt.Equal(deadline) || ms.Result.Status != "match" {
		t.Fatal("quota learned between runs was not persisted independently of the verdict")
	}
}
