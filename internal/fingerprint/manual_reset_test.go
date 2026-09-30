package fingerprint

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestManualResetClearsAllSchedulesPreservesVerdictsAndHistory(t *testing.T) {
	for _, status := range []string{"match", "mismatch", "error", "pending"} {
		t.Run(status, func(t *testing.T) {
			h := setup(t)
			p, _ := policyFor(h.cfg, h.a)
			stamp := signature(h.cfg, h.a, p)
			wait := &coreauth.DiagnosticUnavailable{Reason: "quota", Scope: "credential", RetryAt: h.now.Add(96 * time.Hour)}
			r := ModelResult{Model: "gpt-6-sol", Status: status, Error: "upstream_http_429", Deferred: wait}
			blocked := status != "match"
			ms := &ModelState{Blocked: blocked, Result: &r, Wait: wait, LastMismatchAt: h.now.Add(-time.Minute), CooldownUntil: h.now.Add(time.Hour), NextRunAt: wait.RetryAt, Failures: 7, LastRunAt: h.now.Add(-time.Minute)}
			h.m.states[h.a.ID] = &State{Identity: identity(h.a), ModelStates: map[string]*ModelState{"gpt-6-sol": ms, "removed-model": {Wait: wait, NextRunAt: wait.RetryAt, Failures: 4}}, RequestsToday: 12, BudgetDay: h.now.Format("2006-01-02"), History: []Run{{At: h.now, Results: []ModelResult{r}}}, PolicySignature: stamp}
			historyBefore, _ := json.Marshal(h.m.states[h.a.ID].History)
			if err := h.m.ResetCooldown(h.a); err != nil {
				t.Fatal(err)
			}
			s := h.m.Snapshot(h.a)
			if s.RequestsToday != 12 || s.ModelStates["gpt-6-sol"].Blocked != blocked || s.Results[0].Status != status || !s.NextRunAt.Equal(h.now) {
				t.Fatalf("reset changed verdict/accounting: %+v", s)
			}
			for model, state := range h.m.states[h.a.ID].ModelStates {
				if state.Wait != nil || !state.LastMismatchAt.IsZero() || !state.CooldownUntil.IsZero() || !state.NextRunAt.Equal(h.now) || state.Failures != 0 || state.Result != nil && state.Result.Deferred != nil {
					t.Fatalf("stale schedule %s: %+v", model, state)
				}
			}
			historyAfter, _ := json.Marshal(s.History)
			if string(historyBefore) != string(historyAfter) {
				t.Fatal("history rewritten")
			}
			restarted := New(h.m.cfg, h.m.auths, h.m.probe)
			if got := restarted.Snapshot(h.a).ModelStates["gpt-6-sol"]; got.Wait != nil || !got.NextRunAt.Equal(h.now) || got.Blocked != blocked {
				t.Fatalf("reset not durable: %+v", got)
			}
			due := syncModels(h.m.states[h.a.ID], p, stamp, h.now)
			if len(due) != 2 {
				t.Fatalf("old mismatch reconstructed cooldown: %v", due)
			}
		})
	}
}

func TestManualResetCancelsOldQuotaProbeAndAllowsFreshCheck(t *testing.T) {
	h := setup(t)
	h.cfg.Fingerprint.Models = []string{"gpt-6-sol"}
	oldProbe := h.m.probe
	entered, release := make(chan struct{}), make(chan struct{})
	h.m.probe = func(ctx context.Context, a *coreauth.Auth, model, prompt string) (string, error) {
		close(entered)
		<-release
		return "", quotaFailure{delay: 96 * time.Hour, credential: true}
	}
	h.m.tick(context.Background())
	<-entered
	if err := h.m.ResetCooldown(h.a); err != nil {
		t.Fatal(err)
	}
	close(release)
	h.m.wg.Wait()
	s := h.m.Snapshot(h.a)
	if s.Running || s.ModelStates["gpt-6-sol"].Wait != nil || !s.NextRunAt.Equal(h.now) || len(s.History) != 0 || s.RequestsToday != 1 {
		t.Fatalf("old request resurrected quota: %+v", s)
	}
	h.m.probe = oldProbe
	h.cycle()
	if s = h.m.Snapshot(h.a); s.ModelStates["gpt-6-sol"].Result.Status != "match" || s.Blocked || h.calls != 3 {
		t.Fatalf("fresh verification did not run: %+v", s)
	}
}

func TestManualResetInvalidatesDelayedCommit(t *testing.T) {
	h := setup(t)
	h.cycle()
	p, _ := policyFor(h.cfg, h.a)
	stamp := signature(h.cfg, h.a, p)
	ctx, cancel := context.WithCancel(context.Background())
	h.m.active[h.a.ID] = &activeRun{signature: stamp, cancel: cancel}
	if err := h.m.ResetCooldown(h.a); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() == nil || h.m.stillCurrent(h.a, stamp) {
		t.Fatal("old run still current")
	}
	wait := &coreauth.DiagnosticUnavailable{Reason: "quota", RetryAt: h.now.Add(96 * time.Hour)}
	h.m.deferProbe(h.a, "gpt-6-sol", p, wait)
	h.m.finish(h.a, p, nil, p.Models, "reference_bank_unavailable", stamp)
	if h.m.reserve(h.a, p) {
		t.Fatal("old run reserved new budget")
	}
	if got := h.m.Snapshot(h.a).ModelStates["gpt-6-sol"]; got.Wait != nil || got.Blocked {
		t.Fatalf("late write revived old state: %+v", got)
	}
}

func TestManualResetStillRespectsRealQuotaAndBudget(t *testing.T) {
	for _, reason := range []string{"quota", "budget", "disabled"} {
		t.Run(reason, func(t *testing.T) {
			h := setup(t)
			h.cfg.Fingerprint.Models = []string{"gpt-6-sol"}
			h.cycle()
			n := h.calls
			switch reason {
			case "quota":
				h.a.Quota = coreauth.QuotaState{Exceeded: true, Reason: "credential_quota", NextRecoverAt: h.now.Add(time.Hour)}
			case "budget":
				h.cfg.Fingerprint.DailyRequestLimit = ptr(n)
			case "disabled":
				h.a.Disabled = true
			}
			if err := h.m.ResetCooldown(h.a); err != nil {
				t.Fatal(err)
			}
			h.cycle()
			if h.calls != n {
				t.Fatalf("%s bypassed", reason)
			}
		})
	}
}

func TestManualResetSchedulesFirstProbeWithoutStartupDelay(t *testing.T) {
	h := setup(t)
	h.cfg.Fingerprint.Models = []string{"gpt-6-sol"}
	h.cfg.Fingerprint.StartupDelaySeconds = 3600
	h.m.started = h.now
	if err := h.m.ResetCooldown(h.a); err != nil {
		t.Fatal(err)
	}
	h.cycle()
	if h.calls != 3 || h.m.Snapshot(h.a).ModelStates["gpt-6-sol"].Result.Status != "match" {
		t.Fatal("manual enable kept first-probe startup delay")
	}
}

func TestManualResetRejectsStaleAuthListQuotaSnapshot(t *testing.T) {
	h := setup(t)
	h.cfg.Fingerprint.Models = []string{"gpt-6-sol"}
	h.a.Generation = 1
	h.a.Quota = coreauth.QuotaState{Exceeded: true, Reason: "credential_quota", NextRecoverAt: h.now.Add(96 * time.Hour)}
	h.cycle()
	stale := h.a.Clone()
	h.a.Generation = 2
	h.a.Quota = coreauth.QuotaState{}
	if err := h.m.ResetCooldown(h.a); err != nil {
		t.Fatal(err)
	}
	h.m.auths = func() []*coreauth.Auth { return []*coreauth.Auth{stale} }
	h.cycle()
	if h.m.Snapshot(h.a).ModelStates["gpt-6-sol"].Wait != nil || h.calls != 0 {
		t.Fatal("pre-reset scheduler snapshot revived the quota wait")
	}
	h.m.auths = func() []*coreauth.Auth { return []*coreauth.Auth{h.a} }
	h.cycle()
	if h.calls != 3 {
		t.Fatal("current generation did not run forced check")
	}
}
