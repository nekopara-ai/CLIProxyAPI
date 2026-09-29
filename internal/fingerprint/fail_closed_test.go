package fingerprint

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestFailedProbeInvalidatesPriorMatch(t *testing.T) {
	for _, tc := range []struct {
		name    string
		outputs int
		err     error
		code    string
	}{
		{"503_no_answers", 0, statusFailure(503), "upstream_http_503"},
		{"503_one_answer", 1, statusFailure(503), "upstream_http_503"},
		{"503_two_answers", 2, statusFailure(503), "upstream_http_503"},
		{"408", 0, statusFailure(408), "upstream_http_408"},
		{"429", 0, statusFailure(429), "upstream_http_429"},
		{"transport", 0, errors.New("synthetic connection failure"), "upstream_request_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := setup(t)
			h.cfg.Fingerprint.Models = []string{"gpt-6-astra", "gpt-6-sol"}
			h.cfg.Fingerprint.ExpectedModels = map[string]string{"gpt-6-astra": "gpt-6-sol"}
			h.cfg.Fingerprint.QuestionRetries = ptr(1)
			h.answers["gpt-6-astra"] = h.answers["gpt-6-sol"]
			h.cycle()
			if !h.m.Allowed(h.a, "gpt-6-astra") || h.m.Snapshot(h.a).ModelStates["gpt-6-astra"].Result.Status != "match" {
				t.Fatal("initial complete match did not open routing")
			}
			original := h.m.probe
			attempts := 0
			h.index = map[string]int{}
			h.m.probe = func(ctx context.Context, a *coreauth.Auth, model, prompt string) (string, error) {
				attempts++
				if attempts > tc.outputs {
					h.calls++
					return "", tc.err
				}
				return original(ctx, a, model, prompt)
			}
			h.now = h.now.Add(time.Hour)
			h.cycle()
			s := h.m.Snapshot(h.a)
			ms := s.ModelStates["gpt-6-astra"]
			if ms.Result.Status != "error" || ms.Result.Error != tc.code || ms.Result.UsedOutputs != tc.outputs || !ms.Blocked || h.m.Allowed(h.a, "gpt-6-astra(high)") || s.Reason != "fingerprint_check_error" {
				t.Fatalf("failed probe preserved routing or lost its cause: %+v", ms)
			}
			if !h.m.Allowed(h.a, "gpt-6-sol") || !h.m.Allowed(h.a, "gpt-5.6-sol") || h.a.Disabled || !ms.LastMismatchAt.IsZero() || !ms.CooldownUntil.IsZero() {
				t.Fatal("request error was treated as a mismatch or affected another model")
			}
			before := h.calls
			h.cycle()
			if h.calls != before {
				t.Fatal("error ignored retry schedule")
			}
			restarted := New(h.m.cfg, h.m.auths, h.m.probe)
			if restarted.Allowed(h.a, "gpt-6-astra") || !restarted.Allowed(h.a, "gpt-6-sol") {
				t.Fatal("restart lost the model-specific block")
			}
			h.m.probe = original
			h.index = map[string]int{}
			h.now = ms.NextRunAt
			h.cycle()
			if !h.m.Allowed(h.a, "gpt-6-astra") || h.m.Snapshot(h.a).ModelStates["gpt-6-astra"].Result.Status != "match" {
				t.Fatal("fresh complete match did not recover routing")
			}
		})
	}
}

func TestLowConfidenceInvalidatesPriorMatch(t *testing.T) {
	h := setup(t)
	h.cfg.Fingerprint.Models = []string{"gpt-6-sol"}
	h.cycle()
	if !h.m.Allowed(h.a, "gpt-6-sol") {
		t.Fatal("initial complete match did not open routing")
	}
	h.cfg.Fingerprint.Confidence = ptr(1.0)
	h.cycle()
	s := h.m.Snapshot(h.a)
	if s.Results[0].Status != "inconclusive" || !s.Blocked || h.m.Allowed(h.a, "gpt-6-sol") || s.Reason != "fingerprint_low_confidence" {
		t.Fatalf("low-confidence result preserved a prior match: %+v", s)
	}
}

func TestPersistedNonMatchingResultsFailClosed(t *testing.T) {
	for _, status := range []string{"error", "inconclusive", "insufficient", "mismatch", "unknown"} {
		t.Run(status, func(t *testing.T) {
			h := setup(t)
			next := h.now.Add(3 * time.Hour)
			h.m.states[authKey(h.a)] = &State{Identity: identity(h.a), RequestsToday: 17, ModelStates: map[string]*ModelState{
				"gpt-6-sol":   {NextRunAt: next, Result: &ModelResult{Model: "gpt-6-sol", Status: "match"}},
				"gpt-6-astra": {NextRunAt: next, LastRunAt: h.now, Failures: 2, Result: &ModelResult{Model: "gpt-6-astra", Status: status}},
			}}
			if err := h.m.saveLocked(); err != nil {
				t.Fatal(err)
			}
			m := New(h.m.cfg, h.m.auths, h.m.probe)
			s := m.Snapshot(h.a)
			ms := s.ModelStates["gpt-6-astra"]
			if m.Allowed(h.a, "gpt-6-astra") || !m.Allowed(h.a, "gpt-6-sol") || !s.Blocked || ms.Result.Status != status || !ms.NextRunAt.Equal(next) || !ms.LastRunAt.Equal(h.now) || ms.Failures != 2 || s.RequestsToday != 17 || h.calls != 0 {
				t.Fatalf("startup did not reconcile the old result without probing: %+v", s)
			}
			raw, err := os.ReadFile(m.stateFile)
			if err != nil {
				t.Fatal(err)
			}
			var saved struct{ States map[string]*State }
			if err := json.Unmarshal(raw, &saved); err != nil || !saved.States[authKey(h.a)].ModelStates["gpt-6-astra"].Blocked {
				t.Fatal("startup correction was not persisted")
			}
		})
	}
}

func TestMissingReferenceBankInvalidatesPriorMatch(t *testing.T) {
	h := setup(t)
	h.cfg.Fingerprint.Models = []string{"gpt-6-sol"}
	h.cycle()
	before := h.calls
	h.cfg.Fingerprint.BankFile = filepath.Join(t.TempDir(), "missing-bank.json")
	h.cycle()
	s := h.m.Snapshot(h.a)
	if h.calls != before || h.m.Allowed(h.a, "gpt-6-sol") || !s.Blocked || s.Error != "reference_bank_unavailable" || s.ModelStates["gpt-6-sol"].Result.Error != "reference_bank_unavailable" {
		t.Fatalf("unavailable bank retained a passing result: %+v", s)
	}
}
