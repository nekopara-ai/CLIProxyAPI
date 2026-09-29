package fingerprint

import (
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/thinking"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// ModelState owns eligibility and scheduling for one resolved upstream model.
type ModelState struct {
	Wait            *coreauth.DiagnosticUnavailable `json:"wait,omitempty"`
	Blocked         bool                            `json:"blocked"`
	LastMismatchAt  time.Time                       `json:"last_mismatch_at,omitempty"`
	CooldownUntil   time.Time                       `json:"cooldown_until,omitempty"`
	NextRunAt       time.Time                       `json:"next_run_at"`
	LastRunAt       time.Time                       `json:"last_run_at,omitempty"`
	Failures        int                             `json:"failures"`
	Result          *ModelResult                    `json:"result,omitempty"`
	ResultPolicy    *config.FingerprintPolicy       `json:"result_policy,omitempty"`
	ResultSignature string                          `json:"result_signature,omitempty"`
	ResultsStale    bool                            `json:"results_stale,omitempty"`
}

func modelKey(model string) string {
	return strings.ToLower(strings.TrimSpace(thinking.ParseSuffix(strings.TrimSpace(model)).ModelName))
}

func configuredModel(p config.FingerprintPolicy, model string) string {
	base := modelKey(model)
	for _, candidate := range p.Models {
		if modelKey(candidate) == base && base != "" {
			return candidate
		}
	}
	return ""
}

// Preserve the old accounting/history, but attribute legacy exclusions only to
// models with recorded mismatches or the persisted trigger. Never blanket-block.
func migrateModelStates(s *State) {
	if s.ModelStates != nil {
		return
	}
	s.ModelStates = make(map[string]*ModelState)
	for _, result := range s.Results {
		r := result
		ms := &ModelState{Result: &r, LastRunAt: s.LastRunAt, NextRunAt: s.NextRunAt}
		if s.Blocked && r.Status == "mismatch" {
			ms.Blocked, ms.LastMismatchAt, ms.CooldownUntil = true, s.LastMismatchAt, s.CooldownUntil
		}
		s.ModelStates[r.Model] = ms
	}
	if s.Blocked && s.TriggerModel != "" {
		ms := s.ModelStates[s.TriggerModel]
		if ms == nil {
			ms = &ModelState{NextRunAt: s.NextRunAt}
			s.ModelStates[s.TriggerModel] = ms
		}
		ms.Blocked, ms.LastMismatchAt, ms.CooldownUntil = true, s.LastMismatchAt, s.CooldownUntil
	}
	// Legacy decisions do not record their full policy and must be refreshed.
	s.PolicySignature = ""
}

func retryDelay(p config.FingerprintPolicy, failures int) time.Duration {
	retry := min(*p.RetrySeconds, *p.MaxRetrySeconds)
	for i := 1; i < failures && retry < *p.MaxRetrySeconds; i++ {
		retry = min(retry*2, *p.MaxRetrySeconds)
	}
	return time.Duration(retry) * time.Second
}

func syncModels(s *State, p config.FingerprintPolicy, stamp string, now time.Time) []string {
	migrateModelStates(s)
	changed := s.PolicySignature != stamp
	due := []string{}
	for _, model := range p.Models {
		ms := s.ModelStates[model]
		if ms == nil {
			ms = &ModelState{NextRunAt: s.NextRunAt}
			if !s.LastRunAt.IsZero() {
				ms.NextRunAt = now
			}
			s.ModelStates[model] = ms
		}
		if changed && !ms.LastRunAt.IsZero() {
			ms.NextRunAt = now
		}
		if ms.Blocked && !ms.LastMismatchAt.IsZero() {
			until := ms.LastMismatchAt.Add(time.Duration(*p.CooldownSeconds) * time.Second)
			if !ms.CooldownUntil.Equal(until) {
				ms.CooldownUntil, ms.NextRunAt = until, until
			}
			if ms.NextRunAt.Before(until) {
				ms.NextRunAt = until
			}
		}
		if ms.Wait != nil {
			if ms.Wait.RetryAt.After(now) {
				if ms.NextRunAt.Before(ms.Wait.RetryAt) {
					ms.NextRunAt = ms.Wait.RetryAt
				}
			} else {
				ms.Wait = nil
			}
		}
		if !ms.NextRunAt.After(now) && (!ms.Blocked || !ms.CooldownUntil.After(now)) {
			due = append(due, model)
		}
	}
	s.PolicySignature = stamp
	refreshSummary(s, p)
	return due
}

// The credential summary is informational only; Allowed checks ModelStates.
func refreshSummary(s *State, p config.FingerprintPolicy) {
	s.Blocked, s.Reason, s.TriggerModel = false, "", ""
	s.LastMismatchAt, s.CooldownUntil, s.NextRunAt = time.Time{}, time.Time{}, time.Time{}
	s.Results = nil
	for _, model := range p.Models {
		ms := s.ModelStates[model]
		if ms == nil {
			continue
		}
		if ms.Result != nil {
			s.Results = append(s.Results, *ms.Result)
		}
		if s.NextRunAt.IsZero() || ms.NextRunAt.Before(s.NextRunAt) {
			s.NextRunAt = ms.NextRunAt
		}
		if ms.Blocked {
			s.Blocked = true
			reason := modelBlockReason(ms)
			if s.Reason == "" || reason == "fingerprint_model_mismatch" {
				s.Reason = reason
				s.TriggerModel = model
			}
			if s.CooldownUntil.IsZero() || ms.CooldownUntil.Before(s.CooldownUntil) {
				s.CooldownUntil = ms.CooldownUntil
			}
			if ms.LastMismatchAt.After(s.LastMismatchAt) {
				s.LastMismatchAt = ms.LastMismatchAt
			}
		}
	}
}

func modelBlockReason(ms *ModelState) string {
	if !ms.LastMismatchAt.IsZero() {
		return "fingerprint_model_mismatch"
	}
	if ms.Result != nil {
		switch ms.Result.Status {
		case "mismatch":
			return "fingerprint_model_mismatch"
		case "pending":
			return "fingerprint_pending_retry"
		case "insufficient":
			return "fingerprint_insufficient_answers"
		case "error":
			return "fingerprint_check_error"
		case "inconclusive":
			return "fingerprint_low_confidence"
		}
	}
	return "fingerprint_unverified"
}

func applyModelResult(s *State, p config.FingerprintPolicy, r ModelResult, stamp string, now time.Time) {
	ms := s.ModelStates[r.Model]
	if ms == nil {
		ms = &ModelState{}
		s.ModelStates[r.Model] = ms
	}
	if r.Deferred != nil && r.Status == "deferred" {
		deferModel(ms, *r.Deferred, p, now)
		refreshSummary(s, p)
		return
	}
	// An incomplete probe is not a new verdict. Preserve prior eligibility;
	// without a prior result, wait for a complete verification before routing.
	if r.Status == "pending" && ms.Result == nil {
		ms.Blocked = true
	}
	ms.Wait = nil
	ms.Result, ms.ResultSignature, ms.ResultPolicy, ms.LastRunAt = &r, stamp, copyPolicy(p), now
	switch r.Status {
	case "pending":
		// Count incomplete attempts for the existing retry backoff, not as verdicts.
		ms.Failures++
		ms.NextRunAt = now.Add(retryDelay(p, ms.Failures))
		if ms.CooldownUntil.After(ms.NextRunAt) {
			ms.NextRunAt = ms.CooldownUntil
		}
	case "match":
		ms.Blocked, ms.Failures = false, 0
		ms.LastMismatchAt, ms.CooldownUntil = time.Time{}, time.Time{}
		ms.NextRunAt = now.Add(time.Duration(*p.IntervalSeconds) * time.Second)
	case "mismatch":
		ms.Blocked, ms.Failures, ms.LastMismatchAt = true, 0, now
		ms.CooldownUntil = now.Add(time.Duration(*p.CooldownSeconds) * time.Second)
		ms.NextRunAt = ms.CooldownUntil
	default:
		// Every completed non-match invalidates an earlier passing decision.
		// Keep the failure diagnostic and retry schedule; only a fresh match
		// can reopen routing, including after transport/configuration errors.
		ms.Blocked = true
		ms.Failures++
		ms.NextRunAt = now.Add(retryDelay(p, ms.Failures))
		if ms.Blocked && ms.CooldownUntil.After(ms.NextRunAt) {
			ms.NextRunAt = ms.CooldownUntil
		}
	}
	if r.Deferred != nil {
		deferModel(ms, *r.Deferred, p, now)
	}
	refreshSummary(s, p)
}
