package fingerprint

import (
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func (m *Monitor) runInvalidatedLocked(key string) bool {
	run := m.active[key]
	return run != nil && run.invalidated
}

func (s *State) resetIsNewerThan(a *coreauth.Auth) bool {
	return a.RegistrationEpoch < s.resetEpoch || a.RegistrationEpoch == s.resetEpoch && a.Generation < s.resetGeneration
}

// ResetCooldown clears scheduling restrictions, not fingerprint verdicts or
// accounting. A blocked model must still pass a complete fresh verification.
func (m *Monitor) ResetCooldown(a *coreauth.Auth) error {
	if m == nil || !supported(a) {
		return nil
	}
	p, policyErr := policyFor(m.cfg(), a)
	m.mu.Lock()
	defer m.mu.Unlock()
	key := authKey(a)
	s := m.states[key]
	if s != nil && s.Identity == identity(a) && s.resetIsNewerThan(a) {
		return nil
	}
	if s == nil || s.Identity != identity(a) {
		s = &State{Identity: identity(a), NextRunAt: m.now()}
		m.states[key] = s
	}
	if run := m.active[key]; run != nil {
		run.invalidated = true
		run.cancel()
	}
	s.resetGeneration = a.Generation
	s.resetEpoch = a.RegistrationEpoch
	s.Suspended = disabled(a)
	migrateModelStates(s)
	now := m.now()
	if policyErr == nil {
		for _, model := range p.Models {
			if s.ModelStates[model] == nil {
				s.ModelStates[model] = &ModelState{}
			}
		}
	}
	for _, ms := range s.ModelStates {
		if ms == nil {
			continue
		}
		ms.Wait = nil
		ms.LastMismatchAt, ms.CooldownUntil = time.Time{}, time.Time{}
		ms.NextRunAt, ms.Failures = now, 0
		if ms.Result != nil && ms.Result.Deferred != nil {
			result := *ms.Result
			result.Deferred = nil
			ms.Result = &result
		}
	}
	s.LastMismatchAt, s.CooldownUntil = time.Time{}, time.Time{}
	s.NextRunAt, s.Failures = now, 0
	// Results/history remain diagnostic records, including the old retry hint
	// in history. The live result no longer advertises an active quota wait.
	if policyErr == nil {
		refreshSummary(s, p)
	}
	if s.Suspended {
		clearSchedule(s)
	}
	return m.saveLocked()
}

// Clear live scheduling without rewriting verdicts, history or request accounting.
func clearSchedule(s *State) {
	s.Running, s.Progress, s.CurrentResults = false, nil, nil
	s.NextRunAt = time.Time{}
	for _, ms := range s.ModelStates {
		if ms != nil {
			ms.NextRunAt, ms.Wait = time.Time{}, nil
		}
	}
}
