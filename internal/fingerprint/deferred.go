package fingerprint

import (
	"errors"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func deferModel(ms *ModelState, wait coreauth.DiagnosticUnavailable, p config.FingerprintPolicy, now time.Time) {
	if !wait.RetryAt.After(now) {
		wait.RetryAt = now.Add(retryDelay(p, 1))
	}
	if ms.Wait != nil && ms.Wait.RetryAt.After(wait.RetryAt) {
		wait.RetryAt = ms.Wait.RetryAt
	}
	ms.Wait = &wait
	if ms.NextRunAt.Before(wait.RetryAt) {
		ms.NextRunAt = wait.RetryAt
	}
	if ms.Blocked && ms.CooldownUntil.After(ms.NextRunAt) {
		ms.NextRunAt = ms.CooldownUntil
	}
}

// Called under m.mu before occupying a worker or reserving request budget.
func (m *Monitor) filterAvailable(s *State, a *coreauth.Auth, p config.FingerprintPolicy, models []string, now time.Time) []string {
	changed := false
	// Capture known cooldowns even for models not yet due, so a restart cannot
	// forget a business limit observed between scheduled fingerprint cycles.
	for _, model := range p.Models {
		ms := s.ModelStates[model]
		if wait := coreauth.DiagnosticAvailability(a, model, now); wait != nil {
			if ms.Wait != nil && ms.Wait.RetryAt.After(now) && !wait.RetryAt.After(now) {
				wait.RetryAt = ms.Wait.RetryAt
			}
			var before coreauth.DiagnosticUnavailable
			if ms.Wait != nil {
				before = *ms.Wait
			}
			deferModel(ms, *wait, p, now)
			changed = changed || before != *ms.Wait
		}
	}
	ready := make([]string, 0, len(models))
	for _, model := range models {
		if wait := s.ModelStates[model].Wait; wait == nil || !wait.RetryAt.After(now) {
			ready = append(ready, model)
		}
	}
	if changed {
		refreshSummary(s, p)
		_ = m.saveLocked()
	}
	return ready
}

func (m *Monitor) deferProbe(a *coreauth.Auth, model string, p config.FingerprintPolicy, wait *coreauth.DiagnosticUnavailable) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.states[authKey(a)]
	for _, candidate := range p.Models {
		if modelKey(candidate) == modelKey(model) || wait.Scope == "credential" {
			deferModel(s.ModelStates[candidate], *wait, p, m.now())
		}
	}
	refreshSummary(s, p)
	_ = m.saveLocked()
}

// A final service-side admission check can reject after budget reservation.
// No request was dispatched in that case, so it must not consume daily budget.
func (m *Monitor) refundReservation(a *coreauth.Auth) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s := m.states[authKey(a)]; s != nil && s.RequestsToday > 0 {
		s.RequestsToday--
		_ = m.saveLocked()
	}
}

func deferredError(err error, now time.Time) *coreauth.DiagnosticUnavailable {
	var local *coreauth.DiagnosticUnavailable
	if errors.As(err, &local) {
		copy := *local
		return &copy
	}
	var status interface{ StatusCode() int }
	if !errors.As(err, &status) {
		return nil
	}
	wait := &coreauth.DiagnosticUnavailable{Scope: "model"}
	switch status.StatusCode() {
	case 429:
		wait.Reason = "quota"
	case 401, 402, 403:
		wait.Reason, wait.Scope = "unauthorized", "credential"
	default:
		return nil
	}
	var scoped interface{ IsCredentialScoped() bool }
	if errors.As(err, &scoped) && scoped.IsCredentialScoped() {
		wait.Scope = "credential"
	}
	var hint interface{ RetryAfter() *time.Duration }
	if errors.As(err, &hint) {
		if delay := hint.RetryAfter(); delay != nil && *delay > 0 {
			wait.RetryAt = now.Add(*delay)
		}
	}
	return wait
}
