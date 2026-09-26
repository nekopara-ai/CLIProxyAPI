package auth

import (
	"context"
	"errors"
	"time"
)

// DiagnosticUnavailable is a local admission decision, never an upstream error.
// It deliberately contains no raw provider response or credential material.
type DiagnosticUnavailable struct {
	Reason  string    `json:"reason"`
	Scope   string    `json:"scope"`
	RetryAt time.Time `json:"retry_at"`
}

func (e *DiagnosticUnavailable) Error() string { return "diagnostic deferred: " + e.Reason }

// DiagnosticAvailability reuses business cooldown/credential eligibility, but
// not the independent execution-model guard that diagnostics are meant to test.
// The model must be the resolved upstream model, not a public route alias.
func DiagnosticAvailability(a *Auth, model string, now time.Time) *DiagnosticUnavailable {
	blocked, reason, retryAt := isAuthBlockedForModel(a, model, now)
	if !blocked {
		return nil
	}
	wait := &DiagnosticUnavailable{Reason: "unavailable", Scope: "model", RetryAt: retryAt}
	switch {
	case a == nil:
		wait.Reason, wait.Scope = "credential_missing", "credential"
	case a.Disabled || a.Status == StatusDisabled:
		wait.Reason, wait.Scope = "disabled", "credential"
	case hasUnauthorizedAuthFailure(a):
		wait.Reason, wait.Scope = "unauthorized", "credential"
	default:
		if exp, ok := a.AccessTokenExpirationTime(); ok && !exp.IsZero() && !exp.After(now) {
			wait.Reason, wait.Scope = "token_expired", "credential"
		} else if a.Quota.Exceeded && a.Quota.Reason == "credential_quota" && a.Quota.NextRecoverAt.After(now) {
			wait.Reason, wait.Scope = "quota", "credential"
		} else {
			if a.ForcedCooldownUntil.After(now) || len(a.ModelStates) == 0 {
				wait.Scope = "credential"
			}
			if reason == blockReasonCooldown {
				wait.Reason = "quota"
			} else if reason == blockReasonDisabled {
				wait.Reason = "disabled"
			} else if retryAt.After(now) {
				wait.Reason = "cooldown"
			}
		}
	}
	return wait
}

// RecordDiagnosticFailure feeds newly discovered quota/auth restrictions back
// into the normal scheduler. Successful probes never clear concurrent business
// failures; classifier and transport failures never create quota restrictions.
func (m *Manager) RecordDiagnosticFailure(ctx context.Context, a *Auth, model string, err error) {
	if m == nil || a == nil || err == nil || ctx.Err() != nil {
		return
	}
	var status interface{ StatusCode() int }
	if !errors.As(err, &status) {
		return
	}
	switch status.StatusCode() {
	case 401, 402, 403, 429:
		m.MarkResult(ctx, Result{
			AuthID: a.ID, Provider: a.Provider, Model: model,
			Error: resultErrorFromError(err), RetryAfter: retryAfterFromError(err),
			CredentialScope: isCredentialScopedError(err),
		})
	}
}
