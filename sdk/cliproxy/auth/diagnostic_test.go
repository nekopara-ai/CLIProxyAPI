package auth

import (
	"testing"
	"time"
)

func TestDiagnosticAdmissionMatchesBusinessGate(t *testing.T) {
	now := time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		a    *Auth
		want string
	}{
		{"missing", nil, "credential_missing"},
		{"manual", &Auth{Disabled: true}, "disabled"},
		{"status-disabled", &Auth{Status: StatusDisabled}, "disabled"},
		{"expired", &Auth{Metadata: map[string]any{"access_token": "synthetic", "expired": now.Add(-time.Second).Format(time.RFC3339)}}, "token_expired"},
		{"credential-quota", &Auth{Quota: QuotaState{Exceeded: true, Reason: "credential_quota", NextRecoverAt: now.Add(5 * time.Hour)}}, "quota"},
		{"expired-quota", &Auth{Unavailable: true, Quota: QuotaState{Exceeded: true, Reason: "credential_quota", NextRecoverAt: now}}, ""},
		{"forced", &Auth{ForcedCooldownUntil: now.Add(time.Hour)}, "cooldown"},
		{"model-quota", &Auth{ModelStates: map[string]*ModelState{"gpt-6-sol(high)": {Unavailable: true, Quota: QuotaState{Exceeded: true, NextRecoverAt: now.Add(time.Hour)}}}}, "quota"},
		{"sibling-quota", &Auth{Unavailable: true, Quota: QuotaState{Exceeded: true}, ModelStates: map[string]*ModelState{"gpt-6-astra": {Unavailable: true, Quota: QuotaState{Exceeded: true, NextRecoverAt: now.Add(time.Hour)}}}}, ""},
		{"healthy", &Auth{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wait := DiagnosticAvailability(tc.a, "gpt-6-sol", now)
			blocked, _, deadline := isAuthBlockedForModel(tc.a, "gpt-6-sol", now)
			if blocked != (wait != nil) {
				t.Fatal("diagnostic gate diverged from business")
			}
			if tc.want == "" {
				if wait != nil {
					t.Fatalf("unexpected wait %+v", wait)
				}
				return
			}
			if wait == nil || wait.Reason != tc.want || !wait.RetryAt.Equal(deadline) {
				t.Fatalf("wait %+v, want %s", wait, tc.want)
			}
		})
	}
}
