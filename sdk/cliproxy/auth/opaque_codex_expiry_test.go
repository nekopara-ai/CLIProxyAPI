package auth

import (
	"testing"
	"time"
)

func TestOpaqueCodexTokenIgnoresLegacyExpiryHint(t *testing.T) {
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	past := now.Add(-24 * time.Hour)
	for _, tc := range []struct {
		name        string
		provider    string
		metadata    map[string]any
		rejected    string
		wantBlocked bool
	}{
		{"imported", "codex", map[string]any{"access_token": "opaque-imported-token", "expired": past.Format(time.RFC3339)}, "", false},
		{"metadata-provider", "", map[string]any{"type": "codex", "access_token": "opaque-imported-token", "expired": past.Format(time.RFC3339)}, "", false},
		{"upstream-rejected", "codex", map[string]any{"access_token": "opaque-imported-token", "expired": past.Format(time.RFC3339)}, "opaque-imported-token", true},
		{"explicit-expiry", "codex", map[string]any{"access_token": "opaque-imported-token", "expired": now.Add(time.Hour).Format(time.RFC3339), "expires_at": past.Format(time.RFC3339)}, "", true},
		{"relative-expiry", "codex", map[string]any{"access_token": "opaque-imported-token", "expired": past.Format(time.RFC3339), "expires_in": 60, "last_refresh": past.Format(time.RFC3339)}, "", true},
		{"refreshable-oauth", "codex", map[string]any{"access_token": "opaque-imported-token", "refresh_token": "synthetic-refresh", "expired": past.Format(time.RFC3339)}, "", true},
		{"refresh-alias", "codex", map[string]any{"access_token": "opaque-imported-token", "refreshToken": "synthetic-refresh", "expired": past.Format(time.RFC3339)}, "", true},
		{"expired-jwt", "codex", map[string]any{"access_token": makeTestJWT(past.Unix()), "expired": now.Add(time.Hour).Format(time.RFC3339)}, "", true},
		{"valid-jwt", "codex", map[string]any{"access_token": makeTestJWT(now.Add(time.Hour).Unix()), "expired": past.Format(time.RFC3339)}, "", false},
		{"malformed-jwt", "codex", map[string]any{"access_token": "invalid.jwt.token", "expired": past.Format(time.RFC3339)}, "", true},
		{"other-provider", "claude", map[string]any{"access_token": "opaque-imported-token", "expired": past.Format(time.RFC3339)}, "", true},
		{"siwc", "codex", map[string]any{"access_token": "opaque-imported-token", "expired": past.Format(time.RFC3339), "use_siwc": true, "siwc": map[string]any{"access_token": "opaque-siwc", "expires_at": past.Format(time.RFC3339)}}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &Auth{Provider: tc.provider, Metadata: tc.metadata, RejectedAccessToken: tc.rejected}
			original := a.Metadata["expired"]
			if got := !a.HasValidAccessToken(now); got != tc.wantBlocked {
				t.Fatalf("blocked = %v, want %v", got, tc.wantBlocked)
			}
			blocked, _, _ := isAuthBlockedForModel(a, "gpt-6-astra", now)
			if blocked != tc.wantBlocked {
				t.Fatalf("business blocked = %v, want %v", blocked, tc.wantBlocked)
			}
			if got := DiagnosticAvailability(a, "gpt-6-astra", now); (got != nil) != tc.wantBlocked {
				t.Fatalf("diagnostic wait = %+v, want blocked %v", got, tc.wantBlocked)
			}
			if a.Metadata["expired"] != original {
				t.Fatal("expiry lookup mutated shared metadata")
			}
		})
	}
}

func TestOpaqueCodexLegacyExpiryStillHonorsQuotaAndDisablement(t *testing.T) {
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	for _, reason := range []string{"quota", "disabled"} {
		t.Run(reason, func(t *testing.T) {
			a := &Auth{Provider: "codex", Metadata: map[string]any{
				"access_token": "opaque-imported-token", "expired": now.Add(-time.Hour).Format(time.RFC3339),
			}}
			if reason == "quota" {
				a.Quota = QuotaState{Exceeded: true, Reason: "credential_quota", NextRecoverAt: now.Add(time.Hour)}
			} else {
				a.Disabled = true
			}
			if wait := DiagnosticAvailability(a, "gpt-6-astra", now); wait == nil || wait.Reason != reason {
				t.Fatalf("wait = %+v, want %s", wait, reason)
			}
		})
	}
}
