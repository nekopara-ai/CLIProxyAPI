package util

import (
	"strings"
	"testing"
)

const cookieRedactedValue = "[REDACTED]"

func TestMaskSensitiveHeaderValueFullyRedactsCookieMaterial(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{
			name:  "lowercase cookie",
			key:   "cookie",
			value: "session=abc123; codex_turn_ticket=secret-ticket-value",
		},
		{
			name:  "mixed case cookie",
			key:   "CoOkIe",
			value: "a=1; b=2; c=3",
		},
		{
			name:  "uppercase cookie",
			key:   "COOKIE",
			value: "__Secure-next-auth.session-token=eyJhbGciOi.payload.sig",
		},
		{
			name:  "mixed case set-cookie",
			key:   "sEt-CoOkIe",
			value: "codex_turn_ticket=ticket-value-xyz; Path=/; HttpOnly; Secure; SameSite=Lax",
		},
		{
			name:  "set-cookie with multiple cookies",
			key:   "Set-Cookie",
			value: "a=1; Path=/, b=2; Path=/; HttpOnly",
		},
		{
			name:  "mixed case x-codex-turn-state",
			key:   "x-CoDeX-TuRn-StAtE",
			value: "turn-state-ticket-0123456789abcdef",
		},
		{
			name:  "x-codex-turn-state whitespace padded key",
			key:   "  X-Codex-Turn-State  ",
			value: "ticket-material",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MaskSensitiveHeaderValue(tt.key, tt.value)
			if got != cookieRedactedValue {
				t.Fatalf("MaskSensitiveHeaderValue(%q, %q) = %q, want %q", tt.key, tt.value, got, cookieRedactedValue)
			}
			if strings.Contains(got, tt.value) {
				t.Fatalf("masked value %q still contains original secret material", got)
			}
		})
	}
}

func TestMaskSensitiveHeaderValueDoesNotLeakCookieSubstrings(t *testing.T) {
	secret := "turn-ticket-9f8e7d6c5b4a3210"
	for _, key := range []string{"Cookie", "Set-Cookie", "X-Codex-Turn-State"} {
		got := MaskSensitiveHeaderValue(key, "prefix="+secret+"; suffix=tail")
		for _, fragment := range []string{secret, "turn-ticket", "9f8e7d6c", "b4a3210", "prefix=", "suffix="} {
			if strings.Contains(got, fragment) {
				t.Fatalf("key %q masked value %q leaked fragment %q", key, got, fragment)
			}
		}
	}
}

func TestMaskSensitiveHeaderValuePreservesUnrelatedHeaders(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{"ordinary header", "X-Request-Id", "req-12345"},
		{"content type", "Content-Type", "application/json"},
		{"user agent", "User-Agent", "codex-cli/1.0"},
		{"content length", "Content-Length", "512"},
		{"custom session header", "X-Codex-Session-Id", "session-abc"},
		{"empty value", "X-Custom", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MaskSensitiveHeaderValue(tt.key, tt.value); got != tt.value {
				t.Fatalf("MaskSensitiveHeaderValue(%q, %q) = %q, want unchanged %q", tt.key, tt.value, got, tt.value)
			}
		})
	}
}

func TestMaskSensitiveHeaderValueStillHandlesExistingSensitiveHeaders(t *testing.T) {
	if got, want := MaskSensitiveHeaderValue("Authorization", "Bearer abcdefghijklmnop"), "Bearer abcd...mnop"; got != want {
		t.Fatalf("Authorization = %q, want %q", got, want)
	}
	if got := MaskSensitiveHeaderValue("X-Api-Key", "abcdefghijklmnop"); strings.Contains(got, "abcdefghijklmnop") {
		t.Fatalf("X-Api-Key leaked full value: %q", got)
	}
}
