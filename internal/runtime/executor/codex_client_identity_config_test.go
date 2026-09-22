package executor

import (
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func codexIdentityTestAuth() *cliproxyauth.Auth {
	return &cliproxyauth.Auth{Provider: "codex", Metadata: map[string]any{"email": "user@example.com"}}
}

// TestCodexCloakingHeadersUseConfiguredIdentity is the regression guard for the upstream
// version gate: raising the version must be possible through config, not a rebuild.
func TestCodexCloakingHeadersUseConfiguredIdentity(t *testing.T) {
	cfg := &config.Config{Codex: config.CodexConfig{ClientIdentity: config.CodexClientIdentity{Version: "0.160.0"}}}
	headers := http.Header{}
	applyCodexCloakingHeaders(headers, cfg, codexIdentityTestAuth())
	if got := headers.Get("Version"); got != "0.160.0" {
		t.Fatalf("Version = %q, want 0.160.0", got)
	}
	if got := headers.Get("Originator"); got != "codex_cli_rs" {
		t.Fatalf("Originator = %q, want codex_cli_rs", got)
	}
	if got, want := headers.Get("User-Agent"), "codex_cli_rs/0.160.0 (Linux 7.0.0-28; x86_64) rust"; got != want {
		t.Fatalf("User-Agent = %q, want %q", got, want)
	}
}

// TestModelOverrideHeadersHonorConfiguredIdentity ensures the catalog's pinned Codex
// identity is rewritten from the live config for catalog-managed models.
func TestModelOverrideHeadersHonorConfiguredIdentity(t *testing.T) {
	cfg := &config.Config{Codex: config.CodexConfig{ClientIdentity: config.CodexClientIdentity{Version: "0.160.0"}}}
	headers := http.Header{}
	applyModelHeaderOverrides(headers, "gpt-5.6-luna", codexOverrideIdentity{cfg: cfg, auth: codexIdentityTestAuth()})
	if got := headers.Get("Version"); got != "0.160.0" {
		t.Fatalf("Version = %q, want 0.160.0", got)
	}
	if got, want := headers.Get("User-Agent"), "codex_cli_rs/0.160.0 (Linux 7.0.0-28; x86_64) rust"; got != want {
		t.Fatalf("User-Agent = %q, want %q", got, want)
	}
}

// TestModelOverrideHeadersRespectPerCredentialCloakingOptOut guarantees the identity rewrite
// never overrides a credential that explicitly disabled cloaking.
func TestModelOverrideHeadersRespectPerCredentialCloakingOptOut(t *testing.T) {
	cfg := &config.Config{
		Codex: config.CodexConfig{ClientIdentity: config.CodexClientIdentity{Version: "0.160.0"}},
		CodexKey: []config.CodexKey{{
			APIKey:               "custom-key",
			BaseURL:              "https://example.com/v1",
			DisableCodexCloaking: boolPtr(true),
		}},
	}
	auth := &cliproxyauth.Auth{Provider: "codex", Attributes: map[string]string{
		"api_key":  "custom-key",
		"base_url": "https://example.com/v1",
	}}
	headers := http.Header{}
	applyModelHeaderOverrides(headers, "gpt-5.6-luna", codexOverrideIdentity{cfg: cfg, auth: auth})
	// The catalog value still lands, but the configured identity must not be forced on top.
	if got := headers.Get("Version"); got == "0.160.0" {
		t.Fatalf("Version = %q, want the catalog value, not the configured identity", got)
	}
}
