package helps

import (
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

// TestTurnTicketProbeUsesConfiguredIdentity covers the synthetic probe path: a configured
// Codex identity must reach the probe so it is not rejected by the upstream version gate.
func TestTurnTicketProbeUsesConfiguredIdentity(t *testing.T) {
	cfg := &config.Config{Codex: config.CodexConfig{ClientIdentity: config.CodexClientIdentity{Version: "0.160.0"}}}
	identity := cfg.ResolveCodexIdentity()
	headers := http.Header{}
	applyCodexTurnTicketProbeIdentity(headers, turnTicketTestAuth("auth-a"), "gpt-5.5", identity)
	if got := headers.Get("Version"); got != "0.160.0" {
		t.Fatalf("Version = %q, want 0.160.0", got)
	}
	if got, want := headers.Get("User-Agent"), "codex_cli_rs/0.160.0 (Linux 7.0.0-28; x86_64) rust"; got != want {
		t.Fatalf("User-Agent = %q, want %q", got, want)
	}
	if got := headers.Get("Originator"); got != "codex_cli_rs" {
		t.Fatalf("Originator = %q, want codex_cli_rs", got)
	}
}

// TestTurnTicketProbeKeepsConfiguredIdentityAboveMinimumVersion verifies an explicit newer
// configured version is not downgraded back to the built-in floor.
func TestTurnTicketProbeKeepsConfiguredIdentityAboveMinimumVersion(t *testing.T) {
	cfg := &config.Config{Codex: config.CodexConfig{ClientIdentity: config.CodexClientIdentity{Version: "0.200.0"}}}
	headers := http.Header{}
	applyCodexTurnTicketProbeIdentity(headers, turnTicketTestAuth("auth-a"), "gpt-6-sol", cfg.ResolveCodexIdentity())
	if got := headers.Get("Version"); got != "0.200.0" {
		t.Fatalf("Version = %q, want 0.200.0 (must not downgrade to the floor)", got)
	}
}
