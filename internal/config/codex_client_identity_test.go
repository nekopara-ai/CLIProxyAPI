package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/constant"
)

func TestResolveCodexIdentityDefaults(t *testing.T) {
	var cfg *Config
	got := cfg.ResolveCodexIdentity()
	if got.Version != constant.CodexClientVersion {
		t.Fatalf("Version = %q, want %q", got.Version, constant.CodexClientVersion)
	}
	if got.Originator != constant.CodexOriginator {
		t.Fatalf("Originator = %q, want %q", got.Originator, constant.CodexOriginator)
	}
	if got.UserAgent != constant.CodexUserAgent {
		t.Fatalf("UserAgent = %q, want %q", got.UserAgent, constant.CodexUserAgent)
	}
}

func TestResolveCodexIdentityConfiguredVersionKeepsUserAgentConsistent(t *testing.T) {
	cfg := &Config{Codex: CodexConfig{ClientIdentity: CodexClientIdentity{Version: "0.160.1"}}}
	got := cfg.ResolveCodexIdentity()
	if got.Version != "0.160.1" {
		t.Fatalf("Version = %q, want 0.160.1", got.Version)
	}
	if got.Originator != constant.CodexOriginator {
		t.Fatalf("Originator = %q, want default %q", got.Originator, constant.CodexOriginator)
	}
	if want := "codex_cli_rs/0.160.1 (Linux 7.0.0-28; x86_64) rust"; got.UserAgent != want {
		t.Fatalf("UserAgent = %q, want %q", got.UserAgent, want)
	}
}

func TestResolveCodexIdentityConfiguredAllFields(t *testing.T) {
	cfg := &Config{Codex: CodexConfig{ClientIdentity: CodexClientIdentity{
		Version:    "9.9.9",
		Originator: "custom-cli",
		UserAgent:  "custom-cli/9.9.9 (Test)",
	}}}
	got := cfg.ResolveCodexIdentity()
	if got.Version != "9.9.9" || got.Originator != "custom-cli" || got.UserAgent != "custom-cli/9.9.9 (Test)" {
		t.Fatalf("identity = %#v", got)
	}
}

func TestLoadConfigOptional_CodexClientIdentitySanitized(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	configYAML := []byte(`
codex:
  client-identity:
    version: "  0.155.0  "
    originator: "  codex_cli_rs  "
    user-agent: "  codex_cli_rs/0.155.0 (Linux) rust  "
`)
	if err := os.WriteFile(configPath, configYAML, 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	cfg, err := LoadConfigOptional(configPath, false)
	if err != nil {
		t.Fatalf("LoadConfigOptional() error = %v", err)
	}
	if got := cfg.Codex.ClientIdentity.Version; got != "0.155.0" {
		t.Fatalf("Version = %q, want 0.155.0", got)
	}
	if got := cfg.Codex.ClientIdentity.Originator; got != "codex_cli_rs" {
		t.Fatalf("Originator = %q, want codex_cli_rs", got)
	}
	if got := cfg.Codex.ClientIdentity.UserAgent; got != "codex_cli_rs/0.155.0 (Linux) rust" {
		t.Fatalf("UserAgent = %q", got)
	}
	if resolved := cfg.ResolveCodexIdentity(); resolved.UserAgent != "codex_cli_rs/0.155.0 (Linux) rust" {
		t.Fatalf("resolved UserAgent = %q", resolved.UserAgent)
	}
}
