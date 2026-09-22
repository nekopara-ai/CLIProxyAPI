package config

import (
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/constant"
)

// CodexIdentity is the resolved outbound Codex client identity.
type CodexIdentity struct {
	Version    string
	Originator string
	UserAgent  string
}

// ResolveCodexIdentity resolves the effective Codex client identity from the live config.
// Configured values win; empty fields fall back to the built-in defaults. Version and
// Originator are resolved first so a configured Version with an unset User-Agent still
// yields a self-consistent User-Agent.
func (cfg *Config) ResolveCodexIdentity() CodexIdentity {
	identity := CodexIdentity{
		Version:    constant.CodexClientVersion,
		Originator: constant.CodexOriginator,
	}
	if cfg != nil {
		if value := strings.TrimSpace(cfg.Codex.ClientIdentity.Version); value != "" {
			identity.Version = value
		}
		if value := strings.TrimSpace(cfg.Codex.ClientIdentity.Originator); value != "" {
			identity.Originator = value
		}
		if value := strings.TrimSpace(cfg.Codex.ClientIdentity.UserAgent); value != "" {
			identity.UserAgent = value
		}
	}
	if identity.UserAgent == "" {
		if identity.Version == constant.CodexClientVersion && identity.Originator == constant.CodexOriginator {
			identity.UserAgent = constant.CodexUserAgent
		} else {
			identity.UserAgent = constant.CodexUserAgentFor(identity.Originator, identity.Version)
		}
	}
	return identity
}
