// Package buildinfo exposes compile-time metadata shared across the server.
package buildinfo

import "strings"

// Capability constants advertised on management API responses so management
// panels do not need to infer runtime semantics from free-form version strings.
const (
	ForkName                 = "nekopara"
	ExcludedModelsPrecedence = "override"
	DefaultLocalVersion      = "8.0.77-nekopara.1-local"
)

// The following variables are overridden via ldflags during release builds.
// Defaults cover local development builds.
var (
	// Version is the semantic version or git describe output of the binary.
	Version = "dev"

	// Commit is the git commit SHA baked into the binary.
	Commit = "none"

	// BuildDate records when the binary was built in UTC.
	BuildDate = "unknown"
)

// NormalizeVersion returns a valid >=8.0.33 semantic version when a server
// binary is compiled locally without explicit -ldflags "-X main.Version=...".
func NormalizeVersion(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.EqualFold(trimmed, "dev") {
		return DefaultLocalVersion
	}
	return trimmed
}
