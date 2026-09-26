package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// InternalRequestAPIKey resolves a hash reference without duplicating a secret in policy snapshots.
// An unset reference preserves compatibility. An invalid or revoked reference must not
// silently attribute requests to another client or publish more unknown-key usage.
func (cfg *Config) InternalRequestAPIKey() (string, error) {
	if cfg == nil || strings.TrimSpace(cfg.InternalRequestAPIKeySHA256) == "" {
		return "", nil
	}
	want := strings.ToLower(strings.TrimSpace(cfg.InternalRequestAPIKeySHA256))
	decoded, err := hex.DecodeString(want)
	if err != nil || len(decoded) != sha256.Size {
		return "", errors.New("internal-request-api-key-sha256 must be a SHA-256 hex digest")
	}
	for _, raw := range cfg.APIKeys {
		key := strings.TrimSpace(raw)
		if key == "" {
			continue
		}
		sum := sha256.Sum256([]byte(key))
		if hex.EncodeToString(sum[:]) == want {
			return key, nil
		}
	}
	return "", errors.New("internal-request-api-key-sha256 does not match a configured api-keys entry")
}
