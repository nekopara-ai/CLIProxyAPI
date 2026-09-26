package config

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestInternalRequestAPIKey(t *testing.T) {
	const key = "synthetic-system-key"
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(key)))
	for _, tc := range []struct {
		name, ref, want string
		keys            []string
		fail            bool
	}{
		{"unset", "", "", []string{key}, false},
		{"selects referenced key, not first", hash, key, []string{"business-key", key}, false},
		{"trim and case", " " + strings.ToUpper(hash) + " ", key, []string{" " + key + " "}, false},
		{"malformed", "not-a-hash", "", []string{key}, true},
		{"revoked", hash, "", []string{"business-key"}, true},
		{"empty keys", hash, "", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{InternalRequestAPIKeySHA256: tc.ref}
			cfg.APIKeys = tc.keys
			got, err := cfg.InternalRequestAPIKey()
			if got != tc.want || (err != nil) != tc.fail {
				t.Fatal("unexpected key resolution")
			}
			if err != nil && strings.Contains(err.Error(), key) {
				t.Fatal("secret leaked in diagnostic")
			}
		})
	}
	var nilConfig *Config
	if got, err := nilConfig.InternalRequestAPIKey(); got != "" || err != nil {
		t.Fatal("nil configuration should preserve compatibility")
	}
	var cfg Config
	if err := yaml.Unmarshal([]byte("internal-request-api-key-sha256: "+hash+"\napi-keys: ["+key+"]\n"), &cfg); err != nil {
		t.Fatal(err)
	}
	if got, err := cfg.InternalRequestAPIKey(); got != key || err != nil {
		t.Fatal("YAML reference was not loaded")
	}
}
