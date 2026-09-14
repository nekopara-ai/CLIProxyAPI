package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigOptional_TimezoneOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := []byte("port: 8080\ntimezone-override: \"  America/New_York  \"\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := LoadConfigOptional(path, true)
	if err != nil {
		t.Fatalf("LoadConfigOptional: %v", err)
	}
	if got := cfg.TimezoneOverride; got != "America/New_York" {
		t.Fatalf("TimezoneOverride = %q, want America/New_York", got)
	}
}
