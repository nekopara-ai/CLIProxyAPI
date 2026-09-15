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
	if cfg.TimezoneOverrideCountry != "" || cfg.TimezoneOverrideRegion != "" || cfg.TimezoneOverrideCity != "" {
		t.Fatalf("unconfigured location triple = %q/%q/%q, want empty", cfg.TimezoneOverrideCountry, cfg.TimezoneOverrideRegion, cfg.TimezoneOverrideCity)
	}
}

func TestLoadConfigOptional_TimezoneOverrideLocation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := []byte("port: 8080\ntimezone-override: \"America/New_York\"\n" +
		"timezone-override-country: \"  US  \"\n" +
		"timezone-override-region: \"New York\"\n" +
		"timezone-override-city: \" New York \"\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := LoadConfigOptional(path, true)
	if err != nil {
		t.Fatalf("LoadConfigOptional: %v", err)
	}
	if cfg.TimezoneOverrideCountry != "US" || cfg.TimezoneOverrideRegion != "New York" || cfg.TimezoneOverrideCity != "New York" {
		t.Fatalf("location triple = %q/%q/%q, want US/New York/New York", cfg.TimezoneOverrideCountry, cfg.TimezoneOverrideRegion, cfg.TimezoneOverrideCity)
	}
}
