package watcher

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"gopkg.in/yaml.v3"
)

func TestIsOAuthModelAliasOnlyChange(t *testing.T) {
	base := &config.Config{Port: 8080, AuthDir: t.TempDir()}
	aliasChanged := base.CloneForRuntime()
	aliasChanged.OAuthModelAlias = map[string][]config.OAuthModelAlias{
		"codex": {{Name: "gpt-5", Alias: "gpt-5-public"}},
	}
	if !isOAuthModelAliasOnlyChange(base, aliasChanged) {
		t.Fatal("expected an alias-only change to be classified as alias-only")
	}

	unchanged := base.CloneForRuntime()
	if isOAuthModelAliasOnlyChange(base, unchanged) {
		t.Fatal("unchanged configs must not take the preserve-executors path")
	}

	otherChanged := aliasChanged.CloneForRuntime()
	otherChanged.Port++
	if isOAuthModelAliasOnlyChange(base, otherChanged) {
		t.Fatal("alias plus port changes must take the full reload path")
	}
}

func TestWatcherRoutesOnlyOAuthModelAliasChangeToNarrowCallback(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	base := &config.Config{
		Port:               8080,
		AuthDir:            filepath.Join(tmpDir, "auth"),
		CredentialInFlight: config.DefaultCredentialInFlightConfig(),
	}
	if errMkdir := os.MkdirAll(base.AuthDir, 0o755); errMkdir != nil {
		t.Fatalf("create auth dir: %v", errMkdir)
	}
	write := func(cfg *config.Config) {
		data, errMarshal := yaml.Marshal(cfg)
		if errMarshal != nil {
			t.Fatalf("marshal config: %v", errMarshal)
		}
		if errWrite := os.WriteFile(configPath, data, 0o644); errWrite != nil {
			t.Fatalf("write config: %v", errWrite)
		}
	}
	write(base)
	loadedBase, errLoad := config.LoadConfig(configPath)
	if errLoad != nil {
		t.Fatalf("load base config: %v", errLoad)
	}

	var fullReloads atomic.Int32
	var aliasReloads atomic.Int32
	w := &Watcher{
		configPath:     configPath,
		authDir:        base.AuthDir,
		reloadCallback: func(*config.Config) { fullReloads.Add(1) },
	}
	w.SetConfig(loadedBase)
	w.SetOAuthModelAliasReloadCallback(func(cfg *config.Config) {
		if cfg == nil || len(cfg.OAuthModelAlias["codex"]) != 1 {
			t.Errorf("alias callback received unexpected config: %+v", cfg)
		}
		aliasReloads.Add(1)
	})

	aliasConfig := loadedBase.CloneForRuntime()
	aliasConfig.OAuthModelAlias = map[string][]config.OAuthModelAlias{
		"codex": {{Name: "gpt-5", Alias: "gpt-5-public"}},
	}
	write(aliasConfig)
	if !w.reloadConfig() {
		t.Fatal("alias-only reload failed")
	}
	if got := aliasReloads.Load(); got != 1 {
		t.Fatalf("narrow callback count = %d, want 1", got)
	}
	if got := fullReloads.Load(); got != 0 {
		t.Fatalf("full callback count = %d, want 0", got)
	}

	otherConfig := aliasConfig.CloneForRuntime()
	otherConfig.Port++
	write(otherConfig)
	if !w.reloadConfig() {
		t.Fatal("full reload failed")
	}
	if got := fullReloads.Load(); got != 1 {
		t.Fatalf("full callback count after unrelated change = %d, want 1", got)
	}
	if got := aliasReloads.Load(); got != 1 {
		t.Fatalf("narrow callback count after unrelated change = %d, want 1", got)
	}
}
