package watcher

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestConfigWatcherSurvivesRepeatedAtomicReplacement(t *testing.T) {
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auths")
	if err := os.Mkdir(authDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	write := func(path string, port int) {
		t.Helper()
		if err := os.WriteFile(path, []byte(fmt.Sprintf("port: %d\nauth-dir: %q\n", port, authDir)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(path, 18001)
	reloads := make(chan int, 16)
	w, err := NewWatcher(path, authDir, func(cfg *config.Config) { reloads <- cfg.Port })
	if err != nil {
		t.Fatal(err)
	}
	w.SetConfig(&config.Config{Port: 18001, AuthDir: authDir})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer w.Stop()
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	for _, port := range []int{18002, 18003} {
		tmp := filepath.Join(dir, "config.next.yaml")
		write(tmp, port)
		if err := os.Rename(tmp, path); err != nil {
			t.Fatal(err)
		}
		timeout := time.NewTimer(3 * time.Second)
		matched := false
		for !matched {
			select {
			case got := <-reloads:
				matched = got == port
			case <-timeout.C:
				t.Fatalf("atomic replacement with port %d was not reloaded", port)
			}
		}
		timeout.Stop()
	}
}

func TestConfigReloadDoesNotMarkConcurrentSaveAsApplied(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	write := func(port int) {
		t.Helper()
		if err := os.WriteFile(path, []byte(fmt.Sprintf("port: %d\nauth-dir: %q\n", port, dir)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(18002)
	var applied []int
	w, err := NewWatcher(path, dir, func(cfg *config.Config) {
		applied = append(applied, cfg.Port)
		if cfg.Port == 18002 {
			write(18003)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Stop()
	w.SetConfig(&config.Config{Port: 18001, AuthDir: dir})
	w.ReloadConfigIfChanged()
	w.ReloadConfigIfChanged()
	if len(applied) != 2 || applied[0] != 18002 || applied[1] != 18003 {
		t.Fatalf("newer save was marked applied without reloading it: %v", applied)
	}
}
