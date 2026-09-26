package management

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/fingerprint"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestAuthFileFingerprintModelBlockKeepsCredentialAvailable(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	dir := t.TempDir()
	a := &coreauth.Auth{
		ID: "synthetic-fingerprint", FileName: "synthetic.json", Provider: "codex", Status: coreauth.StatusActive,
		Attributes: map[string]string{"path": filepath.Join(dir, "synthetic.json")},
		Metadata:   map[string]any{"account_id": "synthetic"},
	}
	if err := os.WriteFile(a.Attributes["path"], []byte(`{"type":"codex","disabled":false}`), 0600); err != nil {
		t.Fatal(err)
	}
	enabled := true
	cfg := &config.Config{AuthDir: dir, Fingerprint: config.FingerprintConfig{FingerprintPolicy: config.FingerprintPolicy{
		Enabled: &enabled, Models: []string{"gpt-6-sol", "gpt-6-astra"},
	}}}
	identity, _ := json.Marshal([]any{a.Provider, a.ID, a.Metadata["account_id"], a.Metadata["email"]})
	sum := sha256.Sum256(identity)
	state := &fingerprint.State{Identity: hex.EncodeToString(sum[:]), ModelStates: map[string]*fingerprint.ModelState{
		"gpt-6-sol":   {Blocked: true, CooldownUntil: time.Now().Add(3 * time.Hour)},
		"gpt-6-astra": {Blocked: false},
	}}
	raw, _ := json.Marshal(map[string]any{"version": 1, "states": map[string]*fingerprint.State{a.ID: state}})
	if err := os.WriteFile(filepath.Join(dir, ".fingerprint-state"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	monitor := fingerprint.New(func() *config.Config { return cfg }, func() []*coreauth.Auth { return []*coreauth.Auth{a} }, nil)
	previous := fingerprint.Current()
	fingerprint.SetCurrent(monitor)
	t.Cleanup(func() { fingerprint.SetCurrent(previous) })
	h := NewHandlerWithoutConfigFilePath(cfg, nil)
	entry := h.buildAuthFileEntry(a)
	if entry == nil || entry["disabled"] != false || entry["unavailable"] != false || entry["status"] != coreauth.StatusActive {
		t.Fatalf("model block incorrectly disabled whole credential: %+v", entry)
	}
	snapshot, ok := entry["fingerprint_status"].(fingerprint.Snapshot)
	if !ok || !snapshot.Blocked || !snapshot.ModelStates["gpt-6-sol"].Blocked || snapshot.ModelStates["gpt-6-astra"].Blocked {
		t.Fatalf("missing model-level management state: %+v", snapshot)
	}
	if monitor.Allowed(a, "gpt-6-sol(high)") || !monitor.Allowed(a, "gpt-6-astra") || !monitor.Allowed(a, "gpt-5.6-sol") {
		t.Fatal("model eligibility disagrees with management state")
	}
}
