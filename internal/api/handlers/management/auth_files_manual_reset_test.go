package management

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/fingerprint"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestCredentialStatusForceCheckAlreadyEnabled(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	authDir := t.TempDir()
	fileName := "manual-enabled.json"
	filePath := filepath.Join(authDir, fileName)
	if err := os.WriteFile(filePath, []byte(`{"type":"codex","disabled":false}`), 0600); err != nil {
		t.Fatal(err)
	}
	enabled := true
	cfg := &config.Config{AuthDir: authDir, Fingerprint: config.FingerprintConfig{FingerprintPolicy: config.FingerprintPolicy{Enabled: &enabled, Models: []string{"gpt-6-sol"}}}}
	manager := coreauth.NewManager(nil, nil, nil)
	auth, err := manager.Register(context.Background(), &coreauth.Auth{ID: fileName, FileName: fileName, Provider: "codex", Status: coreauth.StatusActive, Attributes: map[string]string{"path": filePath}})
	if err != nil {
		t.Fatal(err)
	}
	identityRaw, _ := json.Marshal([]any{"codex", fileName, nil, nil})
	sum := sha256.Sum256(identityRaw)
	deadline := time.Now().Add(96 * time.Hour)
	wait := &coreauth.DiagnosticUnavailable{Reason: "quota", Scope: "credential", RetryAt: deadline}
	result := fingerprint.ModelResult{Model: "gpt-6-sol", Status: "error", Error: "upstream_http_429", Deferred: wait}
	persisted := fingerprint.State{Identity: hex.EncodeToString(sum[:]), RequestsToday: 5, History: []fingerprint.Run{{Results: []fingerprint.ModelResult{result}}}, ModelStates: map[string]*fingerprint.ModelState{"gpt-6-sol": {Blocked: true, Result: &result, Wait: wait, NextRunAt: deadline, Failures: 7}}}
	stateRaw, _ := json.Marshal(map[string]any{"version": 1, "states": map[string]any{fileName: persisted}})
	if err := os.WriteFile(filepath.Join(authDir, ".fingerprint-state"), stateRaw, 0600); err != nil {
		t.Fatal(err)
	}
	monitor := fingerprint.New(func() *config.Config { return cfg }, manager.List, nil)
	auth.Quota = coreauth.QuotaState{Exceeded: true, Reason: "credential_quota", NextRecoverAt: deadline}
	if _, err = manager.Update(context.Background(), auth); err != nil {
		t.Fatal(err)
	}
	calls := 0
	manager.SetCooldownResetHook(func(a *coreauth.Auth) error { calls++; return monitor.ResetCooldown(a) })
	h := NewHandlerWithoutConfigFilePath(cfg, manager)
	for _, disabled := range []bool{false, true, false, false} {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		body := `{"name":"` + fileName + `","disabled":false}`
		if disabled {
			body = `{"name":"` + fileName + `","disabled":true}`
		}
		c.Request = httptest.NewRequest(http.MethodPatch, "/v8/management/credentials/status", strings.NewReader(body))
		h.PatchAuthFileStatus(c)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		latest, _ := manager.GetByID(fileName)
		if latest.Disabled != disabled || latest.Quota.Exceeded || !latest.NextRetryAfter.IsZero() {
			t.Fatalf("manual status did not clear business wait: %+v", latest)
		}
	}
	if calls != 4 {
		t.Fatalf("manual enable did not notify every time: %d", calls)
	}
	got := monitor.Snapshot(auth)
	ms := got.ModelStates["gpt-6-sol"]
	if ms.Wait != nil || ms.NextRunAt.After(time.Now()) || ms.Failures != 0 || !ms.Blocked || ms.Result.Status != "error" || got.RequestsToday != 5 || len(got.History) != 1 || got.History[0].Results[0].Deferred == nil {
		t.Fatalf("forced enable failed to clear wait while preserving verdict and history: %+v", got)
	}
}
