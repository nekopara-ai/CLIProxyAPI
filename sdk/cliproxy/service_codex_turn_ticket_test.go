package cliproxy

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// turnTicketServiceConfig returns a config with a stored-ticket-eligible model scope but
// the feature still disabled, which is the state operators start from.
func turnTicketServiceConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Codex.TurnTicket.TargetLength = 292
	adaptive := false
	cfg.Codex.TurnTicket.AdaptiveInjection = &adaptive
	cfg.Codex.TurnTicket.Models = []string{"gpt-5.5"}
	return cfg
}

// turnTicketServiceState builds a syntactically valid Fernet-shaped turn-state token.
func turnTicketServiceState(t *testing.T) string {
	t.Helper()
	const wantLength = 292
	payload := make([]byte, 0, wantLength)
	payload = append(payload, 0x80)
	stamp := make([]byte, 8)
	binary.BigEndian.PutUint64(stamp, uint64(time.Now().Unix()))
	payload = append(payload, stamp...)
	for i := 0; i < wantLength; i++ {
		payload = append(payload, 0)
	}
	for trim := len(payload); trim >= 9; trim-- {
		candidate := base64.RawURLEncoding.EncodeToString(payload[:trim])
		if len(candidate) == wantLength {
			return candidate
		}
	}
	t.Fatalf("could not build a %d-character turn state", wantLength)
	return ""
}

// TestServiceConfigReloadEnablesTurnTicketInjection is the service-level regression for
// the reload defect: commitConfigUpdate replaces the config pointer, so any consumer that
// captured the startup pointer keeps reading stale settings. The injector must therefore
// observe the reloaded config on its very next call.
func TestServiceConfigReloadEnablesTurnTicketInjection(t *testing.T) {
	defer helps.ConfigureCodexTurnTickets(nil, nil)
	startCfg := turnTicketServiceConfig()
	service := &Service{cfg: startCfg, coreManager: coreauth.NewManager(nil, nil, nil)}
	service.startCodexTurnTicketHarvester(context.Background())
	defer service.stopCodexTurnTicketHarvester()

	process := helps.CurrentCodexTurnTickets()
	if process == nil {
		t.Fatal("startCodexTurnTicketHarvester did not install the process-wide wiring")
	}
	state := turnTicketServiceState(t)
	process.Store.Store("auth-a", "gpt-5.5", helps.NewCodexTurnTicket(state, time.Now(), time.Hour))
	auth := &coreauth.Auth{ID: "auth-a", Provider: "codex"}

	// The feature starts disabled, so a stored ticket must not be replayed yet.
	disabledHeaders := http.Header{}
	helps.ApplyCodexTurnTicket(auth, "gpt-5.5", disabledHeaders)
	if got := disabledHeaders.Get(helps.CodexTurnStateHeader); got != "" {
		t.Fatalf("injection happened while the feature was disabled: %q", got)
	}

	// Enable the feature the same way the file watcher and the management API do: commit a
	// new in-memory config. No service restart and no re-wiring is involved.
	reloaded := startCfg.CloneForRuntime()
	reloaded.Codex.TurnTicket.Enabled = true
	reloaded.Codex.TurnTicket.GatewayMint = func() *bool { v := false; return &v }() // Exercise the rollback engine.
	if commit := service.commitConfigUpdate(reloaded); commit.cfg == nil {
		t.Fatal("commitConfigUpdate rejected the reloaded config")
	}

	enabledHeaders := http.Header{}
	helps.ApplyCodexTurnTicket(auth, "gpt-5.5", enabledHeaders)
	if got := enabledHeaders.Get(helps.CodexTurnStateHeader); got != state {
		t.Fatalf("config reload did not enable injection: got %d chars, want the stored %d-char ticket", len(got), len(state))
	}
}

// TestServiceConfigReloadDisablesTurnTicketInjection covers the opposite direction: a
// reload that turns the feature off must stop injection immediately, without waiting for a
// restart or a fresh harvest cycle.
func TestServiceConfigReloadDisablesTurnTicketInjection(t *testing.T) {
	defer helps.ConfigureCodexTurnTickets(nil, nil)
	startCfg := turnTicketServiceConfig()
	startCfg.Codex.TurnTicket.Enabled = true
	startCfg.Codex.TurnTicket.GatewayMint = func() *bool { v := false; return &v }() // Exercise the rollback engine.
	service := &Service{cfg: startCfg, coreManager: coreauth.NewManager(nil, nil, nil)}
	service.startCodexTurnTicketHarvester(context.Background())
	defer service.stopCodexTurnTicketHarvester()

	process := helps.CurrentCodexTurnTickets()
	if process == nil {
		t.Fatal("startCodexTurnTicketHarvester did not install the process-wide wiring")
	}
	state := turnTicketServiceState(t)
	process.Store.Store("auth-a", "gpt-5.5", helps.NewCodexTurnTicket(state, time.Now(), time.Hour))
	auth := &coreauth.Auth{ID: "auth-a", Provider: "codex"}

	enabledHeaders := http.Header{}
	helps.ApplyCodexTurnTicket(auth, "gpt-5.5", enabledHeaders)
	if got := enabledHeaders.Get(helps.CodexTurnStateHeader); got != state {
		t.Fatalf("the enabled feature did not inject: got %d chars", len(got))
	}

	reloaded := startCfg.CloneForRuntime()
	reloaded.Codex.TurnTicket.Enabled = false
	if commit := service.commitConfigUpdate(reloaded); commit.cfg == nil {
		t.Fatal("commitConfigUpdate rejected the reloaded config")
	}

	disabledHeaders := http.Header{}
	clientValue := "client-supplied-value"
	disabledHeaders.Set(helps.CodexTurnStateHeader, clientValue)
	helps.ApplyCodexTurnTicket(auth, "gpt-5.5", disabledHeaders)
	if got := disabledHeaders.Get(helps.CodexTurnStateHeader); got != clientValue {
		t.Fatalf("injection continued after the reload disabled it: got %q", got)
	}
}

// TestCodexTurnTicketSummaryNeverLeaksMaterial pins the redaction contract of the
// diagnostics surface used by logs and by the management API.
func TestCodexTurnTicketSummaryNeverLeaksMaterial(t *testing.T) {
	defer helps.ConfigureCodexTurnTickets(nil, nil)
	cfg := turnTicketServiceConfig()
	cfg.Codex.TurnTicket.Enabled = true
	cfg.Codex.TurnTicket.GatewayMint = func() *bool { v := false; return &v }() // Exercise the rollback engine.
	cfg.Codex.TurnTicket.HarvestProxyURLs = []string{"direct", "http://user:proxy-secret@127.0.0.1:8080"}
	service := &Service{cfg: cfg, coreManager: coreauth.NewManager(nil, nil, nil)}
	service.startCodexTurnTicketHarvester(context.Background())
	defer service.stopCodexTurnTicketHarvester()

	process := helps.CurrentCodexTurnTickets()
	if process == nil {
		t.Fatal("startCodexTurnTicketHarvester did not install the process-wide wiring")
	}
	state := turnTicketServiceState(t)
	process.Store.Store("auth-a", "gpt-5.5", helps.NewCodexTurnTicket(state, time.Now(), time.Hour))

	summary := CodexTurnTicketSummary()
	for _, leaked := range []string{state, "auth-a", "proxy-secret"} {
		if summary == "" || strings.Contains(summary, leaked) {
			t.Fatalf("summary %q leaked %q", summary, leaked)
		}
	}
	snapshot := CodexTurnTicketSnapshot()
	if !snapshot.Configured || !snapshot.Enabled {
		t.Fatalf("snapshot did not report the enabled feature: %+v", snapshot)
	}
	if snapshot.Buckets != 1 || snapshot.HealthyTickets != 1 {
		t.Fatalf("snapshot occupancy = %d/%d, want 1/1", snapshot.Buckets, snapshot.HealthyTickets)
	}
}

func TestServiceConfigReloadTogglesOnlyTicketInjection(t *testing.T) {
	defer helps.ConfigureCodexTurnTickets(nil, nil)
	cfg := turnTicketServiceConfig()
	cfg.Codex.TurnTicket.Enabled = true
	cfg.Codex.TurnTicket.GatewayMint = func() *bool { v := false; return &v }() // Exercise the rollback engine.
	service := &Service{cfg: cfg, coreManager: coreauth.NewManager(nil, nil, nil)}
	service.startCodexTurnTicketHarvester(context.Background())
	defer service.stopCodexTurnTicketHarvester()
	process := helps.CurrentCodexTurnTickets()
	state := turnTicketServiceState(t)
	auth := &coreauth.Auth{ID: "auth-a", Provider: "codex", Metadata: map[string]any{"access_token": "fixture"}}
	process.Store.Store(auth.ID, "gpt-5.5", helps.NewCodexTurnTicket(state, time.Now(), time.Hour))
	for _, enabled := range []bool{true, false, true} {
		reloaded := cfg.CloneForRuntime()
		reloaded.Codex.TurnTicket.InjectionEnabled = &enabled
		if commit := service.commitConfigUpdate(reloaded); commit.cfg == nil {
			t.Fatal("config update was rejected")
		}
		headers := http.Header{}
		if helps.ApplyCodexTurnTicket(auth, "gpt-5.5", headers) != enabled {
			t.Fatal("injection did not follow the live config")
		}
		if !process.Harvester.Running() || !helps.CodexTurnTicketAllowsExecution(auth, "gpt-5.5") {
			t.Fatal("toggling injection stopped the harvester or blocked a healthy credential")
		}
		missing := auth.Clone()
		missing.ID = "missing"
		if helps.CodexTurnTicketAllowsExecution(missing, "gpt-5.5") {
			t.Fatal("toggling injection bypassed fail-closed scheduling")
		}
	}
}
