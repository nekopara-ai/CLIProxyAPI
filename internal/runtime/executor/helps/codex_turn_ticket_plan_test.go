package helps

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	auth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func ticketPlanJWT(plan, account string) string {
	b, _ := json.Marshal(map[string]any{"https://api.openai.com/auth": map[string]string{"chatgpt_plan_type": plan, "chatgpt_account_id": account}})
	return "header." + base64.RawURLEncoding.EncodeToString(b) + ".signature"
}

func TestCodexTurnTicketPlanSources(t *testing.T) {
	for _, tc := range []struct {
		name     string
		metadata map[string]any
		want     int
		source   string
	}{
		{"opaque import explicit team", map[string]any{"access_token": "opaque", "account_id": "workspace", CodexTurnTicketPlanField: "team"}, 332, "manual"},
		{"id token team", map[string]any{"id_token": ticketPlanJWT("team", "workspace"), "account_id": "workspace"}, 332, "id_token"},
		{"access only business", map[string]any{"access_token": ticketPlanJWT("business", "workspace"), "account_id": "workspace"}, 332, "access_token"},
		{"different workspace", map[string]any{"id_token": ticketPlanJWT("pro", "personal"), "account_id": "workspace"}, 292, "config"},
		{"no selected workspace", map[string]any{"id_token": ticketPlanJWT("team", "workspace")}, 292, "config"},
		{"explicit beats token", map[string]any{CodexTurnTicketPlanField: "pro", "id_token": ticketPlanJWT("team", "workspace"), "account_id": "workspace"}, 292, "manual"},
		{"invalid policy fails closed", map[string]any{CodexTurnTicketPlanField: "typo"}, 1, "manual"},
		{"filename and plan metadata not authoritative", map[string]any{"email": "team@example.invalid", "plan_type": "team"}, 292, "config"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := ResolveCodexTurnTicketPlan(&auth.Auth{Metadata: tc.metadata}, 292)
			if p.TargetLength != tc.want || p.Source != tc.source {
				t.Fatalf("policy=%+v", p)
			}
		})
	}
}

func TestCodexTeamTicketRestoreInjectionAndPolicyChange(t *testing.T) {
	now := time.Now()
	path := filepath.Join(t.TempDir(), "tickets")
	store := NewPersistentCodexTurnTicketStore(path, 292, time.Hour)
	a := &auth.Auth{ID: "imported-team", Provider: "codex", Status: auth.StatusActive, Metadata: map[string]any{"access_token": "opaque", CodexTurnTicketPlanField: "team"}}
	cfg := &config.Config{}
	cfg.Codex.TurnTicket.Enabled = true
	adaptive := false
	cfg.Codex.TurnTicket.AdaptiveInjection = &adaptive
	cfg.Codex.TurnTicket.Models = []string{"gpt-6-astra"}
	store.Store(a.ID, "gpt-6-astra", NewCodexTurnTicket(testTurnState(t, now.Unix(), 332), now, time.Hour))
	store = NewPersistentCodexTurnTicketStore(path, 292, time.Hour)
	h := NewCodexTurnTicketHarvester(store, func() *config.Config { return cfg }, func() []*auth.Auth { return []*auth.Auth{a} })
	old := codexTurnTicketProcess.Swap(&CodexTurnTicketProcess{Store: store, Harvester: h})
	defer codexTurnTicketProcess.Store(old)
	inject := NewCodexTurnTicketInjector(store, func() *config.Config { return cfg })
	headers := http.Header{}
	if !CodexTurnTicketAllowsExecution(a, "gpt-6-astra") || !inject.Apply(a, "gpt-6-astra", headers) || len(headers.Get(CodexTurnStateHeader)) != 332 {
		t.Fatal("imported Team ticket not restored/admitted/injected")
	}
	snapshot := SnapshotCodexTurnTicketForAuth(a)
	if snapshot.TargetLength != 332 || snapshot.Plan != "team" || snapshot.State != "healthy" {
		t.Fatalf("snapshot=%+v", snapshot)
	}
	if SnapshotCodexTurnTickets().HealthyTickets != 1 {
		t.Fatal("Team absent from healthy total")
	}
	a.Metadata[CodexTurnTicketPlanField] = "pro"
	if CodexTurnTicketAllowsExecution(a, "gpt-6-astra") || inject.Apply(a, "gpt-6-astra", http.Header{}) {
		t.Fatal("Team ticket crossed into personal policy")
	}
	h.setProbeCooldown(a.ID, "gpt-6-astra", now.Add(time.Hour))
	InvalidateCodexTurnTicketsForAuth(a.ID)
	a.Metadata[CodexTurnTicketPlanField] = "team"
	if CodexTurnTicketAllowsExecution(a, "gpt-6-astra") {
		t.Fatal("old ticket resurrected after switching back")
	}
	if !h.reserveProbeSlot(a.ID, "gpt-6-astra", now, EffectiveCodexTurnTicketConfig(cfg)) {
		t.Fatal("stale success cooldown remains")
	}
}

func TestCodexTeamPassiveCaptureRejectsPersonalAndDegraded(t *testing.T) {
	a := &auth.Auth{ID: "team", Provider: "codex", Metadata: map[string]any{"access_token": "opaque", CodexTurnTicketPlanField: "team"}}
	cfg := &config.Config{}
	cfg.Codex.TurnTicket.Enabled = true
	adaptive := false
	cfg.Codex.TurnTicket.AdaptiveInjection = &adaptive
	cfg.Codex.TurnTicket.Models = []string{"gpt-6-astra"}
	store := NewCodexTurnTicketStore()
	h := NewCodexTurnTicketHarvester(store, func() *config.Config { return cfg }, nil)
	for _, length := range []int{292, 312, 356, 332} {
		headers := http.Header{}
		headers.Set(CodexTurnStateHeader, testTurnState(t, time.Now().Unix(), length))
		h.HarvestCodexTurnStatePassively(a, "gpt-6-astra", headers)
		if got := store.Lookup(a.ID, "gpt-6-astra"); (got != nil) != (length == 332) {
			t.Fatalf("capture length %d accepted=%t", length, got != nil)
		}
	}
}
