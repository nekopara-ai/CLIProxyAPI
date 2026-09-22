package management

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestBuildAuthFileEntryIncludesCodexTurnTicketSnapshot(t *testing.T) {
	cfg := &config.Config{}
	cfg.Codex.TurnTicket.Enabled = true
	cfg.Codex.TurnTicket.TargetLength = 292
	adaptive := false
	cfg.Codex.TurnTicket.AdaptiveInjection = &adaptive
	cfg.Codex.TurnTicket.Models = []string{"gpt-5.5"}
	auth := &coreauth.Auth{
		ID:       "codex-ticket-auth",
		Index:    "codex-ticket-index",
		FileName: "codex-ticket.json",
		Provider: "codex",
		Status:   coreauth.StatusActive,
		Metadata: map[string]any{"access_token": "test-access-token", "auth_kind": "oauth"},
		Attributes: map[string]string{
			"runtime_only": "true",
		},
	}
	process := helps.ConfigureCodexTurnTickets(func() *config.Config { return cfg }, func() []*coreauth.Auth {
		return []*coreauth.Auth{auth}
	})
	defer helps.ConfigureCodexTurnTickets(nil, nil)

	now := time.Now().Truncate(time.Second)
	process.Store.Store(auth.ID, "gpt-5.5", &helps.CodexTurnTicket{
		State:      "gAAAAA" + strings.Repeat("x", 286),
		Length:     292,
		CapturedAt: now,
		ExpiresAt:  now.Add(time.Hour),
	})

	entry := (&Handler{}).buildAuthFileEntry(auth)
	encoded, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal auth file entry: %v", err)
	}
	var payload struct {
		CodexTurnTicket struct {
			State         string `json:"state"`
			HealthyModels int    `json:"healthy_models"`
			TotalModels   int    `json:"total_models"`
			TargetLength  int    `json:"target_length"`
		} `json:"codex_turn_ticket"`
	}
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatalf("decode auth file entry: %v", err)
	}
	if payload.CodexTurnTicket.State != "healthy" || payload.CodexTurnTicket.HealthyModels != 1 || payload.CodexTurnTicket.TotalModels != 1 || payload.CodexTurnTicket.TargetLength != 292 {
		t.Fatalf("unexpected ticket payload: %+v", payload.CodexTurnTicket)
	}
}
