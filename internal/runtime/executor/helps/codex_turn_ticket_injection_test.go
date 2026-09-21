package helps

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"gopkg.in/yaml.v3"
)

func TestCodexTurnTicketInjectionConfig(t *testing.T) {
	for _, tc := range []struct {
		name, field string
		want        bool
	}{
		{"omitted", "", true},
		{"null", "    injection-enabled: null\n", true},
		{"enabled", "    injection-enabled: true\n", true},
		{"disabled", "    injection-enabled: false\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cfg config.Config
			if err := yaml.Unmarshal([]byte("codex:\n  turn-ticket:\n    enabled: true\n"+tc.field), &cfg); err != nil {
				t.Fatal(err)
			}
			effective := EffectiveCodexTurnTicketConfig(cfg.CloneForRuntime())
			if effective.InjectionEnabled != tc.want || !effective.Enabled || !effective.FailClosed {
				t.Fatalf("unexpected effective switches: %+v", effective)
			}
		})
	}
}

func TestCodexTurnTicketInjectionOffKeepsHarvestingAndGuards(t *testing.T) {
	for _, length := range []int{292, 332} {
		t.Run(strconv.Itoa(length), func(t *testing.T) {
			state := testTurnState(t, time.Now().Unix(), length)
			var calls atomic.Int64
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set(CodexTurnStateHeader, state)
			}))
			defer upstream.Close()
			cfg := turnTicketTestConfig()
			off := false
			cfg.Codex.TurnTicket.InjectionEnabled = &off
			cfg.ProxyURL = "direct"
			cfg.Codex.TurnTicket.HarvestProxyURLs = []string{"direct"}
			auth := turnTicketTestAuth("active")
			auth.Attributes = map[string]string{"base_url": upstream.URL}
			if length == 332 {
				auth.Metadata["codex_turn_ticket_plan"] = "team"
			}
			disabled := auth.Clone()
			disabled.ID, disabled.Disabled = "disabled", true
			backoff := auth.Clone()
			backoff.ID = "backoff"
			process := ConfigureCodexTurnTickets(func() *config.Config { return cfg }, func() []*cliproxyauth.Auth {
				return []*cliproxyauth.Auth{auth, disabled, backoff}
			})
			defer ConfigureCodexTurnTickets(nil, nil)
			process.Harvester.backoffRun[codexTurnTicketKey(backoff.ID, "gpt-5.5")] = time.Now().Add(time.Hour)
			if CodexTurnTicketAllowsExecution(auth, "gpt-5.5") {
				t.Fatal("injection switch bypassed the missing-ticket guard")
			}
			process.Harvester.probeAll(context.Background())
			if calls.Load() != 1 || process.Store.Lookup(auth.ID, "gpt-5.5") == nil {
				t.Fatal("active probing stopped or disabled/backoff credentials were probed")
			}
			if !CodexTurnTicketAllowsExecution(auth, "gpt-5.5") {
				t.Fatal("healthy probed ticket did not satisfy the scheduling guard")
			}
			for _, clientState := range []string{"", "client-turn-state"} {
				headers := http.Header{}
				if clientState != "" {
					headers.Set(CodexTurnStateHeader, clientState)
				}
				if ApplyCodexTurnTicket(auth, "gpt-5.5", headers) || headers.Get(CodexTurnStateHeader) != clientState {
					t.Fatal("injection-disabled request did not preserve client headers")
				}
			}
			global := SnapshotCodexTurnTickets()
			credential := SnapshotCodexTurnTicketForAuth(auth)
			if !global.Enabled || global.InjectionEnabled || !global.FailClosed || credential.InjectionEnabled || credential.State != "healthy" {
				t.Fatalf("health reporting changed: global=%+v credential=%+v", global, credential)
			}
			passive := auth.Clone()
			passive.ID = "passive"
			HarvestCodexTurnStateOnResponse(passive, "gpt-5.5", http.Header{CodexTurnStateHeader: []string{state}})
			if process.Store.Lookup(passive.ID, "gpt-5.5") == nil {
				t.Fatal("injection switch disabled passive capture")
			}
			process.Store.Delete(auth.ID, "gpt-5.5")
			if CodexTurnTicketAllowsExecution(auth, "gpt-5.5") {
				t.Fatal("losing the healthy ticket no longer blocks scheduling")
			}
		})
	}
}
