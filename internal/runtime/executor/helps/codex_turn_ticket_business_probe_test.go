package helps

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestCodexTurnTicketBusinessFirst(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		status, length             int
		authProxy, direct, invalid bool
		fallback                   bool
		team                       bool
	}{
		{name: "team business healthy", status: 200, length: 332, team: true},
		{name: "team degraded fallback", status: 200, length: 356, team: true, fallback: true},
		{name: "team rejects personal", status: 200, length: 292, team: true},
		{name: "credential proxy healthy", status: 200, length: 292, authProxy: true},
		{name: "global proxy healthy", status: 200, length: 292},
		{name: "credential proxy degraded", status: 200, length: 312, authProxy: true, fallback: true},
		{name: "global proxy degraded", status: 200, length: 312, fallback: true},
		{name: "explicit direct overrides global", status: 200, length: 292, direct: true},
		{name: "missing ticket", status: 200},
		{name: "other length", status: 200, length: 300},
		{name: "rate limited", status: 429, length: 312},
		{name: "unauthorized", status: 401, length: 312},
		{name: "forbidden", status: 403, length: 312},
		{name: "server error", status: 502, length: 312},
		{name: "invalid business proxy", invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var businessHits, harvestHits, globalHits atomic.Int64
			target := 292
			if tc.team {
				target = 332
			}
			business := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				businessHits.Add(1)
				if r.Header.Get(CodexTurnStateHeader) != "" {
					t.Error("probe replayed the expiring ticket")
				}
				if tc.length > 0 {
					w.Header().Set(CodexTurnStateHeader, testTurnState(t, time.Now().Unix(), tc.length))
				}
				w.WriteHeader(tc.status)
			}))
			defer business.Close()
			harvest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if businessHits.Load() != 1 {
					t.Error("harvest must follow the business probe")
				}
				harvestHits.Add(1)
				w.Header().Set(CodexTurnStateHeader, testTurnState(t, time.Now().Unix(), target))
			}))
			defer harvest.Close()
			global := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				globalHits.Add(1)
				w.WriteHeader(500)
			}))
			defer global.Close()
			cfg := turnTicketTestConfig()
			cfg.ProxyURL = business.URL
			cfg.Codex.TurnTicket.HarvestProxyURLs = []string{harvest.URL}
			auth := turnTicketTestAuth("auth-a")
			if tc.team {
				auth.Metadata[CodexTurnTicketPlanField] = "team"
			}
			auth.Attributes = map[string]string{"base_url": business.URL}
			if tc.authProxy {
				auth.ProxyURL, cfg.ProxyURL = business.URL, global.URL
			}
			if tc.direct {
				auth.ProxyURL, cfg.ProxyURL = "direct", global.URL
			}
			if tc.invalid {
				auth.ProxyURL = "ftp://invalid.example"
			}
			store := NewCodexTurnTicketStore()
			old := NewCodexTurnTicket(testTurnState(t, time.Now().Add(-55*time.Minute).Unix(), target), time.Now(), time.Hour)
			store.Store(auth.ID, "gpt-5.5", old)
			h := NewCodexTurnTicketHarvester(store, turnTicketTestConfigProvider(cfg), func() []*cliproxyauth.Auth { return []*cliproxyauth.Auth{auth} })
			h.probeAll(context.Background())
			wantBusiness := int64(1)
			if tc.invalid {
				wantBusiness = 0
			}
			wantHarvest := int64(0)
			if tc.fallback {
				wantHarvest = 1
			}
			if businessHits.Load() != wantBusiness || harvestHits.Load() != wantHarvest || globalHits.Load() != 0 {
				t.Fatalf("hits business/harvest/unused global = %d/%d/%d; want %d/%d/0", businessHits.Load(), harvestHits.Load(), globalHits.Load(), wantBusiness, wantHarvest)
			}
			if h.Stats(292).Probed != 1+wantHarvest {
				t.Fatal("probe counter must count both attempts")
			}
			ticket := store.Lookup(auth.ID, "gpt-5.5")
			healthy := tc.fallback || (tc.status == 200 && tc.length == target)
			if healthy && ticket.State == old.State {
				t.Fatal("healthy result did not replace the expiring ticket")
			}
			if !healthy && ticket.State != old.State {
				t.Fatal("failed probe replaced the still-valid ticket")
			}
			if healthy {
				h.probeAll(context.Background())
				if h.Stats(292).Probed != 1+wantHarvest {
					t.Fatal("fresh ticket should suppress further probes")
				}
			}
		})
	}
}
