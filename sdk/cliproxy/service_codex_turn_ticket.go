package cliproxy

import (
	"context"
	"strings"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

var codexTurnTicketLifecycleMu sync.Mutex

// startCodexTurnTicketHarvester installs the process-wide turn-state ticket store and
// starts the background harvester when the configuration enables it.
//
// With turn-ticket.enabled false the wiring is installed but inert: injection and passive
// capture both check the live config on every call, so the feature costs nothing until an
// operator opts in. Once enabled, passive capture from live traffic records any healthy
// token the upstream mints for a real request at no extra quota; only the synthetic probe
// loop, which spends quota through a dedicated egress, additionally needs a proxy URL.
func (s *Service) startCodexTurnTicketHarvester(ctx context.Context) {
	if s == nil || s.coreManager == nil {
		return
	}
	s.cfgMu.RLock()
	cfg := s.cfg
	s.cfgMu.RUnlock()
	if cfg == nil {
		return
	}
	codexTurnTicketLifecycleMu.Lock()
	defer codexTurnTicketLifecycleMu.Unlock()
	process := helps.ConfigureCodexTurnTickets(cfg, s.codexTurnTicketAuths)
	if process == nil || process.Harvester == nil {
		return
	}
	process.Harvester.Start(ctx)
	effective := helps.EffectiveCodexTurnTicketConfig(cfg)
	if !effective.Enabled {
		log.Infof("codex turn tickets: disabled (turn-ticket.enabled is false)")
		return
	}
	if strings.TrimSpace(effective.HarvestProxyURL) == "" {
		log.Warnf("codex turn tickets: enabled but codex.turn-ticket.harvest-proxy-url is empty; synthetic probing stays off")
		return
	}
	log.Infof("codex turn tickets: harvester started (models=%v target_length=%d ttl_seconds=%d interval_seconds=%d)",
		effective.Models, effective.TargetLength, effective.TTLSeconds, effective.ProbeIntervalSeconds)
}

// stopCodexTurnTicketHarvester stops the probe loop and drops the process-wide wiring so
// an embedded SDK that re-runs the service does not keep injecting stale tickets.
func (s *Service) stopCodexTurnTicketHarvester() {
	codexTurnTicketLifecycleMu.Lock()
	defer codexTurnTicketLifecycleMu.Unlock()
	process := helps.CurrentCodexTurnTickets()
	if process == nil || process.Harvester == nil {
		return
	}
	process.Harvester.Stop()
}

// codexTurnTicketAuths snapshots the credentials eligible for harvesting. It reads the
// manager lazily on every harvest cycle so credentials added or removed at runtime are
// picked up without restarting the service.
func (s *Service) codexTurnTicketAuths() []*coreauth.Auth {
	if s == nil {
		return nil
	}
	manager := s.coreManager
	if manager == nil {
		return nil
	}
	return manager.List()
}

// CodexTurnTicketSummary reports the harvester's counters for diagnostics. It never
// exposes token material.
func CodexTurnTicketSummary() string {
	return helps.DescribeCodexTurnTickets()
}

// codexTurnTicketConfigEnabled reports whether the configuration asks for synthetic
// probing. Used by tests and by callers that want to log the effective state.
func codexTurnTicketConfigEnabled(cfg *config.Config) bool {
	return helps.EffectiveCodexTurnTicketConfig(cfg).Enabled
}
