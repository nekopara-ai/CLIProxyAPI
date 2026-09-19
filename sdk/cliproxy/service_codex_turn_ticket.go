package cliproxy

import (
	"context"
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
// loop, which spends quota through a dedicated egress, additionally needs one or more
// explicit proxy URLs and/or the "direct" setting.
//
// The harvester is always started when the wiring is installed. Its loop re-reads the live
// config every cycle, so an operator can enable the feature through a config reload and the
// first probe follows without a restart.
func (s *Service) startCodexTurnTicketHarvester(ctx context.Context) {
	if s == nil || s.coreManager == nil {
		return
	}
	if s.currentConfig() == nil {
		return
	}
	codexTurnTicketLifecycleMu.Lock()
	defer codexTurnTicketLifecycleMu.Unlock()
	process := helps.ConfigureCodexTurnTickets(s.currentConfig, s.codexTurnTicketAuths)
	if process == nil || process.Harvester == nil {
		return
	}
	s.coreManager.SetExecutionModelGuard(helps.CodexTurnTicketAllowsExecution)
	process.Harvester.Start(ctx)
	effective := helps.EffectiveCodexTurnTicketConfig(s.currentConfig())
	if !effective.Enabled {
		log.Infof("codex turn tickets: disabled (turn-ticket.enabled is false); hot reload will enable it in place")
		return
	}
	if len(effective.HarvestProxyURLs) == 0 {
		log.Warnf("codex turn tickets: enabled but codex.turn-ticket.harvest-proxy-urls is empty; synthetic probing stays off")
		return
	}
	snapshot := helps.SnapshotCodexTurnTickets()
	log.Infof("codex turn tickets: harvester started (models=%v harvest_egresses=%d target_length=%d ttl_seconds=%d interval_seconds=%d fail_closed=%t persistent=%t restored=%d)",
		effective.Models, len(effective.HarvestProxyURLs), effective.TargetLength, effective.TTLSeconds, effective.ProbeIntervalSeconds, effective.FailClosed, snapshot.PersistentStore, snapshot.RestoredTickets)
}

// currentConfig returns the live configuration pointer under the config lock. Every
// consumer that must observe hot reloads goes through this instead of capturing s.cfg once.
func (s *Service) currentConfig() *config.Config {
	if s == nil {
		return nil
	}
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.cfg
}

// stopCodexTurnTicketHarvester stops the probe loop and drops the process-wide wiring so
// an embedded SDK that re-runs the service does not keep injecting stale tickets.
func (s *Service) stopCodexTurnTicketHarvester() {
	codexTurnTicketLifecycleMu.Lock()
	defer codexTurnTicketLifecycleMu.Unlock()
	if s != nil && s.coreManager != nil {
		s.coreManager.SetExecutionModelGuard(nil)
	}
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

// CodexTurnTicketSnapshot reports the full redacted turn-ticket state for the management
// API. It never exposes token material, credential identifiers, or proxy credentials.
func CodexTurnTicketSnapshot() helps.CodexTurnTicketSnapshot {
	return helps.SnapshotCodexTurnTickets()
}

// codexTurnTicketConfigEnabled reports whether the configuration asks for synthetic
// probing. Used by tests and by callers that want to log the effective state.
func codexTurnTicketConfigEnabled(cfg *config.Config) bool {
	return helps.EffectiveCodexTurnTicketConfig(cfg).Enabled
}
