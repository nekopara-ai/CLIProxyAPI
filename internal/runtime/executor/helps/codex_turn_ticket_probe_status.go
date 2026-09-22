package helps

import (
	"net/http"
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// CodexTurnTicketProbeSnapshot separates actual probe activity from ticket readiness.
// NextProbeAt is the earliest eligible time; the serialized worker may run it later.
// These fields never contain credential, ticket, cookie, or proxy material.
type CodexTurnTicketProbeSnapshot struct {
	ProbeInFlight       bool      `json:"probe_in_flight"`
	ProbePhase          string    `json:"probe_phase,omitempty"`
	ProbeStartedAt      time.Time `json:"probe_started_at,omitempty"`
	ProbeAttempts       int64     `json:"probe_attempts"`
	LastProbeAt         time.Time `json:"last_probe_at,omitempty"`
	LastProbePhase      string    `json:"last_probe_phase,omitempty"`
	LastProbeResult     string    `json:"last_probe_result,omitempty"`
	LastProbeComplete   bool      `json:"last_probe_complete"`
	LastProbeMatches    bool      `json:"last_probe_model_match"`
	NextProbeAt         time.Time `json:"next_probe_at,omitempty"`
	ProbeBackoffUntil   time.Time `json:"probe_backoff_until,omitempty"`
	HarvestBackoffUntil time.Time `json:"harvest_backoff_until,omitempty"`
}

type codexTurnTicketProbeProgress struct {
	CodexTurnTicketProbeSnapshot
}

func (h *CodexTurnTicketHarvester) bringRoutingProbeForward(auth *cliproxyauth.Auth, model string, effective CodexTurnTicketConfig, route codexTurnTicketRoute, until time.Time) {
	h.store.mu.RLock()
	defer h.store.mu.RUnlock()
	key := codexTurnTicketKey(auth.ID, model)
	if h.store.routeLocked(key, codexRoutingContext(auth, effective)) != route {
		return
	}
	h.scheduleMu.Lock()
	defer h.scheduleMu.Unlock()
	if h.nextProbe[key].After(until) {
		h.nextProbe[key] = until
	}
}

func (h *CodexTurnTicketHarvester) beginRoutingProbe(authID, model, phase string, started time.Time) {
	h.observationMu.Lock()
	defer h.observationMu.Unlock()
	if h.probeProgress == nil {
		h.probeProgress = make(map[string]codexTurnTicketProbeProgress)
	}
	key := codexTurnTicketKey(authID, model)
	progress := h.probeProgress[key]
	progress.ProbeInFlight, progress.ProbePhase, progress.ProbeStartedAt = true, phase, started
	progress.ProbeAttempts++
	h.probeProgress[key] = progress
}

func (h *CodexTurnTicketHarvester) endRoutingProbe(authID, model, phase string, result codexRoutingProbe, observation CodexTurnTicketObservation) {
	h.observationMu.Lock()
	key := codexTurnTicketKey(authID, model)
	progress := h.probeProgress[key]
	progress.ProbeInFlight, progress.ProbePhase = false, ""
	progress.LastProbeAt, progress.LastProbePhase = observation.ObservedAt, phase
	progress.LastProbeResult = observation.Result
	progress.LastProbeComplete, progress.LastProbeMatches = result.Complete, result.Model == model
	h.probeProgress[key] = progress
	h.observationMu.Unlock()
	// Misses and rejected candidates are observations too. Previously the adaptive
	// path recorded only activation, leaving the UI blank during continuous probing.
	h.recordObservation(authID, model, observation)
}

func (h *CodexTurnTicketHarvester) probeSnapshot(authID, model string) CodexTurnTicketProbeSnapshot {
	key := codexTurnTicketKey(authID, model)
	h.observationMu.RLock()
	snapshot := h.probeProgress[key].CodexTurnTicketProbeSnapshot
	h.observationMu.RUnlock()
	h.scheduleMu.Lock()
	snapshot.NextProbeAt = h.nextProbe[key]
	snapshot.ProbeBackoffUntil = h.backoffRun[key]
	if snapshot.ProbeBackoffUntil.After(snapshot.NextProbeAt) {
		snapshot.NextProbeAt = snapshot.ProbeBackoffUntil
	}
	h.scheduleMu.Unlock()
	_, snapshot.HarvestBackoffUntil = h.routingHarvestCandidates(authID, model, codexTurnTicketEffectiveConfig(h.cfgProvider), time.Now())
	return snapshot
}

func routingProbeObservation(auth *cliproxyauth.Auth, model, phase string, result codexRoutingProbe, ticket *CodexTurnTicket, effective CodexTurnTicketConfig, err error) CodexTurnTicketObservation {
	state := ExtractCodexTurnState(result.Header)
	observation := CodexTurnTicketObservation{ObservedAt: time.Now(), StatusCode: result.Status, StateLength: len(state)}
	switch {
	case err != nil:
		observation.Result = codexTurnTicketProbeErrorClass(err)
	case phase == "harvest" && result.Status == http.StatusForbidden:
		observation.Result = "harvest_egress_rejected"
	case result.Status == http.StatusUnauthorized || result.Status == http.StatusForbidden || result.Status == http.StatusTooManyRequests:
		observation.Result = "rejected"
	case result.Status != http.StatusOK:
		observation.Result = "http_error"
	case IsHealthyCodexTurnState(state, codexTurnTicketDegradedLength(codexTurnTicketTargetLength(auth, effective))):
		observation.Result = "degraded"
	case !result.Complete:
		observation.Result = "incomplete_response"
	case result.Model != model:
		observation.Result = "model_mismatch"
	case phase == "business_validation":
		observation.Result = "validation_passed"
		if ticket == nil || (state != "" && state != ticket.State) {
			observation.Result = "validation_ticket_changed"
		}
	case !IsHealthyCodexTurnState(state, codexTurnTicketTargetLength(auth, effective)):
		observation.Result = "missing_healthy_state"
	case phase == "harvest":
		observation.Result = "candidate"
		if len(codexRoutingCookies(result.Header, result.ObservedAt, effective)) == 0 {
			observation.Result = "missing_routing_cookie"
		}
	default:
		observation.Result = "business_direct"
		observation.Healthy = true
	}
	return observation
}
