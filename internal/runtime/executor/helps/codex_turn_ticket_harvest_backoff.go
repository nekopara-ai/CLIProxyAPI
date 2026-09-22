package helps

import "time"

func (h *CodexTurnTicketHarvester) parkRoutingHarvestEgress(authID, model, egress string, now time.Time) {
	h.scheduleMu.Lock()
	defer h.scheduleMu.Unlock()
	if h.harvestRejectedAt == nil {
		h.harvestRejectedAt = make(map[string]map[string]time.Time)
	}
	key := codexTurnTicketKey(authID, model)
	if h.harvestRejectedAt[key] == nil {
		h.harvestRejectedAt[key] = make(map[string]time.Time)
	}
	h.harvestRejectedAt[key][egress] = now
}

// Acquisition backoff never contributes to NextProbeAt: clean business probes
// must keep classifying the route even when every acquisition egress is blocked.
func (h *CodexTurnTicketHarvester) routingHarvestCandidates(authID, model string, effective CodexTurnTicketConfig, now time.Time) ([]string, time.Time) {
	h.scheduleMu.Lock()
	defer h.scheduleMu.Unlock()
	rejected := h.harvestRejectedAt[codexTurnTicketKey(authID, model)]
	var candidates []string
	var earliest time.Time
	for _, egress := range effective.HarvestProxyURLs {
		if at, ok := rejected[egress]; ok {
			until := at.Add(time.Duration(effective.HarvestRejectBackoffSeconds) * time.Second)
			if now.Before(until) {
				if earliest.IsZero() || until.Before(earliest) {
					earliest = until
				}
				continue
			}
			delete(rejected, egress)
		}
		candidates = append(candidates, egress)
	}
	if len(candidates) != 0 {
		earliest = time.Time{}
	}
	return candidates, earliest
}
