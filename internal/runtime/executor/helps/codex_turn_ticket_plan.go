package helps

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// CodexTurnTicketPlanField is an explicit routing policy, not an authentication
// grant. It also supports imported opaque access tokens without ID/refresh tokens.
const CodexTurnTicketPlanField = "codex_turn_ticket_plan"

type CodexTurnTicketPlan struct {
	Plan         string `json:"plan"`
	Source       string `json:"plan_source"`
	TargetLength int    `json:"target_length"`
}

// ResolveCodexTurnTicketPlan never infers a subscription from a filename or state
// length. JWT claims are routing hints only and must refer to the selected workspace.
func ResolveCodexTurnTicketPlan(auth *cliproxyauth.Auth, fallback int) CodexTurnTicketPlan {
	p := CodexTurnTicketPlan{Plan: "default", Source: "config", TargetLength: fallback}
	if auth == nil || auth.Metadata == nil {
		return p
	}
	if value, present := auth.Metadata[CodexTurnTicketPlanField]; present && value != nil {
		raw, ok := value.(string)
		mode := strings.ToLower(strings.TrimSpace(raw))
		if !ok || (mode != "" && mode != "auto" && mode != "pro" && mode != "team") {
			return CodexTurnTicketPlan{Plan: "invalid", Source: "manual", TargetLength: 1}
		}
		if mode == "pro" {
			return CodexTurnTicketPlan{Plan: "pro", Source: "manual", TargetLength: 292}
		}
		if mode == "team" {
			return CodexTurnTicketPlan{Plan: "team", Source: "manual", TargetLength: 332}
		}
	}
	account, _ := auth.Metadata["account_id"].(string)
	for _, field := range []string{"id_token", "access_token"} {
		raw, _ := auth.Metadata[field].(string)
		parts := strings.Split(strings.TrimSpace(raw), ".")
		if len(parts) != 3 || len(parts[1]) > 65536 {
			continue
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			continue
		}
		var claims struct {
			Auth struct {
				Plan    string `json:"chatgpt_plan_type"`
				Account string `json:"chatgpt_account_id"`
			} `json:"https://api.openai.com/auth"`
		}
		if json.Unmarshal(payload, &claims) != nil || strings.TrimSpace(account) == "" || strings.TrimSpace(account) != claims.Auth.Account {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(claims.Auth.Plan)) {
		case "team", "business":
			return CodexTurnTicketPlan{Plan: "team", Source: field, TargetLength: 332}
		case "free", "plus", "pro":
			return CodexTurnTicketPlan{Plan: "pro", Source: field, TargetLength: 292}
		}
	}
	return p
}

func codexTurnTicketTargetLength(auth *cliproxyauth.Auth, effective CodexTurnTicketConfig) int {
	return ResolveCodexTurnTicketPlan(auth, effective.TargetLength).TargetLength
}

func codexTurnTicketDegradedLength(target int) int {
	if target == 332 {
		return 356
	}
	return 312
}

// InvalidateCodexTurnTicketsForAuth runs after a persisted manual policy change.
// The probe mutex ensures an older in-flight harvest cannot republish its ticket.
func InvalidateCodexTurnTicketsForAuth(authID string) {
	p := CurrentCodexTurnTickets()
	if p == nil || p.Store == nil || p.Harvester == nil {
		return
	}
	h := p.Harvester
	h.probeInFlight.Lock()
	defer h.probeInFlight.Unlock()
	p.Store.mu.Lock()
	for key := range p.Store.tickets {
		id, _, ok := splitCodexTurnTicketKey(key)
		if ok && id == authID {
			delete(p.Store.tickets, key)
		}
	}
	for key := range p.Store.routes {
		id, _, ok := splitCodexTurnTicketKey(key)
		if ok && id == authID {
			delete(p.Store.routes, key)
		}
	}
	if err := p.Store.persistLocked(); err != nil {
		log.Errorf("codex turn tickets: persist auth invalidation: %v", err)
	}
	p.Store.mu.Unlock()
	h.scheduleMu.Lock()
	for key := range h.nextProbe {
		id, _, ok := splitCodexTurnTicketKey(key)
		if ok && id == authID {
			delete(h.nextProbe, key)
		}
	}
	h.scheduleMu.Unlock()
	// Preserve 401/403/429 backoff: changing plan does not reset upstream limits.
	h.observationMu.Lock()
	for key := range h.observations {
		id, _, ok := splitCodexTurnTicketKey(key)
		if ok && id == authID {
			delete(h.observations, key)
		}
	}
	h.observationMu.Unlock()
}

// Count cached buckets using their current account policy, including disabled
// accounts. Cache occupancy does not imply that an account is schedulable.
func (h *CodexTurnTicketHarvester) policyHealthyCount(effective CodexTurnTicketConfig) int {
	if effective.AdaptiveInjection {
		count := 0
		now := time.Now()
		if h.listAuths == nil {
			return count
		}
		for _, auth := range h.listAuths() {
			if auth == nil {
				continue
			}
			for _, model := range effective.Models {
				if h.store.adaptiveAllows(auth, model, effective, now) {
					count++
				}
			}
		}
		return count
	}
	lengths := make(map[string]int)
	if h.listAuths != nil {
		for _, a := range h.listAuths() {
			if a != nil {
				lengths[a.ID] = codexTurnTicketTargetLength(a, effective)
			}
		}
	}
	h.store.mu.RLock()
	defer h.store.mu.RUnlock()
	count := 0
	now := time.Now()
	for key, ticket := range h.store.tickets {
		id, _, _ := splitCodexTurnTicketKey(key)
		if length, ok := lengths[id]; ok {
			if ticket.valid(now, length) {
				count++
			}
		} else if ticket.valid(now, effective.TargetLength) || ticket.valid(now, 332) {
			count++
		}
	}
	return count
}
