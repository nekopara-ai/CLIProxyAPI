package helps

import (
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"net/http"
	"slices"
	"strings"
)

// CodexTurnTicketPolicy is the effective, credential-safe policy exposed in diagnostics.
type CodexTurnTicketPolicy struct {
	MintTicketLength         *int     `json:"mint-ticket-length,omitempty"`
	GatewayMint              bool     `json:"gateway-mint"`
	MintGateway              string   `json:"mint-gateway"`
	MintRejectGateways       []string `json:"mint-reject-gateways,omitempty"`
	MintTicketTTLSeconds     int      `json:"mint-ticket-ttl-seconds"`
	MintPairTTLSeconds       int      `json:"mint-pair-ttl-seconds"`
	MintMaxAttempts          int      `json:"mint-max-attempts"`
	MintTotalTimeoutSeconds  int      `json:"mint-total-timeout-seconds"`
	MintRetryCooldownSeconds int      `json:"mint-retry-cooldown-seconds"`
	MintCacheCapacity        int      `json:"mint-cache-capacity"`
	MintWorkers              int      `json:"mint-workers"`
	MintTransports           []string `json:"mint-transports"`

	PersonalHealthyLength      int      `json:"personal-healthy-length"`
	PersonalDegradedLength     int      `json:"personal-degraded-length"`
	TeamHealthyLength          int      `json:"team-healthy-length"`
	TeamDegradedLength         int      `json:"team-degraded-length"`
	BlockOnDegraded            bool     `json:"block-on-degraded"`
	UnknownStateAction         string   `json:"unknown-state-action"`
	HarvestOnBusinessError     bool     `json:"harvest-on-business-error"`
	ValidationTicketPolicy     string   `json:"validation-ticket-policy"`
	RequireCompleteResponse    bool     `json:"require-complete-response"`
	RequireModelMatch          bool     `json:"require-model-match"`
	RoutingExpiryMarginSeconds int      `json:"routing-expiry-margin-seconds"`
	LegacyExpiryMarginSeconds  int      `json:"legacy-expiry-margin-seconds"`
	RoutingCookieNames         []string `json:"routing-cookie-names"`
	RejectStatusCodes          []int    `json:"reject-status-codes"`
	HarvestRejectStatusCodes   []int    `json:"harvest-reject-status-codes"`
}

func effectiveCodexTurnTicketPolicy(raw config.CodexTurnTicketPolicySettings, failClosed bool) CodexTurnTicketPolicy {
	p := CodexTurnTicketPolicy{PersonalHealthyLength: 780, PersonalDegradedLength: 312, TeamHealthyLength: 780, TeamDegradedLength: 312,
		BlockOnDegraded: failClosed, UnknownStateAction: "retain", ValidationTicketPolicy: "same-or-empty", RequireCompleteResponse: true, RequireModelMatch: true,
		RoutingExpiryMarginSeconds: 5, LegacyExpiryMarginSeconds: 30, RoutingCookieNames: []string{"__cflb", "__oailb"}, RejectStatusCodes: []int{401, 403, 429}, HarvestRejectStatusCodes: []int{403}}
	if raw.PersonalHealthyLength > 0 {
		p.PersonalHealthyLength = raw.PersonalHealthyLength
	}
	if raw.PersonalDegradedLength > 0 {
		p.PersonalDegradedLength = raw.PersonalDegradedLength
	}
	if raw.TeamHealthyLength > 0 {
		p.TeamHealthyLength = raw.TeamHealthyLength
	}
	if raw.TeamDegradedLength > 0 {
		p.TeamDegradedLength = raw.TeamDegradedLength
	}
	if raw.BlockOnDegraded != nil {
		p.BlockOnDegraded = *raw.BlockOnDegraded
	}
	switch raw.UnknownStateAction {
	case "retain", "harvest", "block":
		p.UnknownStateAction = raw.UnknownStateAction
	}
	p.HarvestOnBusinessError = raw.HarvestOnBusinessError
	if raw.ValidationTicketPolicy == "healthy-or-empty" {
		p.ValidationTicketPolicy = raw.ValidationTicketPolicy
	}
	if raw.RequireCompleteResponse != nil {
		p.RequireCompleteResponse = *raw.RequireCompleteResponse
	}
	if raw.RequireModelMatch != nil {
		p.RequireModelMatch = *raw.RequireModelMatch
	}
	if raw.RoutingExpiryMarginSeconds != nil && *raw.RoutingExpiryMarginSeconds >= 0 {
		p.RoutingExpiryMarginSeconds = *raw.RoutingExpiryMarginSeconds
	}
	if raw.LegacyExpiryMarginSeconds != nil && *raw.LegacyExpiryMarginSeconds >= 0 {
		p.LegacyExpiryMarginSeconds = *raw.LegacyExpiryMarginSeconds
	}
	if raw.RoutingCookieNames != nil {
		p.RoutingCookieNames = []string{}
		for _, name := range raw.RoutingCookieNames {
			name = strings.TrimSpace(name)
			if name != "" && (&http.Cookie{Name: name, Value: "test"}).Valid() == nil && !slices.Contains(p.RoutingCookieNames, name) {
				p.RoutingCookieNames = append(p.RoutingCookieNames, name)
			}
		}
	}
	if raw.RejectStatusCodes != nil {
		p.RejectStatusCodes = validCodexRejectCodes(raw.RejectStatusCodes)
	}
	if raw.HarvestRejectStatusCodes != nil {
		p.HarvestRejectStatusCodes = validCodexRejectCodes(raw.HarvestRejectStatusCodes)
	}

	if raw.MintTicketLength != nil {
		v := *raw.MintTicketLength
		p.MintTicketLength = &v
	}
	p.GatewayMint = true
	if raw.GatewayMint != nil {
		p.GatewayMint = *raw.GatewayMint
	}
	p.MintGateway = "unified-88"
	if raw.MintGateway != "" {
		p.MintGateway = raw.MintGateway
	}
	p.MintRejectGateways = append([]string(nil), raw.MintRejectGateways...)
	p.MintTicketTTLSeconds = 240
	if raw.MintTicketTTLSeconds > 0 {
		p.MintTicketTTLSeconds = raw.MintTicketTTLSeconds
	}
	p.MintPairTTLSeconds = 3900
	if raw.MintPairTTLSeconds > 0 {
		p.MintPairTTLSeconds = raw.MintPairTTLSeconds
	}
	p.MintMaxAttempts = 24
	if raw.MintMaxAttempts > 0 {
		p.MintMaxAttempts = raw.MintMaxAttempts
	}
	p.MintTotalTimeoutSeconds = 75
	if raw.MintTotalTimeoutSeconds > 0 {
		p.MintTotalTimeoutSeconds = raw.MintTotalTimeoutSeconds
	}
	p.MintRetryCooldownSeconds = 30
	if raw.MintRetryCooldownSeconds > 0 {
		p.MintRetryCooldownSeconds = raw.MintRetryCooldownSeconds
	}
	p.MintCacheCapacity = 256
	if raw.MintCacheCapacity > 0 {
		p.MintCacheCapacity = raw.MintCacheCapacity
	}
	p.MintWorkers = 4
	if raw.MintWorkers > 0 {
		p.MintWorkers = raw.MintWorkers
	}
	p.MintTransports = []string{"sse", "websocket"}
	if raw.MintTransports != nil {
		p.MintTransports = append([]string(nil), raw.MintTransports...)
	}
	return p
}

func validCodexRejectCodes(values []int) []int {
	out := []int{}
	for _, code := range values {
		if code >= 400 && code <= 599 && !slices.Contains(out, code) {
			out = append(out, code)
		}
	}
	return out
}

func codexRoutingResponseAcceptable(result codexRoutingProbe, model string, effective CodexTurnTicketConfig) bool {
	return (!effective.RequireCompleteResponse || result.Complete) && (!effective.RequireModelMatch || result.Model == model)
}

func codexValidationStateAcceptable(state string, ticket *CodexTurnTicket, target int, effective CodexTurnTicketConfig) bool {
	if ticket == nil {
		return false
	}
	return state == "" || state == ticket.State || (effective.ValidationTicketPolicy == "healthy-or-empty" && IsHealthyCodexTurnState(state, target))
}
