package config

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

var mintRejectedGatewayPattern = regexp.MustCompile(`(?i)^(?:[0-9]+|unified[-_.]?[0-9]+|gateway[-_.][a-z0-9-]+)$`)

// Validate rejects ambiguous policy and misspelled actions before a hot reload.
func (c CodexTurnTicketSettings) Validate() error {
	if c.MintTicketLength != nil && (*c.MintTicketLength < 0 || *c.MintTicketLength > 16384) {
		return fmt.Errorf("codex.turn-ticket.mint-ticket-length must be between 0 and 16384")
	}
	for name, value := range map[string]int{"personal-healthy-length": c.PersonalHealthyLength, "personal-degraded-length": c.PersonalDegradedLength, "team-healthy-length": c.TeamHealthyLength, "team-degraded-length": c.TeamDegradedLength, "target-length": c.TargetLength} {
		if value < 0 || (value > 0 && value < 10) {
			return fmt.Errorf("codex.turn-ticket.%s must be zero (default) or at least 10", name)
		}
	}
	for _, pair := range []struct {
		name              string
		healthy, degraded int
	}{{"personal", c.PersonalHealthyLength, c.PersonalDegradedLength}, {"team", c.TeamHealthyLength, c.TeamDegradedLength}} {
		healthy, degraded := pair.healthy, pair.degraded
		if healthy == 0 {
			healthy = 780
		}
		if degraded == 0 {
			degraded = 312
		}
		if healthy == degraded {
			return fmt.Errorf("codex.turn-ticket: %s healthy and degraded lengths must differ", pair.name)
		}
	}
	fallback := c.TargetLength
	if fallback == 0 {
		fallback = 780
	}
	degraded := c.PersonalDegradedLength
	if degraded == 0 {
		degraded = 312
	}
	if fallback == degraded {
		return fmt.Errorf("codex.turn-ticket.target-length must differ from personal-degraded-length")
	}
	switch c.UnknownStateAction {
	case "", "retain", "harvest", "block":
	default:
		return fmt.Errorf("codex.turn-ticket.unknown-state-action must be retain, harvest, or block")
	}
	switch c.ValidationTicketPolicy {
	case "", "same-or-empty", "healthy-or-empty":
	default:
		return fmt.Errorf("codex.turn-ticket.validation-ticket-policy must be same-or-empty or healthy-or-empty")
	}
	for name, value := range map[string]*int{"routing-expiry-margin-seconds": c.RoutingExpiryMarginSeconds, "legacy-expiry-margin-seconds": c.LegacyExpiryMarginSeconds} {
		if value != nil && (*value < 0 || int64(*value) > int64(1<<63-1)/1_000_000_000) {
			return fmt.Errorf("codex.turn-ticket.%s must be a nonnegative duration in seconds", name)
		}
	}
	for _, codes := range [][]int{c.RejectStatusCodes, c.HarvestRejectStatusCodes} {
		for _, code := range codes {
			if code < 400 || code > 599 {
				return fmt.Errorf("codex.turn-ticket rejection status codes must be between 400 and 599")
			}
		}
	}
	for _, name := range c.RoutingCookieNames {
		if name == "" || name != strings.TrimSpace(name) || (&http.Cookie{Name: name, Value: "test"}).Valid() != nil {
			return fmt.Errorf("codex.turn-ticket.routing-cookie-names contains an invalid cookie name")
		}
	}

	for name, limit := range map[string][2]int{
		"mint-ticket-ttl-seconds": {c.MintTicketTTLSeconds, 1200}, "mint-pair-ttl-seconds": {c.MintPairTTLSeconds, 86400},
		"mint-max-attempts": {c.MintMaxAttempts, 128}, "mint-total-timeout-seconds": {c.MintTotalTimeoutSeconds, 180},
		"mint-retry-cooldown-seconds": {c.MintRetryCooldownSeconds, 3600}, "mint-cache-capacity": {c.MintCacheCapacity, 65536}, "mint-workers": {c.MintWorkers, 32},
	} {
		if limit[0] < 0 || limit[0] > limit[1] {
			return fmt.Errorf("codex.turn-ticket.%s is outside the supported range", name)
		}
	}
	for _, transport := range c.MintTransports {
		if transport != "sse" && transport != "websocket" {
			return fmt.Errorf("codex.turn-ticket.mint-transports must contain sse or websocket")
		}
	}
	if c.MintTransports != nil && len(c.MintTransports) == 0 {
		return fmt.Errorf("codex.turn-ticket.mint-transports must not be empty")
	}
	if strings.ContainsAny(c.MintGateway, "\r\n\x00") || len(c.MintGateway) > 96 {
		return fmt.Errorf("codex.turn-ticket.mint-gateway is invalid")
	}
	for _, gateway := range c.MintRejectGateways {
		if len(gateway) > 96 || !mintRejectedGatewayPattern.MatchString(gateway) {
			return fmt.Errorf("codex.turn-ticket.mint-reject-gateways contains an invalid gateway")
		}
	}
	return nil
}
