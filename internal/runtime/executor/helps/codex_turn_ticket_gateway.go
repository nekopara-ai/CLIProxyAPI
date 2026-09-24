package helps

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps/codexmint"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

type codexMintTransportKey struct{}

// WithCodexMintTransport tags only acquisition/injection bookkeeping, never changes
// the executor's actual connection selection or business payload.
func WithCodexMintTransport(ctx context.Context, transport string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, codexMintTransportKey{}, transport)
}
func codexMintTransport(contexts ...context.Context) string {
	if len(contexts) > 0 && contexts[0] != nil {
		if t, _ := contexts[0].Value(codexMintTransportKey{}).(string); t == "websocket" {
			return t
		}
	}
	return "sse"
}
func codexGatewayConfig(auth *cliproxyauth.Auth, e CodexTurnTicketConfig) codexmint.Config {
	length := codexTurnTicketTargetLength(auth, e)
	if e.MintTicketLength != nil {
		length = *e.MintTicketLength
	}
	return codexmint.Config{Gateway: e.MintGateway, TicketLength: length,
		TicketTTL: time.Duration(e.MintTicketTTLSeconds) * time.Second, PairTTL: time.Duration(e.MintPairTTLSeconds) * time.Second,
		Margin: time.Duration(e.RoutingExpiryMarginSeconds) * time.Second, RefreshBefore: time.Duration(e.RoutingRefreshBeforeSeconds) * time.Second,
		AttemptTimeout: time.Duration(e.ProbeTimeoutSeconds) * time.Second, TotalTimeout: time.Duration(e.MintTotalTimeoutSeconds) * time.Second,
		FailureCooldown: time.Duration(e.MintRetryCooldownSeconds) * time.Second, RejectBackoff: time.Duration(e.RejectBackoffSeconds) * time.Second,
		MaxAttempts: e.MintMaxAttempts, Capacity: e.MintCacheCapacity}.Normalized()
}
func codexGatewayScope(auth *cliproxyauth.Auth, e CodexTurnTicketConfig, transport string) string {
	if auth == nil {
		return ""
	}
	account, _ := auth.Metadata["account_id"].(string)
	policy, _ := json.Marshal(struct {
		Policy       CodexTurnTicketPolicy
		Identity     any
		Models, Pool []string
		Target       int
	}{e.CodexTurnTicketPolicy, e.Identity, e.Models, e.HarvestProxyURLs, codexTurnTicketTargetLength(auth, e)})
	return codexmint.Scope(auth.ID, account, codexAuthAccessToken(auth), ResolveCodexTurnTicketPlan(auth, e.TargetLength, e).Plan, codexTurnTicketBaseURL(auth), codexBusinessEgress(auth, e), transport, string(policy))
}
func codexGatewayEnabled(e CodexTurnTicketConfig) bool { return e.AdaptiveInjection && e.GatewayMint }
func codexGatewayScoped(auth *cliproxyauth.Auth, model string, e CodexTurnTicketConfig) bool {
	return e.Enabled && codexGatewayEnabled(e) && isCodexTurnTicketProbeEligible(auth) && codexTurnTicketAuthScoped(e, auth.ID) && codexTurnTicketModelGated(e, model)
}
func (i *CodexTurnTicketInjector) applyGateway(auth *cliproxyauth.Auth, model string, headers http.Header, e CodexTurnTicketConfig, contexts ...context.Context) bool {
	if !codexGatewayScoped(auth, model, e) || !e.InjectionEnabled || !codexAdaptiveRequestEgressMatches(auth, e, contexts...) {
		return false
	}
	transport := codexMintTransport(contexts...)
	if !slices.Contains(e.MintTransports, transport) {
		return false
	}
	bundle, ok := i.store.mint.Get(codexGatewayScope(auth, e, transport), model, codexGatewayConfig(auth, e))
	if !ok {
		return false
	}
	codexmint.Inject(headers, bundle)
	return true
}

// CodexGatewayRequestAllowed closes the selection-to-I/O expiry/transport gap.
// It is checked after injection; it never starts a probe on the business path.
func CodexGatewayRequestAllowed(auth *cliproxyauth.Auth, model string, injected bool) bool {
	p := CurrentCodexTurnTickets()
	if p == nil || p.Harvester == nil || auth == nil {
		return true
	}
	e := codexTurnTicketEffectiveConfig(p.Harvester.cfgProvider)
	if !e.Enabled || !codexGatewayEnabled(e) || !isCodexOAuthCredential(auth) || !codexTurnTicketModelGated(e, model) || !codexTurnTicketAuthScoped(e, auth.ID) {
		return true
	}
	return !e.FailClosed || injected
}
func (s *CodexTurnTicketStore) gatewayAllows(auth *cliproxyauth.Auth, model string, e CodexTurnTicketConfig) bool {
	if !e.FailClosed {
		return true
	}
	if !e.InjectionEnabled || !isCodexTurnTicketProbeEligible(auth) {
		return false
	}
	for _, transport := range codexGatewayTransports(auth, e) {
		if _, ok := s.mint.Get(codexGatewayScope(auth, e, transport), model, codexGatewayConfig(auth, e)); ok {
			return true
		}
	}
	return false
}
func codexGatewayTransports(auth *cliproxyauth.Auth, e CodexTurnTicketConfig) []string {
	transports := []string{}
	if slices.Contains(e.MintTransports, "sse") {
		transports = append(transports, "sse")
	}
	enabled := false
	if auth != nil {
		if raw := strings.TrimSpace(auth.Attributes["websockets"]); raw != "" {
			enabled, _ = strconv.ParseBool(raw)
		} else {
			switch v := auth.Metadata["websockets"].(type) {
			case bool:
				enabled = v
			case string:
				enabled, _ = strconv.ParseBool(v)
			}
		}
	}
	if enabled && slices.Contains(e.MintTransports, "websocket") {
		transports = append(transports, "websocket")
	}
	return transports
}

// probeGatewayAll uses bounded workers; each account/transport is a single flight
// with one shared budget across all requested models and pair repairs.
func (h *CodexTurnTicketHarvester) probeGatewayAll(ctx context.Context, e CodexTurnTicketConfig) {
	if ctx == nil {
		ctx = context.Background()
	}
	jobs := make(chan *cliproxyauth.Auth)
	var workers sync.WaitGroup
	for n := 0; n < max(1, min(e.MintWorkers, 32)); n++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for auth := range jobs {
				h.probeGatewayAccount(ctx, auth, e)
			}
		}()
	}
	defer func() { close(jobs); workers.Wait() }()
	for _, auth := range h.listAuths() {
		if !isCodexTurnTicketProbeEligible(auth) || !codexTurnTicketAuthScoped(e, auth.ID) {
			continue
		}
		select {
		case jobs <- auth:
		case <-ctx.Done():
			return
		}
	}
}
func (h *CodexTurnTicketHarvester) gatewayCurrent(auth *cliproxyauth.Auth, e CodexTurnTicketConfig, transport, scope string) bool {
	current := codexTurnTicketEffectiveConfig(h.cfgProvider)
	if !current.Enabled || !codexGatewayEnabled(current) || !codexTurnTicketAuthScoped(current, auth.ID) {
		return false
	}
	if h.listAuths != nil {
		for _, a := range h.listAuths() {
			if a != nil && a.ID == auth.ID {
				return isCodexTurnTicketProbeEligible(a) && codexGatewayScope(a, current, transport) == scope
			}
		}
		return false
	}
	return codexGatewayScope(auth, current, transport) == scope
}
func (h *CodexTurnTicketHarvester) probeGatewayAccount(ctx context.Context, auth *cliproxyauth.Auth, e CodexTurnTicketConfig) {
	if ctx == nil {
		ctx = context.Background()
	}
	h.scheduleMu.Lock()
	for _, model := range e.Models {
		if time.Now().Before(h.backoffRun[codexTurnTicketKey(auth.ID, model)]) {
			h.scheduleMu.Unlock()
			return
		}
	}
	h.scheduleMu.Unlock()
	for _, transport := range codexGatewayTransports(auth, e) {
		scope := codexGatewayScope(auth, e, transport)
		cfg := codexGatewayConfig(auth, e)
		endpoint := strings.TrimSuffix(codexTurnTicketBaseURL(auth), "/") + "/responses"
		egresses := []string{codexBusinessEgress(auth, e)}
		for _, egress := range e.HarvestProxyURLs {
			if !slices.Contains(egresses, egress) {
				egresses = append(egresses, egress)
			}
		}
		index := 0
		probe := func(attemptCtx context.Context, req codexmint.Request) (codexmint.Attempt, error) {
			if !h.gatewayCurrent(auth, e, transport, scope) {
				return codexmint.Attempt{Terminal: true, Failure: "configuration_changed"}, errors.New("configuration_changed")
			}
			egress := egresses[index%len(egresses)]
			index++
			if req.Pair != nil {
				egress = req.Pair.Source
			}
			h.probed.Add(1)
			phase := "gateway_" + transport
			h.beginRoutingProbe(auth.ID, req.Model, phase, time.Now())
			result, err := probeCodexGateway(attemptCtx, auth, req, transport, egress, e)
			result.Source = egress
			if !h.gatewayCurrent(auth, e, transport, scope) {
				result.Terminal = true
				result.Failure = "configuration_changed"
				err = errors.New("configuration_changed")
			}
			observed := CodexTurnTicketObservation{ObservedAt: time.Now(), StatusCode: result.Status, StateLength: len(result.State), Result: "candidate_rejected"}
			if err == nil && result.Failure == "" && result.Model == req.Model {
				observed.Result = "created_received"
			}
			h.endRoutingProbe(auth.ID, req.Model, phase, codexRoutingProbe{Model: result.Model, Status: result.Status}, observed)
			gateway := ""
			if pair, changed := codexmint.ReadPair(result.Header, endpoint, time.Now(), cfg); changed {
				gateway = pair.Gateway
			} else if req.Pair != nil {
				gateway = req.Pair.Gateway
			}
			log.WithFields(log.Fields{"auth_hint": codexTurnTicketAuthHint(auth), "model": req.Model, "transport": transport, "gateway": gateway, "status": result.Status, "ticket_length": len(result.State), "model_match": result.Model == req.Model, "result": observed.Result}).Info("codex mint: probe")
			return result, err
		}
		err := h.store.mint.Refresh(ctx, scope, e.Models, endpoint, cfg, probe)
		for _, model := range e.Models {
			snap := h.store.mint.Snapshot(scope, model, cfg)
			h.recordObservation(auth.ID, model, CodexTurnTicketObservation{ObservedAt: time.Now(), StatusCode: snap.Status, StateLength: snap.TicketLength, Healthy: snap.Ready, Result: snap.Reason})
			// Rejection backoff is credential-wide, including the other transport.
			if snap.Status == 401 || snap.Status == 403 || snap.Status == 429 {
				if index > 0 {
					for _, otherTransport := range codexGatewayTransports(auth, e) {
						h.store.mint.Park(codexGatewayScope(auth, e, otherTransport), snap.NextAttemptAt)
					}
					for _, keyModel := range e.Models {
						h.parkBucket(auth.ID, keyModel, snap.NextAttemptAt)
					}
				}
				return
			}
		}
		if err == nil && index > 0 {
			h.harvested.Add(1)
		}
		if ctx.Err() != nil {
			return
		}
	}
}

func (h *CodexTurnTicketHarvester) observeGateway(auth *cliproxyauth.Auth, model string, status int, response, request http.Header, injected bool, e CodexTurnTicketConfig, contexts ...context.Context) {
	if !codexGatewayScoped(auth, model, e) || !codexAdaptiveRequestEgressMatches(auth, e, contexts...) {
		return
	}
	// Header-only success is not evidence of the declared model. Never publish it
	// and never switch the bucket into a bypass/direct state.
	if !injected {
		return
	}
	var cflb, oailb string
	for _, cookie := range codexRequestCookies(request) {
		if cookie.Name == "__cflb" {
			cflb = cookie.Value
		}
		if cookie.Name == "__oailb" {
			oailb = cookie.Value
		}
	}
	cfg := codexGatewayConfig(auth, e)
	scope := codexGatewayScope(auth, e, codexMintTransport(contexts...))
	pair, changed := codexmint.ReadPair(response, strings.TrimSuffix(codexTurnTicketBaseURL(auth), "/")+"/responses", time.Now(), cfg)
	sentCookie := "__cflb=" + cflb + "; __oailb=" + oailb
	badPair := changed && (pair.CFLB == "" || pair.Cookie() != sentCookie)
	state := ExtractCodexTurnState(response)
	badTicket := status == 401 || status == 403 || (state != "" && cfg.TicketLength > 0 && len(state) != cfg.TicketLength)
	if badPair || badTicket {
		if h.store.mint.RejectParts(scope, model, ExtractCodexTurnState(request), sentCookie, badPair || status == 401 || status == 403, badTicket) {
			h.wakeAdaptive(auth.ID, model)
		}
	}
}
func (h *CodexTurnTicketHarvester) gatewaySnapshots(auth *cliproxyauth.Auth, model string, e CodexTurnTicketConfig) map[string]codexmint.Snapshot {
	out := map[string]codexmint.Snapshot{}
	for _, transport := range codexGatewayTransports(auth, e) {
		out[transport] = h.store.mint.Snapshot(codexGatewayScope(auth, e, transport), model, codexGatewayConfig(auth, e))
	}
	return out
}
