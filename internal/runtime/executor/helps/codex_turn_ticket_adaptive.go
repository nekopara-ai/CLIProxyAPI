package helps

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	log "github.com/sirupsen/logrus"
)

// CodexRoutingCookie contains only an upstream routing cookie, never login cookies.
// Values share the ticket store's private 0600 persistence boundary.
type CodexRoutingCookie struct {
	Name      string    `json:"name"`
	Value     string    `json:"value"`
	ExpiresAt time.Time `json:"expires_at"`
}

const (
	codexRouteUnknown = "unknown"
	codexRouteBlocked = "blocked"
	codexRouteDirect  = "direct"
	codexRouteInject  = "inject"
)

type codexTurnTicketRoute struct {
	Mode       string
	Context    string
	Generation uint64
}

// Bind the route to account/workspace/policy/business egress. Token refresh alone
// does not change identity, while a new workspace or egress requires reclassification.
func codexRoutingContext(auth *cliproxyauth.Auth, effective CodexTurnTicketConfig) string {
	if auth == nil {
		return ""
	}
	account, _ := auth.Metadata["account_id"].(string)
	source := auth.ID + "\x00" + account + "\x00" + codexTurnTicketBaseURL(auth) + "\x00" + codexBusinessEgress(auth, effective) + fmt.Sprintf("\x00%d\x00%s", codexTurnTicketTargetLength(auth, effective), codexRoutingPolicyContext(auth, effective))
	sum := sha256.Sum256([]byte(source))
	return hex.EncodeToString(sum[:])
}

func codexBusinessEgress(auth *cliproxyauth.Auth, effective CodexTurnTicketConfig) string {
	if auth != nil && strings.TrimSpace(auth.ProxyURL) != "" {
		return strings.TrimSpace(auth.ProxyURL)
	}
	return effective.BusinessProxyURL
}

func (s *CodexTurnTicketStore) route(auth *cliproxyauth.Auth, model string, effective CodexTurnTicketConfig) codexTurnTicketRoute {
	contextID := codexRoutingContext(auth, effective)
	s.mu.RLock()
	route := s.routeLocked(codexTurnTicketKey(auth.ID, model), contextID)
	s.mu.RUnlock()
	return route
}

// routeLocked normalizes absent or context-stale state without mutating the store.
// s.mu must be held by the caller.
func (s *CodexTurnTicketStore) routeLocked(key, contextID string) codexTurnTicketRoute {
	route := s.routes[key]
	if route.Context != contextID || route.Mode == "" {
		return codexTurnTicketRoute{Mode: codexRouteUnknown, Context: contextID, Generation: route.Generation}
	}
	return route
}

// setRoute invalidates older in-flight probe results. Routing modes are deliberately
// not restored after restart: an old disk ticket must never enable injection by itself.
func (s *CodexTurnTicketStore) setRoute(auth *cliproxyauth.Auth, model string, effective CodexTurnTicketConfig, mode string, discard bool) codexTurnTicketRoute {
	route, _ := s.setRouteIf(auth, model, effective, nil, mode, discard)
	return route
}

// setRouteIf applies a route transition only when the normalized current route still
// matches expected. This keeps a slow probe from overwriting a newer live observation.
func (s *CodexTurnTicketStore) setRouteIf(auth *cliproxyauth.Auth, model string, effective CodexTurnTicketConfig, expected *codexTurnTicketRoute, mode string, discard bool) (codexTurnTicketRoute, bool) {
	key := codexTurnTicketKey(auth.ID, model)
	contextID := codexRoutingContext(auth, effective)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.routes == nil {
		s.routes = make(map[string]codexTurnTicketRoute)
	}
	current := s.routeLocked(key, contextID)
	if expected != nil && current != *expected {
		return current, false
	}
	r := codexTurnTicketRoute{Mode: mode, Context: contextID, Generation: current.Generation + 1}
	s.routes[key] = r
	if discard {
		delete(s.tickets, key)
		if err := s.persistLocked(); err != nil {
			log.Errorf("codex turn tickets: persist discarded routing bundle: %v", err)
		}
	}
	return r, true
}

func (s *CodexTurnTicketStore) publishAdaptive(auth *cliproxyauth.Auth, model string, route codexTurnTicketRoute, ticket *CodexTurnTicket) bool {
	key := codexTurnTicketKey(auth.ID, model)
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.routeLocked(key, route.Context)
	if current != route || current.Mode != codexRouteInject {
		return false
	}
	copyTicket := *ticket
	copyTicket.RoutingCookies = append([]CodexRoutingCookie(nil), ticket.RoutingCookies...)
	s.tickets[key] = &copyTicket
	if err := s.persistLocked(); err != nil {
		log.Errorf("codex turn tickets: persist routing bundle: %v", err)
	}
	return true
}

// markAdaptiveDegraded switches a bucket into injection mode. For a request that was
// injected, the outbound bundle must still be the current one; a late response from an
// older request cannot invalidate a freshly renewed bundle.
func (s *CodexTurnTicketStore) markAdaptiveDegraded(auth *cliproxyauth.Auth, model string, effective CodexTurnTicketConfig, request http.Header, injected bool) bool {
	return s.markAdaptiveResponseMode(auth, model, effective, request, injected, codexRouteInject)
}

func (s *CodexTurnTicketStore) markAdaptiveResponseMode(auth *cliproxyauth.Auth, model string, effective CodexTurnTicketConfig, request http.Header, injected bool, mode string) bool {
	key := codexTurnTicketKey(auth.ID, model)
	contextID := codexRoutingContext(auth, effective)
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.routeLocked(key, contextID)
	if injected {
		ticket := s.tickets[key]
		if ticket == nil || !codexRequestMatchesBundle(request, ticket) {
			return false
		}
	}
	s.routes[key] = codexTurnTicketRoute{Mode: mode, Context: contextID, Generation: current.Generation + 1}
	// A clean request may have started before activation and completed afterward.
	// Its degradation says nothing about the validated bundle it never used.
	if injected || current.Mode != codexRouteInject || mode != codexRouteInject {
		delete(s.tickets, key)
	}
	if err := s.persistLocked(); err != nil {
		log.Errorf("codex turn tickets: persist invalidated routing bundle: %v", err)
	}
	return true
}

// markAdaptiveDirectFromResponse admits only the initial clean business result. Once a
// bucket is in injection mode, only a generation-checked synthetic business probe may
// disable injection; this prevents an older concurrent clean request from winning a race
// against a newer explicit degraded response.
func (s *CodexTurnTicketStore) markAdaptiveDirectFromResponse(auth *cliproxyauth.Auth, model string, effective CodexTurnTicketConfig) (codexTurnTicketRoute, bool) {
	key := codexTurnTicketKey(auth.ID, model)
	contextID := codexRoutingContext(auth, effective)
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.routeLocked(key, contextID)
	if current.Mode == codexRouteInject {
		return current, false
	}
	if current.Mode == codexRouteDirect {
		return current, true
	}
	s.routes[key] = codexTurnTicketRoute{Mode: codexRouteDirect, Context: contextID, Generation: current.Generation + 1}
	delete(s.tickets, key)
	if err := s.persistLocked(); err != nil {
		log.Errorf("codex turn tickets: persist direct routing transition: %v", err)
	}
	return s.routes[key], true
}

// ensureAdaptiveContext resets classification once when the business egress or identity
// changes. Returning changed lets the scheduler discard only the obsolete cooldown.
func (s *CodexTurnTicketStore) ensureAdaptiveContext(auth *cliproxyauth.Auth, model string, effective CodexTurnTicketConfig) (codexTurnTicketRoute, bool) {
	key, contextID := codexTurnTicketKey(auth.ID, model), codexRoutingContext(auth, effective)
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.routes[key]
	if current.Context == contextID && current.Mode != "" {
		return current, false
	}
	current = codexTurnTicketRoute{Mode: codexRouteUnknown, Context: contextID, Generation: current.Generation + 1}
	s.routes[key] = current
	delete(s.tickets, key)
	return current, true
}

func (t *CodexTurnTicket) routingValid(auth *cliproxyauth.Auth, effective CodexTurnTicketConfig, now time.Time) bool {
	if !t.valid(now, codexTurnTicketTargetLength(auth, effective)) || len(t.RoutingCookies) == 0 || t.RoutingValidatedAt.IsZero() || t.RoutingContext != codexRoutingContext(auth, effective) {
		return false
	}
	until := minTime(t.RoutingExpiresAt, t.RoutingCapturedAt.Add(time.Duration(effective.RoutingCookieTTLSeconds)*time.Second))
	if !until.After(now.Add(time.Duration(effective.RoutingExpiryMarginSeconds) * time.Second)) {
		return false
	}
	for _, c := range t.RoutingCookies {
		if !codexRoutingCookieName(c.Name, effective) || c.Value == "" || !c.ExpiresAt.After(now.Add(time.Duration(effective.RoutingExpiryMarginSeconds)*time.Second)) || (&http.Cookie{Name: c.Name, Value: c.Value}).Valid() != nil {
			return false
		}
	}
	return true
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func codexRoutingCookieName(name string, configs ...CodexTurnTicketConfig) bool {
	if len(configs) > 0 {
		return slices.Contains(configs[0].RoutingCookieNames, name)
	}
	return name == "__cflb" || name == "__oailb"
}

func codexRoutingCookies(header http.Header, now time.Time, effective CodexTurnTicketConfig) []CodexRoutingCookie {
	response := &http.Response{Header: header}
	byName := make(map[string]CodexRoutingCookie)
	for _, c := range response.Cookies() {
		if !codexRoutingCookieName(c.Name, effective) {
			continue
		}
		if c.Value == "" || c.MaxAge < 0 {
			delete(byName, c.Name)
			continue
		}
		if c.Valid() != nil {
			continue
		}
		// Only cookies for this backend may be promoted; host-only cookies are normal.
		domain := strings.TrimPrefix(strings.ToLower(c.Domain), ".")
		if domain != "" && domain != "chatgpt.com" {
			continue
		}
		if c.Path != "" && !strings.HasPrefix("/backend-api/codex/responses", c.Path) {
			continue
		}
		until := now.Add(time.Duration(effective.RoutingCookieTTLSeconds) * time.Second)
		if c.MaxAge > 0 {
			until = minTime(until, now.Add(time.Duration(min(c.MaxAge, effective.RoutingCookieTTLSeconds))*time.Second))
		}
		if !c.Expires.IsZero() {
			until = minTime(until, c.Expires)
		}
		if until.After(now) {
			byName[c.Name] = CodexRoutingCookie{Name: c.Name, Value: c.Value, ExpiresAt: until}
		}
	}
	var cookies []CodexRoutingCookie
	for _, name := range effective.RoutingCookieNames {
		if c, ok := byName[name]; ok {
			cookies = append(cookies, c)
		}
	}
	return cookies
}

func setCodexRoutingCookies(headers http.Header, cookies []CodexRoutingCookie, configs ...CodexTurnTicketConfig) {
	effective := EffectiveCodexTurnTicketConfig(nil)
	if len(configs) > 0 {
		effective = configs[0]
	}
	var keep []*http.Cookie
	for _, c := range codexRequestCookies(headers) {
		if !codexRoutingCookieName(c.Name, effective) {
			keep = append(keep, c)
		}
	}
	for key := range headers {
		if strings.EqualFold(key, "Cookie") {
			delete(headers, key)
		}
	}
	request := &http.Request{Header: headers}
	for _, c := range keep {
		request.AddCookie(c)
	}
	for _, c := range cookies {
		request.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
}

func codexRequestCookies(headers http.Header) []*http.Cookie {
	var cookies []*http.Cookie
	for key, values := range headers {
		if !strings.EqualFold(key, "Cookie") {
			continue
		}
		for _, value := range values {
			request := &http.Request{Header: http.Header{"Cookie": []string{value}}}
			cookies = append(cookies, request.Cookies()...)
		}
	}
	return cookies
}

func codexHeaderValue(headers http.Header, name string) string {
	for key, values := range headers {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

func (i *CodexTurnTicketInjector) applyAdaptive(auth *cliproxyauth.Auth, model string, headers http.Header, effective CodexTurnTicketConfig) bool {
	if !isCodexOAuthCredential(auth) {
		return false
	}
	key := codexTurnTicketKey(auth.ID, model)
	contextID := codexRoutingContext(auth, effective)
	i.store.mu.RLock()
	defer i.store.mu.RUnlock()
	if i.store.routeLocked(key, contextID).Mode != codexRouteInject {
		return false
	}
	ticket := i.store.tickets[key]
	if !ticket.routingValid(auth, effective, time.Now()) {
		return false
	}
	for key := range headers {
		if strings.EqualFold(key, CodexTurnStateHeader) {
			delete(headers, key)
		}
	}
	headers.Set(CodexTurnStateHeader, ticket.State)
	setCodexRoutingCookies(headers, ticket.RoutingCookies, effective)
	return true
}

func (s *CodexTurnTicketStore) adaptiveAllows(auth *cliproxyauth.Auth, model string, effective CodexTurnTicketConfig, now time.Time) bool {
	key := codexTurnTicketKey(auth.ID, model)
	contextID := codexRoutingContext(auth, effective)
	s.mu.RLock()
	defer s.mu.RUnlock()
	switch s.routeLocked(key, contextID).Mode {
	case codexRouteDirect:
		return true
	case codexRouteInject:
		return s.tickets[key].routingValid(auth, effective, now)
	default:
		return false
	}
}

func (s *CodexTurnTicketStore) adaptiveSnapshot(auth *cliproxyauth.Auth, model string, effective CodexTurnTicketConfig) (codexTurnTicketRoute, *CodexTurnTicket) {
	key := codexTurnTicketKey(auth.ID, model)
	contextID := codexRoutingContext(auth, effective)
	s.mu.RLock()
	defer s.mu.RUnlock()
	route := s.routeLocked(key, contextID)
	ticket := s.tickets[key]
	if ticket == nil {
		return route, nil
	}
	copyTicket := *ticket
	copyTicket.RoutingCookies = append([]CodexRoutingCookie(nil), ticket.RoutingCookies...)
	return route, &copyTicket
}

// CodexTurnTicketAdaptiveEnabled allows transport code to retain legacy connection
// reuse semantics when the adaptive policy is explicitly disabled.
func CodexTurnTicketAdaptiveEnabled() bool {
	p := CurrentCodexTurnTickets()
	if p == nil || p.Harvester == nil {
		return false
	}
	c := codexTurnTicketEffectiveConfig(p.Harvester.cfgProvider)
	return c.Enabled && c.AdaptiveInjection
}

// A request-scoped proxy has not been classified by the background business probe.
// Do not replay a canonical-egress bundle or let another egress change its decision.
func codexAdaptiveRequestEgressMatches(auth *cliproxyauth.Auth, effective CodexTurnTicketConfig, requestContext ...context.Context) bool {
	if len(requestContext) == 0 {
		return true
	}
	override := cliproxyexecutor.RequestProxyURL(requestContext[0])
	return override == "" || override == strings.TrimSpace(codexBusinessEgress(auth, effective))
}

func ObserveCodexTurnTicketResponse(auth *cliproxyauth.Auth, model string, status int, responseHeaders, requestHeaders http.Header, injected bool, requestContext ...context.Context) {
	p := CurrentCodexTurnTickets()
	if p == nil || p.Harvester == nil {
		return
	}
	effective := codexTurnTicketEffectiveConfig(p.Harvester.cfgProvider)
	if codexGatewayEnabled(effective) {
		p.Harvester.observeGateway(auth, model, status, responseHeaders, requestHeaders, injected, effective, requestContext...)
		return
	}
	if effective.AdaptiveInjection {
		if !codexAdaptiveRequestEgressMatches(auth, effective, requestContext...) {
			return
		}
		p.Harvester.observeAdaptive(auth, model, status, responseHeaders, requestHeaders, injected, effective)
	} else if status == http.StatusSwitchingProtocols || (status >= 200 && status < 300) {
		p.Harvester.HarvestCodexTurnStatePassively(auth, model, responseHeaders)
	}
}

func (h *CodexTurnTicketHarvester) wakeAdaptive(authID, model string) {
	h.scheduleMu.Lock()
	delete(h.nextProbe, codexTurnTicketKey(authID, model))
	h.scheduleMu.Unlock()
	select {
	case h.wake <- struct{}{}:
	default:
	}
}

// Lock the route while publishing a cooldown so a concurrent degraded observation
// either rejects this stale schedule or clears it after transitioning the route.
func (h *CodexTurnTicketHarvester) setAdaptiveCooldown(auth *cliproxyauth.Auth, model string, effective CodexTurnTicketConfig, route codexTurnTicketRoute, until time.Time) {
	h.store.mu.RLock()
	defer h.store.mu.RUnlock()
	if h.store.routeLocked(codexTurnTicketKey(auth.ID, model), codexRoutingContext(auth, effective)) == route {
		h.setProbeCooldown(auth.ID, model, until)
	}
}

func (h *CodexTurnTicketHarvester) observeAdaptive(auth *cliproxyauth.Auth, model string, status int, response, request http.Header, injected bool, effective CodexTurnTicketConfig) {
	if auth == nil || !effective.Enabled || !isCodexOAuthCredential(auth) || !codexTurnTicketModelGated(effective, model) || !codexTurnTicketAuthScoped(effective, auth.ID) || (status != http.StatusSwitchingProtocols && (status < 200 || status >= 300)) {
		return
	}
	state := ExtractCodexTurnState(response)
	target := codexTurnTicketTargetLength(auth, effective)
	if IsHealthyCodexTurnState(state, codexTurnTicketDegradedLength(auth, effective)) {
		if !h.store.markAdaptiveDegraded(auth, model, effective, request, injected) {
			return
		}
		h.recordObservation(auth.ID, model, CodexTurnTicketObservation{ObservedAt: time.Now(), StatusCode: status, StateLength: len(state), Result: "degraded_response"})
		h.wakeAdaptive(auth.ID, model)
		return
	}
	if !IsHealthyCodexTurnState(state, target) {
		mode := ""
		switch effective.UnknownStateAction {
		case "block":
			mode = codexRouteBlocked
		case "harvest":
			mode = codexRouteInject
		}
		if mode != "" && h.store.markAdaptiveResponseMode(auth, model, effective, request, injected, mode) {
			h.wakeAdaptive(auth.ID, model)
		}
		return
	}
	if IsHealthyCodexTurnState(state, target) && !injected && codexHeaderValue(request, CodexTurnStateHeader) == "" && !codexHasRoutingCookie(request, effective) {
		route, ok := h.store.markAdaptiveDirectFromResponse(auth, model, effective)
		if !ok {
			return
		}
		h.recordObservation(auth.ID, model, CodexTurnTicketObservation{ObservedAt: time.Now(), StatusCode: status, StateLength: len(state), Healthy: true, Result: "business_direct"})
		h.setAdaptiveCooldown(auth, model, effective, route, time.Now().Add(time.Duration(effective.ProbeCooldownSeconds)*time.Second))
	}
	// Success with an injected bundle must never imply natural business recovery or
	// extend the fixed routing lease. Only a clean business probe may turn injection off.
}

func codexHasRoutingCookie(headers http.Header, effective CodexTurnTicketConfig) bool {
	for _, c := range codexRequestCookies(headers) {
		if codexRoutingCookieName(c.Name, effective) {
			return true
		}
	}
	return false
}

func codexRequestMatchesBundle(headers http.Header, ticket *CodexTurnTicket) bool {
	if codexHeaderValue(headers, CodexTurnStateHeader) != ticket.State {
		return false
	}
	want := make(map[string]string)
	for _, c := range ticket.RoutingCookies {
		want[c.Name] = c.Value
	}
	for _, c := range codexRequestCookies(headers) {
		if v, ok := want[c.Name]; ok && v == c.Value {
			delete(want, c.Name)
		}
	}
	return len(want) == 0
}

type codexRoutingProbe struct {
	Header     http.Header
	Status     int
	Model      string
	Complete   bool
	ObservedAt time.Time
}

func newCodexRoutingTicket(state string, headers http.Header, observed time.Time, effective CodexTurnTicketConfig) *CodexTurnTicket {
	ticket := NewCodexTurnTicket(state, observed, time.Duration(effective.TTLSeconds)*time.Second)
	if ticket == nil {
		return nil
	}
	ticket.RoutingCookies = codexRoutingCookies(headers, observed, effective)
	if len(ticket.RoutingCookies) == 0 {
		return nil
	}
	ticket.RoutingCapturedAt = observed
	ticket.RoutingExpiresAt = minTime(ticket.ExpiresAt, observed.Add(time.Duration(effective.RoutingCookieTTLSeconds)*time.Second))
	for _, cookie := range ticket.RoutingCookies {
		ticket.RoutingExpiresAt = minTime(ticket.RoutingExpiresAt, cookie.ExpiresAt)
	}
	return ticket
}

// Header-only results identify explicit degradation. Acquired candidates must also
// finish a tiny SSE response with the requested model before they may be replayed.
func probeCodexRouting(ctx context.Context, auth *cliproxyauth.Auth, model, egress string, ticket *CodexTurnTicket, effective CodexTurnTicketConfig) (codexRoutingProbe, error) {
	var result codexRoutingProbe
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(effective.ProbeTimeoutSeconds)*time.Second)
	defer cancel()
	url := strings.TrimSuffix(codexTurnTicketBaseURL(auth), "/") + "/responses"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(codexTurnTicketProbeBody(model))))
	if err != nil {
		return result, err
	}
	req.Close = true
	req.Host = "chatgpt.com"
	req.Header.Set("Authorization", "Bearer "+codexAuthAccessToken(auth))
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("OpenAI-Beta", "responses=experimental")
	applyCodexTurnTicketProbeIdentity(req.Header, auth, model, effective.Identity)
	if ticket != nil {
		req.Header.Set(CodexTurnStateHeader, ticket.State)
		setCodexRoutingCookies(req.Header, ticket.RoutingCookies, effective)
	}
	client, err := codexTurnTicketProbeClient(ctx, auth, egress, 0)
	if err != nil {
		return result, err
	}
	response, err := client.Do(req)
	if err != nil {
		return result, err
	}
	defer func() { _ = response.Body.Close() }()
	result.Header, result.Status, result.ObservedAt = response.Header.Clone(), response.StatusCode, time.Now()
	if result.Status != http.StatusOK || IsHealthyCodexTurnState(ExtractCodexTurnState(result.Header), codexTurnTicketDegradedLength(auth, effective)) {
		return result, nil
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, codexTurnTicketProbeDrainLimit+1))
	if err != nil {
		return result, err
	}
	if len(body) > codexTurnTicketProbeDrainLimit {
		return result, fmt.Errorf("codex turn ticket: adaptive probe response exceeds %d bytes", codexTurnTicketProbeDrainLimit)
	}
	result.Model, result.Complete = codexRoutingCompletedModel(body)
	return result, nil
}

// codexRoutingCompletedModel accepts only a complete Responses SSE stream. Header-only,
// truncated, failed, malformed, or wrong-model responses cannot validate a routing
// bundle even when their HTTP status and turn-state header look healthy.
func codexRoutingCompletedModel(body []byte) (string, bool) {
	type responseEvent struct {
		Type     string          `json:"type"`
		Error    json.RawMessage `json:"error"`
		Response struct {
			Status string          `json:"status"`
			Model  string          `json:"model"`
			Error  json.RawMessage `json:"error"`
		} `json:"response"`
	}

	normalized := bytes.ReplaceAll(body, []byte("\r\n"), []byte("\n"))
	var completedModel string
	for _, block := range bytes.Split(normalized, []byte("\n\n")) {
		block = bytes.TrimSpace(block)
		if len(block) == 0 {
			continue
		}
		var eventName string
		var dataLines [][]byte
		for _, line := range bytes.Split(block, []byte("\n")) {
			if len(line) == 0 || line[0] == ':' {
				continue
			}
			field, value, found := bytes.Cut(line, []byte(":"))
			if !found {
				continue
			}
			value = bytes.TrimPrefix(value, []byte(" "))
			switch string(field) {
			case "event":
				eventName = strings.TrimSpace(string(value))
			case "data":
				dataLines = append(dataLines, value)
			}
		}
		if len(dataLines) == 0 {
			continue
		}
		data := bytes.TrimSpace(bytes.Join(dataLines, []byte("\n")))
		if bytes.Equal(data, []byte("[DONE]")) {
			continue
		}
		var event responseEvent
		if len(data) == 0 || json.Unmarshal(data, &event) != nil {
			return "", false
		}
		if eventName != "" && strings.TrimSpace(event.Type) != "" && eventName != strings.TrimSpace(event.Type) {
			return "", false
		}
		kind := strings.TrimSpace(event.Type)
		if kind == "" {
			kind = eventName
		}
		switch kind {
		case "error", "response.error", "response.failed", "response.incomplete":
			return "", false
		case "response.completed":
			if completedModel != "" || strings.TrimSpace(event.Response.Status) != "completed" || rawJSONPresent(event.Error) || rawJSONPresent(event.Response.Error) {
				return "", false
			}
			completedModel = strings.TrimSpace(event.Response.Model)
			if completedModel == "" {
				return "", false
			}
		}
	}
	return completedModel, completedModel != ""
}

func rawJSONPresent(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null")) && !bytes.Equal(trimmed, []byte("{}"))
}

func (h *CodexTurnTicketHarvester) routingProbe(ctx context.Context, auth *cliproxyauth.Auth, model, phase, egress string, ticket *CodexTurnTicket, effective CodexTurnTicketConfig) (codexRoutingProbe, error) {
	h.probed.Add(1)
	start := time.Now()
	h.beginRoutingProbe(auth.ID, model, phase, start)
	result, err := probeCodexRouting(ctx, auth, model, egress, ticket, effective)
	state := ExtractCodexTurnState(result.Header)
	observation := routingProbeObservation(auth, model, phase, result, ticket, effective, err)
	h.endRoutingProbe(auth.ID, model, phase, result, observation)
	fields := log.Fields{"auth_hint": codexTurnTicketAuthHint(auth), "model": model, "phase": phase, "egress": codexTurnTicketHarvestEgressLabel(egress), "http_status": result.Status, "state_length": len(state), "completed": result.Complete, "model_match": result.Model == model, "result": observation.Result, "elapsed_ms": time.Since(start).Milliseconds(), "error_class": codexTurnTicketProbeErrorClass(err)}
	if observation.Result == "harvest_egress_rejected" {
		fields["next_action"], fields["retry_after_seconds"] = "harvest_egress_backoff", effective.HarvestRejectBackoffSeconds
	} else if observation.Result == "rejected" {
		fields["next_action"], fields["retry_after_seconds"] = "bucket_backoff", effective.RejectBackoffSeconds
	}
	log.WithFields(fields).Info("codex turn ticket: adaptive probe completed")
	return result, err
}

func (h *CodexTurnTicketHarvester) routingRejected(authID, model string, result codexRoutingProbe, effective CodexTurnTicketConfig) bool {
	if slices.Contains(effective.RejectStatusCodes, result.Status) {
		h.parkBucket(authID, model, time.Now().Add(time.Duration(effective.RejectBackoffSeconds)*time.Second))
		return true
	}
	return false
}

func (h *CodexTurnTicketHarvester) probeAdaptive(ctx context.Context, auth *cliproxyauth.Auth, model string, effective CodexTurnTicketConfig) {
	if codexGatewayEnabled(effective) {
		h.probeGatewayAccount(ctx, auth, effective)
		return
	}
	h.probeInFlight.Lock()
	defer h.probeInFlight.Unlock()
	if ctx != nil && ctx.Err() != nil {
		return
	}
	if h.listAuths != nil {
		var current *cliproxyauth.Auth
		for _, a := range h.listAuths() {
			if a != nil && a.ID == auth.ID {
				current = a
				break
			}
		}
		if !isCodexTurnTicketProbeEligible(current) {
			return
		}
		auth = current
	}
	effective = codexTurnTicketEffectiveConfig(h.cfgProvider)
	if !effective.Enabled || !effective.AdaptiveInjection || !codexTurnTicketModelGated(effective, model) || !codexTurnTicketAuthScoped(effective, auth.ID) {
		return
	}
	route, contextChanged := h.store.ensureAdaptiveContext(auth, model, effective)
	if contextChanged {
		// A changed egress must not inherit a prior long natural-healthy cooldown.
		h.scheduleMu.Lock()
		delete(h.nextProbe, codexTurnTicketKey(auth.ID, model))
		h.scheduleMu.Unlock()
	}
	if route.Mode == codexRouteInject {
		if ticket := h.store.Lookup(auth.ID, model); ticket != nil {
			// A hot reload that shortens the local lease or increases the renewal
			// margin must bring the next probe forward immediately.
			renewAt := minTime(ticket.RoutingExpiresAt, ticket.RoutingCapturedAt.Add(time.Duration(effective.RoutingCookieTTLSeconds)*time.Second)).Add(-time.Duration(effective.RoutingRefreshBeforeSeconds) * time.Second)
			h.bringRoutingProbeForward(auth, model, effective, route, renewAt)
		}
	} else if route.Mode == codexRouteDirect {
		observation := h.observation(auth.ID, model)
		if observation.Healthy && !observation.ObservedAt.IsZero() {
			// A shorter healthy cooldown must also affect already classified buckets.
			h.bringRoutingProbeForward(auth, model, effective, route, observation.ObservedAt.Add(time.Duration(effective.ProbeCooldownSeconds)*time.Second))
		}
	}
	if !h.reserveProbeSlot(auth.ID, model, time.Now(), effective) {
		return
	}
	h.setAdaptiveCooldown(auth, model, effective, route, time.Now().Add(time.Duration(effective.RoutingProbeIntervalSeconds)*time.Second))
	business := codexBusinessEgress(auth, effective)
	result, err := h.routingProbe(ctx, auth, model, "business", business, nil, effective)
	if h.routingRejected(auth.ID, model, result, effective) {
		return
	}
	businessFailed := err != nil || result.Status != http.StatusOK
	if businessFailed && !effective.HarvestOnBusinessError {
		return
	}
	if !h.adaptiveProbeContextCurrent(auth, model, effective) {
		return
	}
	state := ExtractCodexTurnState(result.Header)
	target := codexTurnTicketTargetLength(auth, effective)
	if !businessFailed && IsHealthyCodexTurnState(state, target) && codexRoutingResponseAcceptable(result, model, effective) {
		// Do not overwrite an explicit live degradation observed while probing. A
		// successful clean business probe is the only transition from inject to direct.
		updated, ok := h.store.setRouteIf(auth, model, effective, &route, codexRouteDirect, true)
		if !ok {
			return
		}
		h.recordObservation(auth.ID, model, CodexTurnTicketObservation{ObservedAt: time.Now(), StatusCode: 200, StateLength: len(state), Healthy: true, Result: "business_direct"})
		h.setAdaptiveCooldown(auth, model, effective, updated, time.Now().Add(time.Duration(effective.ProbeCooldownSeconds)*time.Second))
		return
	}
	if !businessFailed && !IsHealthyCodexTurnState(state, codexTurnTicketDegradedLength(auth, effective)) {
		switch effective.UnknownStateAction {
		case "block":
			h.store.setRouteIf(auth, model, effective, &route, codexRouteBlocked, true)
			return
		case "harvest":
		default:
			return
		}
	}
	if route.Mode != codexRouteInject {
		var ok bool
		route, ok = h.store.setRouteIf(auth, model, effective, &route, codexRouteInject, true)
		if !ok {
			return
		}
	} else if h.store.route(auth, model, effective) != route {
		return
	}
	for attempt := 0; attempt < effective.HarvestAttempts; attempt++ {
		if ctx != nil && ctx.Err() != nil {
			return
		}
		if h.store.route(auth, model, effective) != route || !h.adaptiveProbeContextCurrent(auth, model, effective) {
			return
		}
		candidates, _ := h.routingHarvestCandidates(auth.ID, model, effective, time.Now())
		egress := chooseCodexTurnTicketHarvestEgress(candidates)
		if egress == "" {
			return
		}
		fresh, err := h.routingProbe(ctx, auth, model, "harvest", egress, nil, effective)
		if slices.Contains(effective.HarvestRejectStatusCodes, fresh.Status) {
			// A pool exit can be forbidden while the credential's business route
			// remains usable. Do not let it suppress renewal for the whole bucket.
			h.parkRoutingHarvestEgress(auth.ID, model, egress, time.Now())
			continue
		}
		if h.routingRejected(auth.ID, model, fresh, effective) {
			return
		}
		if err != nil || fresh.Status != 200 || !codexRoutingResponseAcceptable(fresh, model, effective) || !IsHealthyCodexTurnState(ExtractCodexTurnState(fresh.Header), target) {
			continue
		}
		candidate := newCodexRoutingTicket(ExtractCodexTurnState(fresh.Header), fresh.Header, fresh.ObservedAt, effective)
		if candidate == nil {
			continue
		}
		verified, err := h.routingProbe(ctx, auth, model, "business_validation", business, candidate, effective)
		if h.routingRejected(auth.ID, model, verified, effective) {
			return
		}
		validationState := ExtractCodexTurnState(verified.Header)
		if err != nil || verified.Status != 200 || !codexRoutingResponseAcceptable(verified, model, effective) || !codexValidationStateAcceptable(validationState, candidate, target, effective) {
			continue
		}
		// Activate only the bundle that was actually replayed. A different response
		// ticket is a new candidate, even when its shape looks healthy.
		candidate.RoutingContext, candidate.RoutingValidatedAt = route.Context, verified.ObservedAt
		if !h.adaptiveProbeContextCurrent(auth, model, effective) || !candidate.routingValid(auth, effective, time.Now()) || !h.store.publishAdaptive(auth, model, route, candidate) {
			return
		}
		h.harvested.Add(1)
		h.recordObservation(auth.ID, model, CodexTurnTicketObservation{ObservedAt: time.Now(), StatusCode: 200, StateLength: candidate.Length, Healthy: true, Result: "routing_validated"})
		renewAt := candidate.RoutingExpiresAt.Add(-time.Duration(effective.RoutingRefreshBeforeSeconds) * time.Second)
		h.setAdaptiveCooldown(auth, model, effective, route, renewAt)
		return
	}
}

func (h *CodexTurnTicketHarvester) adaptiveProbeContextCurrent(auth *cliproxyauth.Auth, model string, effective CodexTurnTicketConfig) bool {
	current := codexTurnTicketEffectiveConfig(h.cfgProvider)
	if !current.Enabled || !current.AdaptiveInjection || !codexTurnTicketModelGated(current, model) || !codexTurnTicketAuthScoped(current, auth.ID) {
		return false
	}
	currentAuth := auth
	if h.listAuths != nil {
		currentAuth = nil
		for _, candidate := range h.listAuths() {
			if candidate != nil && candidate.ID == auth.ID {
				currentAuth = candidate
				break
			}
		}
	}
	return isCodexTurnTicketProbeEligible(currentAuth) && codexRoutingContext(currentAuth, current) == codexRoutingContext(auth, effective)
}

// Stable ordering is used by management metadata and never includes cookie values.
func codexRoutingCookieNames(ticket *CodexTurnTicket) []string {
	if ticket == nil {
		return nil
	}
	var names []string
	for _, c := range ticket.RoutingCookies {
		names = append(names, c.Name)
	}
	sort.Strings(names)
	return names
}

// Policy changes invalidate classification and bundles, but admission-only switches
// are evaluated immediately without erasing evidence of degradation.
func codexRoutingPolicyContext(auth *cliproxyauth.Auth, effective CodexTurnTicketConfig) string {
	policy := struct {
		Plan            string
		DegradedLength  int
		Validation      string
		Complete, Model bool
		Cookies         []string
	}{ResolveCodexTurnTicketPlan(auth, effective.TargetLength, effective).Plan,
		codexTurnTicketDegradedLength(auth, effective), effective.ValidationTicketPolicy,
		effective.RequireCompleteResponse, effective.RequireModelMatch, effective.RoutingCookieNames}
	encoded, _ := json.Marshal(policy)
	return string(encoded)
}

func (s *CodexTurnTicketStore) adaptiveAdmissionAllows(auth *cliproxyauth.Auth, model string, effective CodexTurnTicketConfig, now time.Time) bool {
	key, contextID := codexTurnTicketKey(auth.ID, model), codexRoutingContext(auth, effective)
	s.mu.RLock()
	defer s.mu.RUnlock()
	switch s.routeLocked(key, contextID).Mode {
	case codexRouteDirect:
		return true
	case codexRouteBlocked:
		return false
	case codexRouteInject:
		return !effective.BlockOnDegraded || (effective.InjectionEnabled && s.tickets[key].routingValid(auth, effective, now))
	default:
		return !effective.FailClosed
	}
}
