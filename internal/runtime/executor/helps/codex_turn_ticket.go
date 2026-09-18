package helps

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/constant"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
)

// Codex turn-state tickets
//
// The upstream mints a healthy X-Codex-Turn-State token (normally 292 characters,
// prefixed gAAAAA) for accounts and models that are not currently degraded. Under
// capacity pressure it mints a longer degraded variant (commonly 312). Replaying a
// healthy token on a request lets the account skip the degraded state.
//
// The store below is deliberately narrow: it never fabricates a value, it only
// reads and writes the single X-Codex-Turn-State header, and it buckets strictly by
// (auth ID, model). A token minted for one credential is never replayed for another,
// and never for a different model on the same credential.

const (
	// CodexTurnStateHeader is the only header this feature reads or writes upstream.
	CodexTurnStateHeader = "X-Codex-Turn-State"
	// codexTurnTicketStatePrefix is the Fernet prefix the upstream always mints with.
	codexTurnTicketStatePrefix = "gAAAAA"
)

// CodexTurnTicket is one captured healthy turn-state token.
type CodexTurnTicket struct {
	State      string    `json:"state"`
	Length     int       `json:"length"`
	CapturedAt time.Time `json:"captured_at"`
	// ExpiresAt is derived from the issue timestamp inside the token, not from the
	// moment it was observed. See CodexTurnTicketIssueTime.
	ExpiresAt time.Time `json:"expires_at"`
}

func (t *CodexTurnTicket) valid(now time.Time, targetLength int) bool {
	if t == nil {
		return false
	}
	state := strings.TrimSpace(t.State)
	if state == "" || !strings.HasPrefix(state, codexTurnTicketStatePrefix) {
		return false
	}
	if targetLength > 0 && len(state) != targetLength {
		return false
	}
	if t.ExpiresAt.IsZero() || !now.Before(t.ExpiresAt) {
		return false
	}
	return true
}

func (t *CodexTurnTicket) needsRefresh(now time.Time, refreshBefore time.Duration) bool {
	if t == nil || t.ExpiresAt.IsZero() {
		return true
	}
	return !t.ExpiresAt.After(now.Add(refreshBefore))
}

// codexTurnTicketKey buckets tickets by (auth ID, model). The separator is a NUL so
// an auth ID can never collide with a model name that contains the separator.
func codexTurnTicketKey(authID, model string) string {
	return strings.TrimSpace(authID) + "\x00" + strings.TrimSpace(model)
}

// CodexTurnTicketStore keeps captured tickets in memory, bucketed by (auth ID, model).
type CodexTurnTicketStore struct {
	mu      sync.RWMutex
	tickets map[string]*CodexTurnTicket
}

// NewCodexTurnTicketStore returns an empty in-memory ticket store.
func NewCodexTurnTicketStore() *CodexTurnTicketStore {
	return &CodexTurnTicketStore{tickets: make(map[string]*CodexTurnTicket)}
}

// Store records a ticket for the (authID, model) bucket, replacing any previous value.
func (s *CodexTurnTicketStore) Store(authID, model string, ticket *CodexTurnTicket) {
	if s == nil || ticket == nil {
		return
	}
	authID = strings.TrimSpace(authID)
	model = strings.TrimSpace(model)
	if authID == "" || model == "" {
		return
	}
	copied := *ticket
	s.mu.Lock()
	if s.tickets == nil {
		s.tickets = make(map[string]*CodexTurnTicket)
	}
	s.tickets[codexTurnTicketKey(authID, model)] = &copied
	s.mu.Unlock()
}

// Lookup returns the ticket for the (authID, model) bucket, if any.
func (s *CodexTurnTicketStore) Lookup(authID, model string) *CodexTurnTicket {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	ticket := s.tickets[codexTurnTicketKey(authID, model)]
	s.mu.RUnlock()
	if ticket == nil {
		return nil
	}
	copied := *ticket
	return &copied
}

// Delete removes a bucket, used when a stored ticket is known to be unusable.
func (s *CodexTurnTicketStore) Delete(authID, model string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	delete(s.tickets, codexTurnTicketKey(authID, model))
	s.mu.Unlock()
}

// CodexTurnTicketConfig is the effective, normalized ticket configuration.
type CodexTurnTicketConfig struct {
	Enabled              bool
	TargetLength         int
	TTLSeconds           int
	RefreshBeforeSeconds int
	ProbeIntervalSeconds int
	ProbeTimeoutSeconds  int
	ProbeCooldownSeconds int
	RejectBackoffSeconds int
	HarvestProxyURL      string
	Models               []string
	AuthIDs              []string
}

// CodexTurnTicketDefaults lists the model buckets probed when the operator does not
// name any. Only models the upstream actually mints tickets for are useful here.
var CodexTurnTicketDefaults = []string{"gpt-5.5", "gpt-5.6-sol", "gpt-5.6-terra", "gpt-6-astra"}

// EffectiveCodexTurnTicketConfig normalizes cfg.Codex.TurnTicket with defaults.
func EffectiveCodexTurnTicketConfig(cfg *config.Config) CodexTurnTicketConfig {
	effective := CodexTurnTicketConfig{
		TargetLength:         292,
		TTLSeconds:           3600,
		RefreshBeforeSeconds: 600,
		ProbeIntervalSeconds: 60,
		ProbeTimeoutSeconds:  25,
		ProbeCooldownSeconds: 3300,
		RejectBackoffSeconds: 600,
	}
	if cfg == nil {
		effective.Models = append([]string(nil), CodexTurnTicketDefaults...)
		return effective
	}
	raw := cfg.Codex.TurnTicket
	effective.Enabled = raw.Enabled
	effective.HarvestProxyURL = strings.TrimSpace(raw.HarvestProxyURL)
	if raw.TargetLength > 0 {
		effective.TargetLength = raw.TargetLength
	}
	if raw.TTLSeconds > 0 {
		effective.TTLSeconds = raw.TTLSeconds
	}
	if raw.RefreshBeforeSeconds > 0 {
		effective.RefreshBeforeSeconds = raw.RefreshBeforeSeconds
	}
	if raw.ProbeIntervalSeconds > 0 {
		effective.ProbeIntervalSeconds = raw.ProbeIntervalSeconds
	}
	if raw.ProbeTimeoutSeconds > 0 {
		effective.ProbeTimeoutSeconds = raw.ProbeTimeoutSeconds
	}
	if raw.ProbeCooldownSeconds > 0 {
		effective.ProbeCooldownSeconds = raw.ProbeCooldownSeconds
	}
	if raw.RejectBackoffSeconds > 0 {
		effective.RejectBackoffSeconds = raw.RejectBackoffSeconds
	}
	for _, model := range raw.Models {
		if trimmed := strings.TrimSpace(model); trimmed != "" {
			effective.Models = append(effective.Models, trimmed)
		}
	}
	// Enabling the feature without naming models uses the set the upstream actually mints
	// tickets for, so a bare `enabled: true` is useful instead of inert.
	if len(effective.Models) == 0 {
		effective.Models = append([]string(nil), CodexTurnTicketDefaults...)
	}
	for _, authID := range raw.AuthIDs {
		if trimmed := strings.TrimSpace(authID); trimmed != "" {
			effective.AuthIDs = append(effective.AuthIDs, trimmed)
		}
	}
	return effective
}

// codexTurnTicketModelGated reports whether model participates in ticket handling.
func codexTurnTicketModelGated(effective CodexTurnTicketConfig, model string) bool {
	model = strings.TrimSpace(model)
	if model == "" {
		return false
	}
	for _, candidate := range effective.Models {
		if strings.TrimSpace(candidate) == model {
			return true
		}
	}
	return false
}

// fernetTimeVersion is the version byte every Fernet token carries.
const fernetTimeVersion = 0x80

// CodexTurnTicketIssueTime extracts the issue timestamp from a turn-state token.
//
// The upstream mints these tokens with Fernet, whose first nine bytes are an
// unauthenticated-but-plain version byte followed by a big-endian issue timestamp in
// seconds. That prefix is readable without the signing key, which matters because the
// token's lifetime is measured from the instant it was minted, not from the instant we
// observed it: replaying a token we harvested a while ago near, or past, its real
// expiry makes the upstream reject the request. TTL must therefore be anchored to the
// encoded timestamp whenever it can be recovered. When it cannot, callers must treat
// the ticket as short-lived instead of assuming a fresh full TTL.
func CodexTurnTicketIssueTime(state string) (time.Time, bool) {
	raw, ok := decodeFernetToken(state)
	if !ok {
		return time.Time{}, false
	}
	seconds := binary.BigEndian.Uint64(raw[1:9])
	if seconds == 0 || seconds > uint64(math.MaxInt64) {
		return time.Time{}, false
	}
	return time.Unix(int64(seconds), 0).UTC(), true
}

// decodeFernetToken returns the decoded bytes of a Fernet token. Fernet is
// base64url(version || timestamp || iv || ciphertext || hmac), and the first nine bytes
// are visible without the key. Tokens may or may not carry base64 padding depending on
// the encoder, so both forms are accepted.
func decodeFernetToken(state string) ([]byte, bool) {
	trimmed := strings.TrimSpace(state)
	if trimmed == "" {
		return nil, false
	}
	raw, errDecode := base64.RawURLEncoding.DecodeString(strings.TrimRight(trimmed, "="))
	if errDecode != nil {
		decoded, errWithPadding := base64.URLEncoding.DecodeString(trimmed)
		if errWithPadding != nil {
			return nil, false
		}
		raw = decoded
	}
	// Nine bytes is the shortest prefix that carries a timestamp, and the version
	// byte is what distinguishes a Fernet token from any other opaque value.
	if len(raw) < 9 || raw[0] != fernetTimeVersion {
		return nil, false
	}
	return raw, true
}

// MaxCodexTurnTicketLifetime is the fallback TTL applied when a token's encoded issue
// time cannot be recovered. It is intentionally shorter than the configured TTL so an
// unreadable timestamp degrades freshness instead of blindly extending a stale token.
const MaxCodexTurnTicketLifetime = 20 * time.Minute

// codexTurnTicketDefaultBaseURL is the Codex backend the upstream mints turn-state
// tokens for. Credentials that pin their own base URL use that instead.
const codexTurnTicketDefaultBaseURL = "https://chatgpt.com/backend-api/codex"

// NewCodexTurnTicket builds a ticket whose expiry is measured from the token's own
// issue time when that is recoverable, and from the configured TTL otherwise.
func NewCodexTurnTicket(state string, observedAt time.Time, ttl time.Duration) *CodexTurnTicket {
	state = strings.TrimSpace(state)
	if state == "" {
		return nil
	}
	if observedAt.IsZero() {
		observedAt = time.Now()
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	issuedAt, hasIssuedAt := CodexTurnTicketIssueTime(state)
	if !hasIssuedAt || issuedAt.After(observedAt) {
		if ttl > MaxCodexTurnTicketLifetime {
			ttl = MaxCodexTurnTicketLifetime
		}
		issuedAt = observedAt
	}
	return &CodexTurnTicket{
		State:      state,
		Length:     len(state),
		CapturedAt: observedAt,
		ExpiresAt:  issuedAt.Add(ttl),
	}
}

// CodexTurnTicketInjector injects stored tickets into outbound Codex requests.
//
// It is safe for concurrent use and never mutates the store on the request path, so a
// slow or failing upstream probe cannot add latency to client traffic.
type CodexTurnTicketInjector struct {
	store *CodexTurnTicketStore
	cfg   *config.Config
}

// NewCodexTurnTicketInjector returns an injector over store, reading live config.
func NewCodexTurnTicketInjector(store *CodexTurnTicketStore, cfg *config.Config) *CodexTurnTicketInjector {
	return &CodexTurnTicketInjector{store: store, cfg: cfg}
}

// Apply overwrites X-Codex-Turn-State on the outbound headers with the ticket captured
// for this (auth, model) bucket. It is a no-op unless the feature is enabled and the
// model participates; when no usable ticket exists the client-supplied header is left
// untouched, matching pass-through behaviour.
func (i *CodexTurnTicketInjector) Apply(auth *cliproxyauth.Auth, model string, headers http.Header) {
	if i == nil || i.store == nil || headers == nil || auth == nil {
		return
	}
	effective := EffectiveCodexTurnTicketConfig(i.cfg)
	if !effective.Enabled || !codexTurnTicketModelGated(effective, model) {
		return
	}
	ticket := i.store.Lookup(auth.ID, model)
	if !ticket.valid(time.Now(), effective.TargetLength) {
		return
	}
	// Overwrite rather than merge: the request must carry exactly one turn-state, and a
	// stale client-supplied value would otherwise win on case-insensitive lookup.
	headers.Del(CodexTurnStateHeader)
	headers.Set(CodexTurnStateHeader, ticket.State)
}

// CodexTurnTicketHarvester probes Codex accounts through a dedicated egress proxy and
// records healthy turn-state tickets. It never refreshes credentials and never touches
// consumer traffic, so it cannot disturb the live request path.
type CodexTurnTicketHarvester struct {
	store *CodexTurnTicketStore
	cfg   *config.Config

	// listAuths returns the credentials eligible for probing.
	listAuths func() []*cliproxyauth.Auth

	mu      sync.Mutex
	running bool
	stop    chan struct{}
	done    chan struct{}

	// schedule guards the per-bucket probe pacing. A bucket is skipped while it is inside
	// its cooldown, and parked while it is backing off from an upstream rejection.
	scheduleMu sync.Mutex
	nextProbe  map[string]time.Time
	backoffRun map[string]time.Time

	probeInFlight sync.Mutex
	probed        atomic.Int64
	harvested     atomic.Int64
}

// NewCodexTurnTicketHarvester returns a harvester bound to store and listAuths.
func NewCodexTurnTicketHarvester(store *CodexTurnTicketStore, cfg *config.Config, listAuths func() []*cliproxyauth.Auth) *CodexTurnTicketHarvester {
	return &CodexTurnTicketHarvester{
		store:      store,
		cfg:        cfg,
		listAuths:  listAuths,
		nextProbe:  make(map[string]time.Time),
		backoffRun: make(map[string]time.Time),
	}
}

// Start launches the background probe loop. It is idempotent.
func (h *CodexTurnTicketHarvester) Start(ctx context.Context) {
	if h == nil {
		return
	}
	effective := EffectiveCodexTurnTicketConfig(h.cfg)
	if !effective.Enabled || effective.HarvestProxyURL == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.running {
		return
	}
	h.running = true
	h.stop = make(chan struct{})
	h.done = make(chan struct{})
	stop, done := h.stop, h.done
	parent := ctx
	if parent == nil {
		parent = context.Background()
	}
	go func() {
		defer close(done)
		h.run(parent, stop)
	}()
}

// Stop terminates the probe loop and waits for it to exit.
func (h *CodexTurnTicketHarvester) Stop() {
	if h == nil {
		return
	}
	h.mu.Lock()
	if !h.running {
		h.mu.Unlock()
		return
	}
	stop, done := h.stop, h.done
	h.running = false
	close(stop)
	h.mu.Unlock()
	if done != nil {
		<-done
	}
}

func (h *CodexTurnTicketHarvester) run(ctx context.Context, stop <-chan struct{}) {
	effective := EffectiveCodexTurnTicketConfig(h.cfg)
	interval := time.Duration(effective.ProbeIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = time.Minute
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	h.probeAll(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case <-timer.C:
			h.probeAll(ctx)
			timer.Reset(interval)
		}
	}
}

func (h *CodexTurnTicketHarvester) probeAll(ctx context.Context) {
	if h == nil || h.listAuths == nil || h.store == nil {
		return
	}
	effective := EffectiveCodexTurnTicketConfig(h.cfg)
	if !effective.Enabled || effective.HarvestProxyURL == "" {
		return
	}
	scope := make(map[string]struct{}, len(effective.AuthIDs))
	for _, authID := range effective.AuthIDs {
		scope[authID] = struct{}{}
	}
	now := time.Now()
	refreshBefore := time.Duration(effective.RefreshBeforeSeconds) * time.Second
	for _, auth := range h.listAuths() {
		if auth == nil || !isCodexOAuthAuth(auth) {
			continue
		}
		if len(scope) > 0 {
			if _, ok := scope[auth.ID]; !ok {
				continue
			}
		}
		for _, model := range effective.Models {
			if ticket := h.store.Lookup(auth.ID, model); ticket.valid(now, effective.TargetLength) && !ticket.needsRefresh(now, refreshBefore) {
				continue
			}
			h.probeOne(ctx, auth, model, effective)
		}
	}
}

// isCodexOAuthAuth limits probing to OAuth credentials. API-key credential pools have
// no upstream-minted turn-state to harvest, and probing them would waste quota.
func isCodexOAuthAuth(auth *cliproxyauth.Auth) bool {
	if auth == nil {
		return false
	}
	if strings.TrimSpace(auth.ID) == "" {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
		return false
	}
	if auth.AuthKind() == cliproxyauth.AuthKindAPIKey {
		return false
	}
	if auth.Attributes != nil && strings.TrimSpace(auth.Attributes["api_key"]) != "" {
		return false
	}
	return strings.TrimSpace(codexAuthAccessToken(auth)) != ""
}

func codexAuthAccessToken(auth *cliproxyauth.Auth) string {
	if auth == nil || auth.Metadata == nil {
		return ""
	}
	if token, ok := auth.Metadata["access_token"].(string); ok {
		return strings.TrimSpace(token)
	}
	return ""
}

// ErrCodexTurnTicketProbeSkipped reports a probe that was not attempted.
var ErrCodexTurnTicketProbeSkipped = errors.New("codex turn ticket probe skipped")

func (h *CodexTurnTicketHarvester) probeOne(ctx context.Context, auth *cliproxyauth.Auth, model string, effective CodexTurnTicketConfig) {
	// Serialize probes per bucket so a slow attempt cannot pile up behind the interval.
	h.probeInFlight.Lock()
	defer h.probeInFlight.Unlock()
	if ctx != nil && ctx.Err() != nil {
		return
	}
	now := time.Now()
	if !h.reserveProbeSlot(auth.ID, model, now, effective) {
		return
	}
	h.probed.Add(1)
	state, status, errProbe := ProbeCodexTurnState(ctx, auth, model, effective)
	if errProbe != nil {
		return
	}
	// A rejection is not a miss. 429 means the credential is being asked to mint too
	// often, and 401/403 mean the credential itself is unusable; probing again without
	// waiting turns either into a sustained burst that harms every bucket sharing the
	// credential, so the bucket parks for the configured backoff instead.
	if status == http.StatusTooManyRequests || status == http.StatusUnauthorized || status == http.StatusForbidden {
		h.parkBucket(auth.ID, model, time.Now().Add(time.Duration(effective.RejectBackoffSeconds)*time.Second))
		log.Debugf("codex turn ticket: bucket backed off after upstream rejection (status=%d)", status)
		return
	}
	ticket := NewCodexTurnTicket(state, time.Now(), time.Duration(effective.TTLSeconds)*time.Second)
	if ticket == nil || !ticket.valid(time.Now(), effective.TargetLength) {
		return
	}
	h.store.Store(auth.ID, model, ticket)
	h.harvested.Add(1)
}

// reserveProbeSlot reports whether a bucket may be probed now, and pushes its next allowed
// attempt forward. Two limits keep the probe rate something the upstream does not notice:
// an explicit rejection parks the bucket for the backoff window, and every other attempt
// waits out the cooldown. A bucket whose ticket is still healthy and far from expiry never
// reaches this point, because probeAll skips it first.
func (h *CodexTurnTicketHarvester) reserveProbeSlot(authID, model string, now time.Time, effective CodexTurnTicketConfig) bool {
	if h == nil {
		return false
	}
	key := codexTurnTicketKey(authID, model)
	cooldown := time.Duration(effective.ProbeCooldownSeconds) * time.Second
	h.scheduleMu.Lock()
	defer h.scheduleMu.Unlock()
	if until, ok := h.backoffRun[key]; ok {
		if now.Before(until) {
			return false
		}
		delete(h.backoffRun, key)
	}
	if next, ok := h.nextProbe[key]; ok && now.Before(next) {
		return false
	}
	h.nextProbe[key] = now.Add(cooldown)
	return true
}

// parkBucket stops probing one bucket until the given instant.
func (h *CodexTurnTicketHarvester) parkBucket(authID, model string, until time.Time) {
	if h == nil {
		return
	}
	h.scheduleMu.Lock()
	h.backoffRun[codexTurnTicketKey(authID, model)] = until
	h.scheduleMu.Unlock()
}

// ProbeCodexTurnState issues one synthetic request through the harvest proxy and returns
// the healthy turn-state token the upstream minted, if any, together with the HTTP status
// so the caller can tell a rejection from a plain miss.
func ProbeCodexTurnState(ctx context.Context, auth *cliproxyauth.Auth, model string, effective CodexTurnTicketConfig) (string, int, error) {
	if auth == nil {
		return "", 0, ErrCodexTurnTicketProbeSkipped
	}
	token := codexAuthAccessToken(auth)
	if token == "" {
		return "", 0, ErrCodexTurnTicketProbeSkipped
	}
	proxyURL := strings.TrimSpace(effective.HarvestProxyURL)
	if proxyURL == "" {
		return "", 0, ErrCodexTurnTicketProbeSkipped
	}
	timeout := time.Duration(effective.ProbeTimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 25 * time.Second
	}
	probeCtx := ctx
	if probeCtx == nil {
		probeCtx = context.Background()
	}
	probeCtx, cancel := context.WithTimeout(probeCtx, timeout)
	defer cancel()
	return probeCodexTurnStateWithClient(probeCtx, auth, token, model, proxyURL)
}

// codexTurnTicketProbeBody is the smallest request that makes the upstream mint a
// turn-state token. It deliberately asks for no generation beyond a canned reply.
func codexTurnTicketProbeBody(model string) []byte {
	return []byte(`{"model":` + strconv.Quote(strings.TrimSpace(model)) + `,"store":false,"stream":true,"instructions":"Reply with exactly: pong","input":[{"role":"user","content":[{"type":"input_text","text":"ping"}]}]}`)
}

// codexTurnTicketProbeClient is overridable in tests to avoid real network access while
// still exercising the request the harvester builds.
var codexTurnTicketProbeClient = func(ctx context.Context, auth *cliproxyauth.Auth, proxyURL string, timeout time.Duration) (*http.Client, error) {
	transport, mode, errBuild := proxyutil.BuildHTTPTransport(proxyURL)
	if errBuild != nil {
		return nil, fmt.Errorf("codex turn ticket: build harvest proxy transport: %w", errBuild)
	}
	// Only a concrete proxy is acceptable: ModeInherit would fall back to the process's
	// ambient egress and ModeDirect would bypass the harvest path entirely, and both would
	// silently merge probe traffic with the client-traffic path this feature separates.
	if mode != proxyutil.ModeProxy || transport == nil {
		return nil, fmt.Errorf("codex turn ticket: harvest proxy %q is not a usable proxy URL", proxyutil.Redact(proxyURL))
	}
	// Synthetic probes must not share a connection with client traffic: the harvest
	// egress is a different path, and reusing a pooled connection would leak that
	// separation. DisableKeepAlives makes every probe open and close its own connection.
	transport.DisableKeepAlives = true
	return &http.Client{Transport: transport, Timeout: timeout}, nil
}

// probeCodexTurnStateWithClient issues one synthetic Codex request through the harvest
// proxy and returns the turn-state token the upstream minted on the response.
//
// A rejected or token-less response is not an error: it simply means this account and
// model did not mint a healthy ticket right now, and the next cycle may succeed. The
// response body is discarded without being read, which keeps the probe from paying for
// generation.
func probeCodexTurnStateWithClient(ctx context.Context, auth *cliproxyauth.Auth, token, model, proxyURL string) (string, int, error) {
	baseURL := codexTurnTicketBaseURL(auth)
	url := strings.TrimSuffix(baseURL, "/") + "/responses"
	probeCtx := ctx
	if probeCtx == nil {
		probeCtx = context.Background()
	}

	req, errReq := http.NewRequestWithContext(probeCtx, http.MethodPost, url, bytes.NewReader(codexTurnTicketProbeBody(model)))
	if errReq != nil {
		return "", 0, errReq
	}
	// Close the connection after the response headers arrive: the token is all the probe
	// needs, and the upstream would otherwise keep streaming a body nobody reads.
	req.Close = true
	req.Host = "chatgpt.com"
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("OpenAI-Beta", "responses=experimental")
	applyCodexTurnTicketProbeIdentity(req.Header, auth, model)

	client, errClient := codexTurnTicketProbeClient(probeCtx, auth, proxyURL, 0)
	if errClient != nil {
		return "", 0, errClient
	}
	resp, errDo := client.Do(req)
	if errDo != nil {
		return "", 0, errDo
	}
	defer func() {
		if _, errCopy := io.Copy(io.Discard, io.LimitReader(resp.Body, codexTurnTicketProbeDrainLimit)); errCopy != nil {
			log.Debugf("codex turn ticket: discard probe response body: %v", errCopy)
		}
		if errClose := resp.Body.Close(); errClose != nil {
			log.Debugf("codex turn ticket: close probe response body: %v", errClose)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return "", resp.StatusCode, nil
	}
	return ExtractCodexTurnState(resp.Header), resp.StatusCode, nil
}

// codexTurnTicketProbeDrainLimit caps how much of a probe response is discarded. The
// probe only needs the headers, so a response larger than this is abandoned rather than
// read to completion.
const codexTurnTicketProbeDrainLimit = 64 * 1024

// codexTurnTicketBaseURL resolves the Codex backend URL for an auth, matching the
// executor's own default so the probe cannot target a different backend than the
// credential it harvests for.
func codexTurnTicketBaseURL(auth *cliproxyauth.Auth) string {
	if auth != nil && auth.Attributes != nil {
		if base := strings.TrimSpace(auth.Attributes["base_url"]); base != "" {
			return base
		}
	}
	return codexTurnTicketDefaultBaseURL
}

// applyCodexTurnTicketProbeIdentity dresses the probe as the official Codex client. The
// upstream mints turn-state only for recognized client identities, and the account ID
// header is required for OAuth credentials that belong to a workspace.
func applyCodexTurnTicketProbeIdentity(headers http.Header, auth *cliproxyauth.Auth, model string) {
	if headers == nil {
		return
	}
	// Codex builds newer than the catalog default gate the newest models behind a minimum
	// version, so an older advertised version silently turns the probe into a rejection
	// instead of a ticket.
	version := constant.CodexClientVersion
	if codexTurnTicketNeedsMinimumVersion(model) && codexTurnTicketVersionLess(version, codexTurnTicketAstraMinVersion) {
		version = codexTurnTicketAstraMinVersion
	}
	// Version and User-Agent are written together from one value so the upstream never sees
	// a client that contradicts itself.
	headers.Set("Version", version)
	headers.Set("User-Agent", constant.CodexOriginator+"/"+version+" (Linux 7.0.0-28; x86_64) rust")
	headers.Set("Originator", constant.CodexOriginator)
	headers.Set("session_id", uuid.NewString())
	if auth != nil && auth.Metadata != nil {
		if accountID, ok := auth.Metadata["account_id"].(string); ok {
			if trimmed := strings.TrimSpace(accountID); trimmed != "" {
				headers.Set("ChatGPT-Account-Id", trimmed)
			}
		}
	}
}

// codexTurnTicketAstraMinVersion is the oldest Codex client version that the newest
// models accept, mirroring the version the upstream documents for gpt-6 assets.
const codexTurnTicketAstraMinVersion = "0.153.4"

// codexTurnTicketVersionLess compares two dotted numeric versions. It returns true only
// when left is a well-formed version strictly older than right; anything it cannot parse
// reports false, so an unknown version is never "upgraded" on a guess.
func codexTurnTicketVersionLess(left, right string) bool {
	leftParts, okLeft := codexTurnTicketVersionParts(left)
	rightParts, okRight := codexTurnTicketVersionParts(right)
	if !okLeft || !okRight {
		return false
	}
	for i := 0; i < len(leftParts) || i < len(rightParts); i++ {
		var l, r int
		if i < len(leftParts) {
			l = leftParts[i]
		}
		if i < len(rightParts) {
			r = rightParts[i]
		}
		if l != r {
			return l < r
		}
	}
	return false
}

func codexTurnTicketVersionParts(raw string) ([]int, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, false
	}
	segments := strings.Split(trimmed, ".")
	parts := make([]int, 0, len(segments))
	for _, segment := range segments {
		value, errParse := strconv.Atoi(strings.TrimSpace(segment))
		if errParse != nil || value < 0 {
			return nil, false
		}
		parts = append(parts, value)
	}
	return parts, true
}

// codexTurnTicketNeedsMinimumVersion reports whether model is one of the newest models
// that reject older Codex client identities.
func codexTurnTicketNeedsMinimumVersion(model string) bool {
	lowered := strings.ToLower(strings.TrimSpace(model))
	return strings.Contains(lowered, "gpt-6") || strings.Contains(lowered, "astra")
}

// ExtractCodexTurnState reads the turn-state token from an upstream response header.
func ExtractCodexTurnState(header http.Header) string {
	if header == nil {
		return ""
	}
	return strings.TrimSpace(header.Get(CodexTurnStateHeader))
}

// IsHealthyCodexTurnState reports whether state is a well-formed healthy ticket.
func IsHealthyCodexTurnState(state string, targetLength int) bool {
	state = strings.TrimSpace(state)
	if state == "" || !strings.HasPrefix(state, codexTurnTicketStatePrefix) {
		return false
	}
	return targetLength <= 0 || len(state) == targetLength
}

// HarvestCodexTurnStatePassively records a ticket the upstream minted for live traffic.
// This costs no extra quota and keeps buckets fresh while the harvester is idle.
func (h *CodexTurnTicketHarvester) HarvestCodexTurnStatePassively(auth *cliproxyauth.Auth, model string, header http.Header) {
	if h == nil || h.store == nil || auth == nil {
		return
	}
	effective := EffectiveCodexTurnTicketConfig(h.cfg)
	if !effective.Enabled || !codexTurnTicketModelGated(effective, model) {
		return
	}
	state := ExtractCodexTurnState(header)
	if !IsHealthyCodexTurnState(state, effective.TargetLength) {
		return
	}
	now := time.Now()
	ticket := NewCodexTurnTicket(state, now, time.Duration(effective.TTLSeconds)*time.Second)
	if ticket == nil || !ticket.valid(now, effective.TargetLength) {
		return
	}
	h.store.Store(auth.ID, model, ticket)
	h.harvested.Add(1)
}

// CodexTurnTicketStats is a snapshot of harvester counters for diagnostics.
type CodexTurnTicketStats struct {
	Probed    int64
	Harvested int64
}

// Stats returns current harvester counters.
func (h *CodexTurnTicketHarvester) Stats() CodexTurnTicketStats {
	if h == nil {
		return CodexTurnTicketStats{}
	}
	return CodexTurnTicketStats{Probed: h.probed.Load(), Harvested: h.harvested.Load()}
}

// CodexTurnTicketProcess is the process-wide ticket store and harvester wiring used by
// the Codex executors. The process-level holder keeps the injector available on the hot
// path without threading the store through every executor call site.
type CodexTurnTicketProcess struct {
	Store     *CodexTurnTicketStore
	Harvester *CodexTurnTicketHarvester
	Injector  *CodexTurnTicketInjector
}

var codexTurnTicketProcess atomic.Pointer[CodexTurnTicketProcess]

// ConfigureCodexTurnTickets installs the process-wide ticket state. It is called once at
// service start; because the injector reads the live config pointer on every request,
// enabling or disabling the feature through config reload takes effect without a restart.
func ConfigureCodexTurnTickets(cfg *config.Config, listAuths func() []*cliproxyauth.Auth) *CodexTurnTicketProcess {
	store := NewCodexTurnTicketStore()
	process := &CodexTurnTicketProcess{
		Store:     store,
		Harvester: NewCodexTurnTicketHarvester(store, cfg, listAuths),
		Injector:  NewCodexTurnTicketInjector(store, cfg),
	}
	codexTurnTicketProcess.Store(process)
	return process
}

// CurrentCodexTurnTickets returns the process-wide ticket state, or nil when unwired.
func CurrentCodexTurnTickets() *CodexTurnTicketProcess {
	return codexTurnTicketProcess.Load()
}

// ApplyCodexTurnTicket injects a stored ticket when the process store is wired.
func ApplyCodexTurnTicket(auth *cliproxyauth.Auth, model string, headers http.Header) {
	process := CurrentCodexTurnTickets()
	if process == nil || process.Injector == nil {
		return
	}
	process.Injector.Apply(auth, model, headers)
}

// HarvestCodexTurnStateOnResponse records a passively observed ticket when wired.
func HarvestCodexTurnStateOnResponse(auth *cliproxyauth.Auth, model string, header http.Header) {
	process := CurrentCodexTurnTickets()
	if process == nil || process.Harvester == nil {
		return
	}
	process.Harvester.HarvestCodexTurnStatePassively(auth, model, header)
}

// DescribeCodexTurnTickets renders a redacted one-line summary for logs. It never emits
// token material, only counts and bucket keys.
func DescribeCodexTurnTickets() string {
	process := CurrentCodexTurnTickets()
	if process == nil {
		return "codex turn tickets: not configured"
	}
	stats := process.Harvester.Stats()
	return fmt.Sprintf("codex turn tickets: probed=%d harvested=%d", stats.Probed, stats.Harvested)
}
