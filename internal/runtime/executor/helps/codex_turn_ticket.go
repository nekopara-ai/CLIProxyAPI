package helps

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"sort"
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

// validForExecution keeps a small safety margin between selection and upstream I/O so a
// ticket cannot expire while the request is being prepared after the auth manager admits
// the bucket.
func (t *CodexTurnTicket) validForExecution(now time.Time, targetLength int) bool {
	return t.valid(now, targetLength) && t.ExpiresAt.After(now.Add(30*time.Second))
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

// CodexTurnTicketStore keeps captured tickets in memory, bucketed by (auth ID, model),
// and optionally mirrors them to one private atomic file so restarts do not discard a
// healthy ticket that the upstream may no longer be willing to mint.
type CodexTurnTicketStore struct {
	mu              sync.RWMutex
	tickets         map[string]*CodexTurnTicket
	persistedExpiry map[string]time.Time
	persistencePath string
	restored        int
}

type codexTurnTicketDiskRecord struct {
	AuthID string `json:"auth_id"`
	Model  string `json:"model"`
	*CodexTurnTicket
}

type codexTurnTicketDiskFile struct {
	Version   int                         `json:"version"`
	UpdatedAt time.Time                   `json:"updated_at"`
	Tickets   []codexTurnTicketDiskRecord `json:"tickets"`
}

const codexTurnTicketDiskVersion = 1

// codexTurnTicketPersistAdvance limits synchronous fsync work on the live response path.
// A newly healthy bucket is persisted immediately; an already checkpointed bucket is
// refreshed after its replayable lifetime has advanced by at least this much. The in-memory
// ticket is still updated on every healthy response.
const codexTurnTicketPersistAdvance = time.Minute

// NewCodexTurnTicketStore returns an empty in-memory ticket store.
func NewCodexTurnTicketStore() *CodexTurnTicketStore {
	return &CodexTurnTicketStore{
		tickets:         make(map[string]*CodexTurnTicket),
		persistedExpiry: make(map[string]time.Time),
	}
}

// NewPersistentCodexTurnTicketStore restores valid tickets from path and checkpoints new
// buckets immediately, with bounded refresh writes for already-persisted buckets. A corrupt
// or missing file safely starts empty; fail-closed routing then keeps unprotected buckets
// away from live traffic while the harvester repairs them.
func NewPersistentCodexTurnTicketStore(path string, targetLength int, ttl time.Duration) *CodexTurnTicketStore {
	store := NewCodexTurnTicketStore()
	store.persistencePath = strings.TrimSpace(path)
	if store.persistencePath == "" {
		return store
	}
	if errLoad := store.load(targetLength, ttl); errLoad != nil {
		log.Warnf("codex turn tickets: persistent store could not be restored: %v", errLoad)
	}
	return store
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
	key := codexTurnTicketKey(authID, model)
	s.mu.Lock()
	if s.tickets == nil {
		s.tickets = make(map[string]*CodexTurnTicket)
	}
	s.tickets[key] = &copied
	if !s.ticketNeedsCheckpointLocked(key, &copied) {
		s.mu.Unlock()
		return
	}
	if errPersist := s.persistLocked(); errPersist != nil {
		log.Errorf("codex turn tickets: persist healthy ticket: %v", errPersist)
	}
	s.mu.Unlock()
}

func (s *CodexTurnTicketStore) ticketNeedsCheckpointLocked(key string, ticket *CodexTurnTicket) bool {
	if s == nil || ticket == nil || strings.TrimSpace(s.persistencePath) == "" {
		return false
	}
	persisted := s.persistedExpiry[key]
	if persisted.IsZero() {
		return true
	}
	return !ticket.ExpiresAt.Before(persisted.Add(codexTurnTicketPersistAdvance))
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
	if errPersist := s.persistLocked(); errPersist != nil {
		log.Errorf("codex turn tickets: persist ticket removal: %v", errPersist)
	}
	s.mu.Unlock()
}

func splitCodexTurnTicketKey(key string) (string, string, bool) {
	parts := strings.SplitN(key, "\x00", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func (s *CodexTurnTicketStore) load(targetLength int, ttl time.Duration) error {
	data, errRead := os.ReadFile(s.persistencePath)
	if errors.Is(errRead, os.ErrNotExist) {
		return nil
	}
	if errRead != nil {
		return fmt.Errorf("read persistent store: %w", errRead)
	}
	var disk codexTurnTicketDiskFile
	if errUnmarshal := json.Unmarshal(data, &disk); errUnmarshal != nil {
		return fmt.Errorf("parse persistent store: %w", errUnmarshal)
	}
	if disk.Version != codexTurnTicketDiskVersion {
		return fmt.Errorf("unsupported persistent store version %d", disk.Version)
	}
	now := time.Now()
	for _, record := range disk.Tickets {
		authID := strings.TrimSpace(record.AuthID)
		model := strings.TrimSpace(record.Model)
		if authID == "" || model == "" || record.CodexTurnTicket == nil {
			continue
		}
		capturedAt := record.CapturedAt
		if capturedAt.IsZero() {
			capturedAt = now
		}
		restored := NewCodexTurnTicket(record.State, capturedAt, ttl)
		if restored == nil || !restored.valid(now, targetLength) {
			continue
		}
		s.tickets[codexTurnTicketKey(authID, model)] = restored
		s.persistedExpiry[codexTurnTicketKey(authID, model)] = restored.ExpiresAt
		s.restored++
	}
	if errChmod := os.Chmod(s.persistencePath, 0o600); errChmod != nil {
		return fmt.Errorf("secure persistent store permissions: %w", errChmod)
	}
	return nil
}

// persistLocked atomically replaces the private store. s.mu must be held by the caller.
func (s *CodexTurnTicketStore) persistLocked() error {
	if s == nil || strings.TrimSpace(s.persistencePath) == "" {
		return nil
	}
	records := make([]codexTurnTicketDiskRecord, 0, len(s.tickets))
	for key, ticket := range s.tickets {
		authID, model, ok := splitCodexTurnTicketKey(key)
		if !ok || ticket == nil {
			continue
		}
		copied := *ticket
		records = append(records, codexTurnTicketDiskRecord{AuthID: authID, Model: model, CodexTurnTicket: &copied})
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].AuthID != records[j].AuthID {
			return records[i].AuthID < records[j].AuthID
		}
		return records[i].Model < records[j].Model
	})
	disk := codexTurnTicketDiskFile{Version: codexTurnTicketDiskVersion, UpdatedAt: time.Now().UTC(), Tickets: records}
	data, errMarshal := json.MarshalIndent(disk, "", "  ")
	if errMarshal != nil {
		return fmt.Errorf("marshal persistent store: %w", errMarshal)
	}
	data = append(data, '\n')
	dir := filepath.Dir(s.persistencePath)
	if errMkdir := os.MkdirAll(dir, 0o700); errMkdir != nil {
		return fmt.Errorf("create persistent store directory: %w", errMkdir)
	}
	tmpFile, errCreate := os.CreateTemp(dir, filepath.Base(s.persistencePath)+".*.tmp")
	if errCreate != nil {
		return fmt.Errorf("create persistent store temp file: %w", errCreate)
	}
	tmpPath := tmpFile.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	if errChmod := tmpFile.Chmod(0o600); errChmod != nil {
		_ = tmpFile.Close()
		cleanup()
		return fmt.Errorf("secure persistent store temp file: %w", errChmod)
	}
	if _, errWrite := tmpFile.Write(data); errWrite != nil {
		_ = tmpFile.Close()
		cleanup()
		return fmt.Errorf("write persistent store temp file: %w", errWrite)
	}
	if errSync := tmpFile.Sync(); errSync != nil {
		_ = tmpFile.Close()
		cleanup()
		return fmt.Errorf("sync persistent store temp file: %w", errSync)
	}
	if errClose := tmpFile.Close(); errClose != nil {
		cleanup()
		return fmt.Errorf("close persistent store temp file: %w", errClose)
	}
	if errRename := os.Rename(tmpPath, s.persistencePath); errRename != nil {
		cleanup()
		return fmt.Errorf("replace persistent store: %w", errRename)
	}
	if errChmod := os.Chmod(s.persistencePath, 0o600); errChmod != nil {
		return fmt.Errorf("secure persistent store: %w", errChmod)
	}
	// Sync the containing directory after rename so the new filename is durable across
	// an abrupt reboot, not only across an orderly process restart.
	dirHandle, errOpenDir := os.Open(dir)
	if errOpenDir != nil {
		return fmt.Errorf("open persistent store directory: %w", errOpenDir)
	}
	if errSyncDir := dirHandle.Sync(); errSyncDir != nil {
		_ = dirHandle.Close()
		return fmt.Errorf("sync persistent store directory: %w", errSyncDir)
	}
	if errCloseDir := dirHandle.Close(); errCloseDir != nil {
		return fmt.Errorf("close persistent store directory: %w", errCloseDir)
	}
	s.persistedExpiry = make(map[string]time.Time, len(records))
	for _, record := range records {
		if record.CodexTurnTicket == nil {
			continue
		}
		s.persistedExpiry[codexTurnTicketKey(record.AuthID, record.Model)] = record.ExpiresAt
	}
	return nil
}

func (s *CodexTurnTicketStore) restoredCount() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.restored
}

func (s *CodexTurnTicketStore) persistent() bool {
	return s != nil && strings.TrimSpace(s.persistencePath) != ""
}

// CodexTurnTicketConfig is the effective, normalized ticket configuration.
type CodexTurnTicketConfig struct {
	Enabled              bool
	FailClosed           bool
	TargetLength         int
	TTLSeconds           int
	RefreshBeforeSeconds int
	ProbeIntervalSeconds int
	ProbeTimeoutSeconds  int
	ProbeCooldownSeconds int
	RejectBackoffSeconds int
	HarvestProxyURLs     []string
	Models               []string
	AuthIDs              []string
}

// CodexTurnTicketDefaults lists the model buckets probed when the operator does not
// name any. Only models the upstream actually mints tickets for are useful here.
var CodexTurnTicketDefaults = []string{"gpt-5.5", "gpt-5.6-sol", "gpt-5.6-terra", "gpt-6-astra"}

// EffectiveCodexTurnTicketConfig normalizes cfg.Codex.TurnTicket with defaults.
func EffectiveCodexTurnTicketConfig(cfg *config.Config) CodexTurnTicketConfig {
	effective := CodexTurnTicketConfig{
		FailClosed:           true,
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
	if raw.FailClosed != nil {
		effective.FailClosed = *raw.FailClosed
	}
	for _, candidate := range raw.HarvestProxyURLs {
		if trimmed := strings.TrimSpace(candidate); trimmed != "" {
			effective.HarvestProxyURLs = append(effective.HarvestProxyURLs, trimmed)
		}
	}
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

func codexTurnTicketAuthScoped(effective CodexTurnTicketConfig, authID string) bool {
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return false
	}
	if len(effective.AuthIDs) == 0 {
		return true
	}
	for _, candidate := range effective.AuthIDs {
		if strings.TrimSpace(candidate) == authID {
			return true
		}
	}
	return false
}

// codexTurnTicketEffectiveConfig resolves the effective config through the live provider.
// A nil provider means "no configuration": the feature stays disabled with defaults, which
// is the same state as an explicit empty config.
func codexTurnTicketEffectiveConfig(provider func() *config.Config) CodexTurnTicketConfig {
	if provider == nil {
		return EffectiveCodexTurnTicketConfig(nil)
	}
	return EffectiveCodexTurnTicketConfig(provider())
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
	// cfgProvider returns the live service config. The injector resolves it on every call
	// instead of capturing a startup snapshot, so a config reload flips injection on or off
	// without rebuilding the process-wide wiring.
	cfgProvider func() *config.Config
}

// NewCodexTurnTicketInjector returns an injector over store, reading live config through
// cfgProvider on every Apply call.
func NewCodexTurnTicketInjector(store *CodexTurnTicketStore, cfgProvider func() *config.Config) *CodexTurnTicketInjector {
	return &CodexTurnTicketInjector{store: store, cfgProvider: cfgProvider}
}

// Apply overwrites X-Codex-Turn-State on the outbound headers with the ticket captured
// for this (auth, model) bucket. It is a no-op unless the feature is enabled and the
// model participates; when no usable ticket exists the client-supplied header is left
// untouched, matching pass-through behaviour.
func (i *CodexTurnTicketInjector) Apply(auth *cliproxyauth.Auth, model string, headers http.Header) bool {
	if i == nil || i.store == nil || headers == nil || auth == nil {
		return false
	}
	effective := codexTurnTicketEffectiveConfig(i.cfgProvider)
	if !effective.Enabled || !codexTurnTicketModelGated(effective, model) || !codexTurnTicketAuthScoped(effective, auth.ID) {
		return false
	}
	ticket := i.store.Lookup(auth.ID, model)
	if !ticket.validForExecution(time.Now(), effective.TargetLength) {
		return false
	}
	// Overwrite rather than merge: the request must carry exactly one turn-state, and a
	// stale client-supplied value would otherwise win on case-insensitive lookup.
	headers.Del(CodexTurnStateHeader)
	headers.Set(CodexTurnStateHeader, ticket.State)
	return true
}

// CodexTurnTicketHarvester probes Codex accounts through a dedicated explicit egress and
// records healthy turn-state tickets. It never refreshes credentials and never touches
// consumer traffic, so it cannot disturb the live request path.
type CodexTurnTicketHarvester struct {
	store *CodexTurnTicketStore
	// cfgProvider returns the live service config, so enabling or retuning the feature
	// through a config reload is picked up by the next harvest cycle.
	cfgProvider func() *config.Config

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

	observationMu sync.RWMutex
	observations  map[string]CodexTurnTicketObservation

	probeInFlight sync.Mutex
	probed        atomic.Int64
	harvested     atomic.Int64
}

// NewCodexTurnTicketHarvester returns a harvester bound to store and listAuths, reading
// live config through cfgProvider on every cycle.
func NewCodexTurnTicketHarvester(store *CodexTurnTicketStore, cfgProvider func() *config.Config, listAuths func() []*cliproxyauth.Auth) *CodexTurnTicketHarvester {
	return &CodexTurnTicketHarvester{
		store:        store,
		cfgProvider:  cfgProvider,
		listAuths:    listAuths,
		nextProbe:    make(map[string]time.Time),
		backoffRun:   make(map[string]time.Time),
		observations: make(map[string]CodexTurnTicketObservation),
	}
}

// Start launches the background probe loop. It is idempotent.
//
// The loop is launched even when the feature is currently disabled, because the operator
// may enable it later through a config reload. Each cycle re-reads the live config, so a
// disabled cycle is a cheap no-op and an enabled cycle starts probing without a restart.
func (h *CodexTurnTicketHarvester) Start(ctx context.Context) {
	if h == nil {
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
	for {
		// Re-read the live config every cycle so a reload can change the probe interval, or
		// turn probing on and off, without restarting the service.
		effective := codexTurnTicketEffectiveConfig(h.cfgProvider)
		interval := time.Duration(effective.ProbeIntervalSeconds) * time.Second
		if interval <= 0 {
			interval = time.Minute
		}
		h.probeAll(ctx)
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-stop:
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (h *CodexTurnTicketHarvester) probeAll(ctx context.Context) {
	if h == nil || h.listAuths == nil || h.store == nil {
		return
	}
	effective := codexTurnTicketEffectiveConfig(h.cfgProvider)
	if !effective.Enabled || len(effective.HarvestProxyURLs) == 0 {
		return
	}
	scope := make(map[string]struct{}, len(effective.AuthIDs))
	for _, authID := range effective.AuthIDs {
		scope[authID] = struct{}{}
	}
	now := time.Now()
	refreshBefore := time.Duration(effective.RefreshBeforeSeconds) * time.Second
	for _, auth := range h.listAuths() {
		if auth == nil || auth.Disabled || auth.Status != cliproxyauth.StatusActive || !isCodexOAuthAuth(auth) {
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
	return isCodexOAuthCredential(auth) && strings.TrimSpace(codexAuthAccessToken(auth)) != ""
}

func isCodexOAuthCredential(auth *cliproxyauth.Auth) bool {
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
	return true
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
	egress := chooseCodexTurnTicketHarvestEgress(effective.HarvestProxyURLs)
	startedAt := time.Now()
	state, status, errProbe := probeCodexTurnStateThroughEgress(ctx, auth, model, effective, egress)
	logFields := log.Fields{
		"auth_hint":  codexTurnTicketAuthHint(auth),
		"model":      strings.TrimSpace(model),
		"egress":     codexTurnTicketHarvestEgressLabel(egress),
		"elapsed_ms": time.Since(startedAt).Milliseconds(),
	}
	if errProbe != nil {
		h.recordObservation(auth.ID, model, CodexTurnTicketObservation{ObservedAt: time.Now(), Result: "error"})
		logFields["result"] = "error"
		logFields["error_class"] = codexTurnTicketProbeErrorClass(errProbe)
		logFields["next_action"] = "retry_next_cycle"
		logFields["retry_after_seconds"] = effective.ProbeIntervalSeconds
		log.WithFields(logFields).Info("codex turn ticket: active probe completed")
		return
	}
	trimmedState := strings.TrimSpace(state)
	healthy := IsHealthyCodexTurnState(trimmedState, effective.TargetLength)
	logFields["http_status"] = status
	logFields["state_length"] = len(trimmedState)
	logFields["healthy"] = healthy
	h.recordObservation(auth.ID, model, CodexTurnTicketObservation{
		ObservedAt:  time.Now(),
		StatusCode:  status,
		StateLength: len(trimmedState),
		Healthy:     healthy,
		Result:      "probe",
	})
	// A rejection is not a miss. 429 means the credential is being asked to mint too
	// often, and 401/403 mean the credential itself is unusable; probing again without
	// waiting turns either into a sustained burst that harms every bucket sharing the
	// credential, so the bucket parks for the configured backoff instead.
	if status == http.StatusTooManyRequests || status == http.StatusUnauthorized || status == http.StatusForbidden {
		backoffUntil := time.Now().Add(time.Duration(effective.RejectBackoffSeconds) * time.Second)
		h.parkBucket(auth.ID, model, backoffUntil)
		logFields["result"] = "rejected"
		logFields["next_action"] = "backoff"
		logFields["retry_after_seconds"] = effective.RejectBackoffSeconds
		logFields["retry_at"] = backoffUntil.UTC().Format(time.RFC3339)
		log.WithFields(logFields).Info("codex turn ticket: active probe completed")
		return
	}
	ticket := NewCodexTurnTicket(state, time.Now(), time.Duration(effective.TTLSeconds)*time.Second)
	if ticket == nil || !ticket.valid(time.Now(), effective.TargetLength) {
		switch {
		case status != http.StatusOK:
			logFields["result"] = "http_error"
		case len(trimmedState) == 0:
			logFields["result"] = "missing_ticket"
		default:
			logFields["result"] = "unhealthy_ticket"
		}
		logFields["next_action"] = "retry_next_cycle"
		logFields["retry_after_seconds"] = effective.ProbeIntervalSeconds
		log.WithFields(logFields).Info("codex turn ticket: active probe completed")
		return
	}
	h.store.Store(auth.ID, model, ticket)
	cooldownUntil := time.Now().Add(time.Duration(effective.ProbeCooldownSeconds) * time.Second)
	h.setProbeCooldown(auth.ID, model, cooldownUntil)
	h.harvested.Add(1)
	logFields["result"] = "healthy_ticket"
	logFields["next_action"] = "cooldown"
	logFields["retry_after_seconds"] = effective.ProbeCooldownSeconds
	logFields["retry_at"] = cooldownUntil.UTC().Format(time.RFC3339)
	logFields["ticket_expires_at"] = ticket.ExpiresAt.UTC().Format(time.RFC3339)
	log.WithFields(logFields).Info("codex turn ticket: active probe completed")
}

func codexTurnTicketHarvestEgressLabel(egress string) string {
	trimmed := strings.TrimSpace(egress)
	if strings.EqualFold(trimmed, "direct") || strings.EqualFold(trimmed, "none") {
		return "direct"
	}
	return proxyutil.Redact(trimmed)
}

func codexTurnTicketProbeErrorClass(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, ErrCodexTurnTicketProbeSkipped):
		return "skipped"
	default:
		return "transport_error"
	}
}

// reserveProbeSlot reports whether a bucket may be probed now. Rejections retain their
// backoff, while the long cooldown is armed only after a healthy harvest. A plain miss,
// including a 312 turn state, is therefore retried on the next harvest cycle.
func (h *CodexTurnTicketHarvester) reserveProbeSlot(authID, model string, now time.Time, effective CodexTurnTicketConfig) bool {
	if h == nil {
		return false
	}
	key := codexTurnTicketKey(authID, model)
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
	return true
}

func (h *CodexTurnTicketHarvester) setProbeCooldown(authID, model string, until time.Time) {
	if h == nil {
		return
	}
	h.scheduleMu.Lock()
	h.nextProbe[codexTurnTicketKey(authID, model)] = until
	h.scheduleMu.Unlock()
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

// CodexTurnTicketObservation is a redacted last-seen probe result. It records only status
// and token length, never the token itself.
type CodexTurnTicketObservation struct {
	ObservedAt  time.Time `json:"observed_at"`
	StatusCode  int       `json:"status_code,omitempty"`
	StateLength int       `json:"state_length,omitempty"`
	Healthy     bool      `json:"healthy"`
	Result      string    `json:"result,omitempty"`
}

func (h *CodexTurnTicketHarvester) recordObservation(authID, model string, observation CodexTurnTicketObservation) {
	if h == nil {
		return
	}
	h.observationMu.Lock()
	if h.observations == nil {
		h.observations = make(map[string]CodexTurnTicketObservation)
	}
	h.observations[codexTurnTicketKey(authID, model)] = observation
	h.observationMu.Unlock()
}

func (h *CodexTurnTicketHarvester) observation(authID, model string) CodexTurnTicketObservation {
	if h == nil {
		return CodexTurnTicketObservation{}
	}
	h.observationMu.RLock()
	observation := h.observations[codexTurnTicketKey(authID, model)]
	h.observationMu.RUnlock()
	return observation
}

// ProbeCodexTurnState issues one synthetic request through the configured harvest egress
// (either an explicit proxy or an explicit direct connection) and returns
// the healthy turn-state token the upstream minted, if any, together with the HTTP status
// so the caller can tell a rejection from a plain miss.
func ProbeCodexTurnState(ctx context.Context, auth *cliproxyauth.Auth, model string, effective CodexTurnTicketConfig) (string, int, error) {
	egress := chooseCodexTurnTicketHarvestEgress(effective.HarvestProxyURLs)
	return probeCodexTurnStateThroughEgress(ctx, auth, model, effective, egress)
}

func probeCodexTurnStateThroughEgress(ctx context.Context, auth *cliproxyauth.Auth, model string, effective CodexTurnTicketConfig, egress string) (string, int, error) {
	if auth == nil {
		return "", 0, ErrCodexTurnTicketProbeSkipped
	}
	token := codexAuthAccessToken(auth)
	if token == "" {
		return "", 0, ErrCodexTurnTicketProbeSkipped
	}
	if egress == "" {
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
	return probeCodexTurnStateWithClient(probeCtx, auth, token, model, egress)
}

// chooseCodexTurnTicketHarvestEgress selects one configured egress independently for each
// probe. Configuration normalization removes blank entries before this point.
func chooseCodexTurnTicketHarvestEgress(egresses []string) string {
	if len(egresses) == 0 {
		return ""
	}
	if len(egresses) == 1 {
		return strings.TrimSpace(egresses[0])
	}
	return strings.TrimSpace(egresses[rand.IntN(len(egresses))])
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
		return nil, fmt.Errorf("codex turn ticket: build harvest egress transport: %w", errBuild)
	}
	// The egress must be explicit. ModeDirect intentionally bypasses HTTP_PROXY and
	// HTTPS_PROXY, while ModeProxy uses the configured endpoint. ModeInherit is rejected
	// because it could silently merge probe traffic with the client-traffic path.
	if (mode != proxyutil.ModeProxy && mode != proxyutil.ModeDirect) || transport == nil {
		return nil, fmt.Errorf("codex turn ticket: harvest egress %q is not an explicit direct or proxy setting", proxyutil.Redact(proxyURL))
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
	effective := codexTurnTicketEffectiveConfig(h.cfgProvider)
	if !effective.Enabled || !codexTurnTicketModelGated(effective, model) || !codexTurnTicketAuthScoped(effective, auth.ID) {
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
	h.recordObservation(auth.ID, model, CodexTurnTicketObservation{
		ObservedAt:  now,
		StatusCode:  http.StatusOK,
		StateLength: len(state),
		Healthy:     true,
		Result:      "passive",
	})
	h.harvested.Add(1)
}

// CodexTurnTicketStats is a snapshot of harvester counters and store occupancy for
// diagnostics. It never carries token material or credential identifiers.
type CodexTurnTicketStats struct {
	Probed    int64 `json:"probed"`
	Harvested int64 `json:"harvested"`
	Buckets   int   `json:"buckets"`
	Healthy   int   `json:"healthy_tickets"`
}

// Stats returns current harvester counters together with how many buckets exist and how
// many of them currently hold a replayable ticket.
func (h *CodexTurnTicketHarvester) Stats(targetLength int) CodexTurnTicketStats {
	if h == nil {
		return CodexTurnTicketStats{}
	}
	stats := CodexTurnTicketStats{Probed: h.probed.Load(), Harvested: h.harvested.Load()}
	stats.Buckets, stats.Healthy = h.store.occupancy(time.Now(), targetLength)
	return stats
}

// Running reports whether the background probe loop is currently active.
func (h *CodexTurnTicketHarvester) Running() bool {
	if h == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.running
}

// occupancy reports how many buckets the store holds and how many of them currently hold
// a ticket that is valid for targetLength. It reports counts only, never bucket keys.
func (s *CodexTurnTicketStore) occupancy(now time.Time, targetLength int) (buckets, healthy int) {
	if s == nil {
		return 0, 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, ticket := range s.tickets {
		buckets++
		if ticket.valid(now, targetLength) {
			healthy++
		}
	}
	return buckets, healthy
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
// service start. cfgProvider is consulted on every request and every harvest cycle rather
// than being snapshotted here, so enabling, disabling, or retuning the feature through a
// config reload takes effect without a restart.
//
// A nil cfgProvider clears the process-wide wiring, which tests use to restore the
// unwired state a process has before the service starts.
func ConfigureCodexTurnTickets(cfgProvider func() *config.Config, listAuths func() []*cliproxyauth.Auth) *CodexTurnTicketProcess {
	if cfgProvider == nil {
		codexTurnTicketProcess.Store(nil)
		return nil
	}
	initialCfg := cfgProvider()
	effective := EffectiveCodexTurnTicketConfig(initialCfg)
	store := NewPersistentCodexTurnTicketStore(codexTurnTicketPersistencePath(initialCfg), effective.TargetLength, time.Duration(effective.TTLSeconds)*time.Second)
	process := &CodexTurnTicketProcess{
		Store:     store,
		Harvester: NewCodexTurnTicketHarvester(store, cfgProvider, listAuths),
		Injector:  NewCodexTurnTicketInjector(store, cfgProvider),
	}
	codexTurnTicketProcess.Store(process)
	return process
}

const codexTurnTicketPersistenceFile = ".codex-turn-tickets"

func codexTurnTicketPersistencePath(cfg *config.Config) string {
	if cfg == nil || strings.TrimSpace(cfg.AuthDir) == "" {
		return ""
	}
	return filepath.Join(strings.TrimSpace(cfg.AuthDir), codexTurnTicketPersistenceFile)
}

// CurrentCodexTurnTickets returns the process-wide ticket state, or nil when unwired.
func CurrentCodexTurnTickets() *CodexTurnTicketProcess {
	return codexTurnTicketProcess.Load()
}

// ApplyCodexTurnTicket injects a stored ticket when the process store is wired.
func ApplyCodexTurnTicket(auth *cliproxyauth.Auth, model string, headers http.Header) bool {
	process := CurrentCodexTurnTickets()
	if process == nil || process.Injector == nil {
		return false
	}
	return process.Injector.Apply(auth, model, headers)
}

// CodexTurnTicketAllowsExecution is installed into the auth manager as a resolved-model
// guard. With fail-closed enabled, a Codex OAuth credential cannot be selected for a
// gated model until its exact bucket contains a healthy persisted or freshly harvested
// ticket. Unrelated providers, API-key credentials, and ungated models are unaffected.
func CodexTurnTicketAllowsExecution(auth *cliproxyauth.Auth, model string) bool {
	process := CurrentCodexTurnTickets()
	if process == nil || process.Store == nil || process.Harvester == nil || auth == nil {
		return true
	}
	effective := codexTurnTicketEffectiveConfig(process.Harvester.cfgProvider)
	if !effective.Enabled || !effective.FailClosed || !isCodexOAuthCredential(auth) ||
		!codexTurnTicketModelGated(effective, model) || !codexTurnTicketAuthScoped(effective, auth.ID) {
		return true
	}
	return process.Store.Lookup(auth.ID, model).validForExecution(time.Now(), effective.TargetLength)
}

// HarvestCodexTurnStateOnResponse records a passively observed ticket when wired.
func HarvestCodexTurnStateOnResponse(auth *cliproxyauth.Auth, model string, header http.Header) {
	process := CurrentCodexTurnTickets()
	if process == nil || process.Harvester == nil {
		return
	}
	process.Harvester.HarvestCodexTurnStatePassively(auth, model, header)
}

// CodexTurnTicketSnapshot is a redacted, serializable view of the turn-ticket subsystem
// for the management API. It never contains token material or credential identifiers.
type CodexTurnTicketSnapshot struct {
	Configured        bool                            `json:"configured"`
	Enabled           bool                            `json:"enabled"`
	FailClosed        bool                            `json:"fail_closed"`
	HarvesterActive   bool                            `json:"harvester_active"`
	Models            []string                        `json:"models"`
	AuthIDScoped      bool                            `json:"auth_id_scoped"`
	TargetLength      int                             `json:"target_length"`
	TTLSeconds        int                             `json:"ttl_seconds"`
	RefreshBefore     int                             `json:"refresh_before_seconds"`
	ProbeInterval     int                             `json:"probe_interval_seconds"`
	ProbeCooldown     int                             `json:"probe_cooldown_seconds"`
	RejectBackoff     int                             `json:"reject_backoff_seconds"`
	HarvestProxyCount int                             `json:"harvest_proxy_count"`
	HarvestProxyURLs  []string                        `json:"harvest_proxy_urls,omitempty"`
	Probed            int64                           `json:"probed"`
	Harvested         int64                           `json:"harvested"`
	Buckets           int                             `json:"buckets"`
	HealthyTickets    int                             `json:"healthy_tickets"`
	PersistentStore   bool                            `json:"persistent_store"`
	RestoredTickets   int                             `json:"restored_tickets"`
	BucketStates      []CodexTurnTicketBucketSnapshot `json:"bucket_states,omitempty"`
}

// CodexTurnTicketBucketSnapshot is a credential-safe per-model view. AuthHint is either
// a masked OAuth email or a short one-way hash; raw IDs and ticket material are omitted.
type CodexTurnTicketBucketSnapshot struct {
	AuthHint            string    `json:"auth_hint"`
	Model               string    `json:"model"`
	TicketState         string    `json:"ticket_state"`
	TicketLength        int       `json:"ticket_length,omitempty"`
	ExpiresAt           time.Time `json:"expires_at,omitempty"`
	LastObservedAt      time.Time `json:"last_observed_at,omitempty"`
	LastHTTPStatus      int       `json:"last_http_status,omitempty"`
	LastObservedLength  int       `json:"last_observed_length,omitempty"`
	LastObservedHealthy bool      `json:"last_observed_healthy"`
	LastResult          string    `json:"last_result,omitempty"`
}

// CodexTurnTicketCredentialSnapshot is the management-facing ticket state for one
// concrete credential. It is safe to attach to the already privileged auth-files
// response because it contains no ticket material; the surrounding auth-file entry
// already carries the credential ID used for the association.
type CodexTurnTicketCredentialSnapshot struct {
	Configured        bool                           `json:"configured"`
	Enabled           bool                           `json:"enabled"`
	HarvesterActive   bool                           `json:"harvester_active"`
	TargetLength      int                            `json:"target_length"`
	State             string                         `json:"state"`
	HealthyModels     int                            `json:"healthy_models"`
	TotalModels       int                            `json:"total_models"`
	EarliestExpiresAt time.Time                      `json:"earliest_expires_at,omitempty"`
	ModelStates       []CodexTurnTicketModelSnapshot `json:"models,omitempty"`
}

// CodexTurnTicketModelSnapshot describes one model bucket without repeating the
// credential hint used by the global redacted snapshot.
type CodexTurnTicketModelSnapshot struct {
	Model               string    `json:"model"`
	TicketState         string    `json:"ticket_state"`
	TicketLength        int       `json:"ticket_length,omitempty"`
	ExpiresAt           time.Time `json:"expires_at,omitempty"`
	LastObservedAt      time.Time `json:"last_observed_at,omitempty"`
	LastHTTPStatus      int       `json:"last_http_status,omitempty"`
	LastObservedLength  int       `json:"last_observed_length,omitempty"`
	LastObservedHealthy bool      `json:"last_observed_healthy"`
	LastResult          string    `json:"last_result,omitempty"`
}

// SnapshotCodexTurnTickets renders the current turn-ticket state for the management API.
func SnapshotCodexTurnTickets() CodexTurnTicketSnapshot {
	process := CurrentCodexTurnTickets()
	if process == nil || process.Harvester == nil {
		return CodexTurnTicketSnapshot{Configured: false}
	}
	harvester := process.Harvester
	effective := codexTurnTicketEffectiveConfig(harvester.cfgProvider)
	snapshot := CodexTurnTicketSnapshot{
		Configured:        true,
		Enabled:           effective.Enabled,
		FailClosed:        effective.FailClosed,
		HarvesterActive:   harvester.Running(),
		Models:            append([]string(nil), effective.Models...),
		AuthIDScoped:      len(effective.AuthIDs) > 0,
		TargetLength:      effective.TargetLength,
		TTLSeconds:        effective.TTLSeconds,
		RefreshBefore:     effective.RefreshBeforeSeconds,
		ProbeInterval:     effective.ProbeIntervalSeconds,
		ProbeCooldown:     effective.ProbeCooldownSeconds,
		RejectBackoff:     effective.RejectBackoffSeconds,
		HarvestProxyCount: len(effective.HarvestProxyURLs),
		PersistentStore:   process.Store.persistent(),
		RestoredTickets:   process.Store.restoredCount(),
	}
	// Harvest proxy URLs may embed credentials; only redacted forms are ever reported.
	for _, egress := range effective.HarvestProxyURLs {
		snapshot.HarvestProxyURLs = append(snapshot.HarvestProxyURLs, proxyutil.Redact(egress))
	}
	stats := harvester.Stats(effective.TargetLength)
	snapshot.Probed = stats.Probed
	snapshot.Harvested = stats.Harvested
	snapshot.Buckets = stats.Buckets
	snapshot.HealthyTickets = stats.Healthy
	snapshot.BucketStates = harvester.bucketSnapshots(effective)
	return snapshot
}

// SnapshotCodexTurnTicketForAuth returns the current cache/probe state for one Codex
// OAuth credential. Non-Codex and API-key credentials return nil so unrelated auth-file
// entries remain unchanged.
func SnapshotCodexTurnTicketForAuth(auth *cliproxyauth.Auth) *CodexTurnTicketCredentialSnapshot {
	if !isCodexOAuthCredential(auth) {
		return nil
	}
	process := CurrentCodexTurnTickets()
	if process == nil || process.Harvester == nil || process.Store == nil {
		return &CodexTurnTicketCredentialSnapshot{State: "unavailable"}
	}
	harvester := process.Harvester
	effective := codexTurnTicketEffectiveConfig(harvester.cfgProvider)
	snapshot := &CodexTurnTicketCredentialSnapshot{
		Configured:      true,
		Enabled:         effective.Enabled,
		HarvesterActive: harvester.Running(),
		TargetLength:    effective.TargetLength,
		State:           "missing",
	}
	if !effective.Enabled {
		snapshot.State = "disabled"
		return snapshot
	}
	if !codexTurnTicketAuthScoped(effective, auth.ID) {
		snapshot.State = "not_scoped"
		return snapshot
	}

	var expiringModels, invalidModels int
	for _, model := range effective.Models {
		bucket := harvester.bucketSnapshot(auth, model, effective)
		modelState := CodexTurnTicketModelSnapshot{
			Model:               bucket.Model,
			TicketState:         bucket.TicketState,
			TicketLength:        bucket.TicketLength,
			ExpiresAt:           bucket.ExpiresAt,
			LastObservedAt:      bucket.LastObservedAt,
			LastHTTPStatus:      bucket.LastHTTPStatus,
			LastObservedLength:  bucket.LastObservedLength,
			LastObservedHealthy: bucket.LastObservedHealthy,
			LastResult:          bucket.LastResult,
		}
		snapshot.ModelStates = append(snapshot.ModelStates, modelState)
		snapshot.TotalModels++
		switch bucket.TicketState {
		case "healthy":
			snapshot.HealthyModels++
			if snapshot.EarliestExpiresAt.IsZero() || bucket.ExpiresAt.Before(snapshot.EarliestExpiresAt) {
				snapshot.EarliestExpiresAt = bucket.ExpiresAt
			}
		case "expiring":
			expiringModels++
			if snapshot.EarliestExpiresAt.IsZero() || bucket.ExpiresAt.Before(snapshot.EarliestExpiresAt) {
				snapshot.EarliestExpiresAt = bucket.ExpiresAt
			}
		case "expired_or_invalid":
			invalidModels++
		}
	}

	switch {
	case snapshot.TotalModels > 0 && snapshot.HealthyModels == snapshot.TotalModels:
		snapshot.State = "healthy"
	case snapshot.HealthyModels > 0:
		snapshot.State = "partial"
	case expiringModels > 0:
		snapshot.State = "expiring"
	case invalidModels > 0:
		snapshot.State = "expired_or_invalid"
	default:
		snapshot.State = "missing"
	}
	return snapshot
}

func (h *CodexTurnTicketHarvester) bucketSnapshots(effective CodexTurnTicketConfig) []CodexTurnTicketBucketSnapshot {
	if h == nil || h.store == nil || h.listAuths == nil {
		return nil
	}
	now := time.Now()
	out := make([]CodexTurnTicketBucketSnapshot, 0)
	for _, auth := range h.listAuths() {
		if auth == nil || auth.Disabled || auth.Status != cliproxyauth.StatusActive || !isCodexOAuthAuth(auth) || !codexTurnTicketAuthScoped(effective, auth.ID) {
			continue
		}
		for _, model := range effective.Models {
			out = append(out, h.bucketSnapshotAt(auth, model, effective, now))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].AuthHint != out[j].AuthHint {
			return out[i].AuthHint < out[j].AuthHint
		}
		return out[i].Model < out[j].Model
	})
	return out
}

func (h *CodexTurnTicketHarvester) bucketSnapshot(auth *cliproxyauth.Auth, model string, effective CodexTurnTicketConfig) CodexTurnTicketBucketSnapshot {
	return h.bucketSnapshotAt(auth, model, effective, time.Now())
}

func (h *CodexTurnTicketHarvester) bucketSnapshotAt(auth *cliproxyauth.Auth, model string, effective CodexTurnTicketConfig, now time.Time) CodexTurnTicketBucketSnapshot {
	entry := CodexTurnTicketBucketSnapshot{AuthHint: codexTurnTicketAuthHint(auth), Model: model, TicketState: "missing"}
	if h == nil || h.store == nil || auth == nil {
		return entry
	}
	if ticket := h.store.Lookup(auth.ID, model); ticket != nil {
		entry.TicketLength = ticket.Length
		entry.ExpiresAt = ticket.ExpiresAt
		switch {
		case ticket.validForExecution(now, effective.TargetLength):
			entry.TicketState = "healthy"
		case !ticket.valid(now, effective.TargetLength):
			entry.TicketState = "expired_or_invalid"
		default:
			entry.TicketState = "expiring"
		}
	}
	observation := h.observation(auth.ID, model)
	entry.LastObservedAt = observation.ObservedAt
	entry.LastHTTPStatus = observation.StatusCode
	entry.LastObservedLength = observation.StateLength
	entry.LastObservedHealthy = observation.Healthy
	entry.LastResult = observation.Result
	return entry
}

func codexTurnTicketAuthHint(auth *cliproxyauth.Auth) string {
	if auth != nil {
		_, value := auth.AccountInfo()
		if masked := maskCodexTurnTicketEmail(value); masked != "" {
			return masked
		}
	}
	authID := ""
	if auth != nil {
		authID = strings.TrimSpace(auth.ID)
	}
	sum := sha256.Sum256([]byte(authID))
	return "auth-" + hex.EncodeToString(sum[:6])
}

func maskCodexTurnTicketEmail(value string) string {
	value = strings.TrimSpace(value)
	at := strings.LastIndex(value, "@")
	if at <= 0 || at == len(value)-1 {
		return ""
	}
	local, domain := value[:at], value[at+1:]
	prefix := local[:1]
	if len(local) > 1 {
		prefix = local[:2]
	}
	return prefix + "***@" + domain
}

// DescribeCodexTurnTickets renders a redacted one-line summary for logs. It never emits
// token material or credential identifiers, only configuration state and counts.
func DescribeCodexTurnTickets() string {
	snapshot := SnapshotCodexTurnTickets()
	if !snapshot.Configured {
		return "codex turn tickets: not configured"
	}
	return fmt.Sprintf(
		"codex turn tickets: enabled=%t fail_closed=%t harvester_active=%t harvest_egresses=%d persistent=%t restored=%d probed=%d harvested=%d buckets=%d healthy=%d",
		snapshot.Enabled, snapshot.FailClosed, snapshot.HarvesterActive, snapshot.HarvestProxyCount, snapshot.PersistentStore, snapshot.RestoredTickets,
		snapshot.Probed, snapshot.Harvested, snapshot.Buckets, snapshot.HealthyTickets,
	)
}
