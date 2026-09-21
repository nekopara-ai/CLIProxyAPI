Failed to create stream fd: Operation not permitted
Failed to create stream fd: Operation not permitted
Failed to create stream fd: Operation not permitted
package helps

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

// testTurnState builds a syntactically valid Fernet-shaped turn-state of the requested
// total length, stamping issueUnix into the visible nine-byte prefix. The bytes after the
// prefix are not a real ciphertext, which is exactly what the code under test sees in
// production: it never decrypts, it only reads the prefix.
func testTurnState(t *testing.T, issueUnix int64, length int) string {
	t.Helper()
	raw := make([]byte, 0, 96)
	raw = append(raw, fernetTimeVersion)
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(issueUnix))
	raw = append(raw, timestamp...)
	for len(raw)%15 != 0 {
		raw = append(raw, 0)
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	if len(encoded) >= length {
		t.Fatalf("encoded token length %d already exceeds target %d", len(encoded), length)
	}
	// Pad inside the base64 payload by appending filler before the final group so the total
	// length lands exactly on target; the prefix stays intact and decodable.
	filler := length - len(encoded)
	padding := make([]byte, 0, len(raw)+filler)
	padding = append(padding, raw...)
	for i := 0; i < filler; i++ {
		padding = append(padding, 0)
	}
	// Re-encode with a length that yields exactly `length` characters: trim to a multiple
	// that reproduces the requested encoded size.
	for trim := len(padding); trim >= 9; trim-- {
		candidate := base64.RawURLEncoding.EncodeToString(padding[:trim])
		if len(candidate) == length {
			return candidate
		}
	}
	t.Fatalf("could not build a %d-byte turn state", length)
	return ""
}

func TestCodexTurnTicketIssueTimeReadsFernetPrefix(t *testing.T) {
	issued := time.Date(2026, 9, 18, 4, 5, 6, 0, time.UTC)
	state := testTurnState(t, issued.Unix(), 292)
	got, ok := CodexTurnTicketIssueTime(state)
	if !ok {
		t.Fatalf("CodexTurnTicketIssueTime(%q) did not recover an issue time", state)
	}
	if !got.Equal(issued) {
		t.Fatalf("issue time = %s, want %s", got, issued)
	}
}

func TestCodexTurnTicketIssueTimeRejectsNonFernet(t *testing.T) {
	for _, state := range []string{"", "gAAAAA", "not-a-fernet-token", "gAAAAAB", strings.Repeat("A", 292)} {
		if got, ok := CodexTurnTicketIssueTime(state); ok {
			t.Fatalf("CodexTurnTicketIssueTime(%q) = %s, want no result", state, got)
		}
	}
}

// TestNewCodexTurnTicketAnchorsTTLToIssueTime is the core correctness rule: a token that
// was minted before we saw it must expire before a token minted at observation time.
func TestNewCodexTurnTicketAnchorsTTLToIssueTime(t *testing.T) {
	observed := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	minted := observed.Add(-40 * time.Minute)
	state := testTurnState(t, minted.Unix(), 292)
	ticket := NewCodexTurnTicket(state, observed, time.Hour)
	if ticket == nil {
		t.Fatal("NewCodexTurnTicket returned nil")
	}
	want := minted.Add(time.Hour)
	if !ticket.ExpiresAt.Equal(want) {
		t.Fatalf("expiry = %s, want %s (issue time + ttl)", ticket.ExpiresAt, want)
	}
	if ticket.valid(observed, 292) != true {
		t.Fatal("a token 40 minutes into a one hour life should still be usable")
	}
	if ticket.valid(observed.Add(21*time.Minute), 292) {
		t.Fatal("a token past its encoded expiry must not be usable")
	}
}

// TestNewCodexTurnTicketCapsUnreadableTokens keeps the failure mode safe: when the issue
// time cannot be read, the ticket must not claim the full configured lifetime.
func TestNewCodexTurnTicketCapsUnreadableTokens(t *testing.T) {
	observed := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	state := "gAAAAA" + strings.Repeat("x", 286)
	ticket := NewCodexTurnTicket(state, observed, 6*time.Hour)
	if ticket == nil {
		t.Fatal("NewCodexTurnTicket returned nil")
	}
	if got := ticket.ExpiresAt.Sub(observed); got != MaxCodexTurnTicketLifetime {
		t.Fatalf("fallback lifetime = %s, want %s", got, MaxCodexTurnTicketLifetime)
	}
}

// TestNewCodexTurnTicketCapsFutureIssuedTokens covers a clock skew where the token claims
// to have been minted after we observed it.
func TestNewCodexTurnTicketCapsFutureIssuedTokens(t *testing.T) {
	observed := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	state := testTurnState(t, observed.Add(time.Hour).Unix(), 292)
	ticket := NewCodexTurnTicket(state, observed, 6*time.Hour)
	if ticket == nil {
		t.Fatal("NewCodexTurnTicket returned nil")
	}
	if got := ticket.ExpiresAt.Sub(observed); got != MaxCodexTurnTicketLifetime {
		t.Fatalf("future-issued lifetime = %s, want %s", got, MaxCodexTurnTicketLifetime)
	}
}

func TestCodexTurnTicketStoreBucketsByAuthAndModel(t *testing.T) {
	store := NewCodexTurnTicketStore()
	store.Store("auth-a", "gpt-5.5", &CodexTurnTicket{State: "state-a", Length: 292})
	if got := store.Lookup("auth-a", "gpt-5.5"); got == nil || got.State != "state-a" {
		t.Fatalf("same bucket lookup = %#v, want state-a", got)
	}
	if got := store.Lookup("auth-b", "gpt-5.5"); got != nil {
		t.Fatalf("a different credential must not see this ticket, got %#v", got)
	}
	if got := store.Lookup("auth-a", "gpt-5.6-sol"); got != nil {
		t.Fatalf("a different model must not see this ticket, got %#v", got)
	}
	store.Delete("auth-a", "gpt-5.5")
	if got := store.Lookup("auth-a", "gpt-5.5"); got != nil {
		t.Fatalf("ticket survived Delete: %#v", got)
	}
}

func TestCodexTurnTicketKeySeparatesAuthFromModel(t *testing.T) {
	// The NUL separator is what keeps a crafted auth ID from colliding with a model name.
	if codexTurnTicketKey("a\x00m", "") == codexTurnTicketKey("a", "m") {
		t.Fatal("auth ID containing the separator collided with a model bucket")
	}
}

func turnTicketTestConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Codex.TurnTicket.Enabled = true
	cfg.Codex.TurnTicket.HarvestProxyURLs = []string{"http://127.0.0.1:1"}
	cfg.Codex.TurnTicket.Models = []string{"gpt-5.5"}
	return cfg
}

// turnTicketTestConfigProvider exposes cfg through the same lazy accessor the service
// uses, so the tests exercise the hot-reload path instead of a startup snapshot.
func turnTicketTestConfigProvider(cfg *config.Config) func() *config.Config {
	return func() *config.Config { return cfg }
}

func turnTicketTestAuth(id string) *cliproxyauth.Auth {
	return &cliproxyauth.Auth{
		ID:       id,
		Provider: "codex",
		Status:   cliproxyauth.StatusActive,
		Metadata: map[string]any{"access_token": "test-access-token", "auth_kind": "oauth"},
	}
}

func TestPersistentCodexTurnTicketStoreSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), codexTurnTicketPersistenceFile)
	state := testTurnState(t, time.Now().Unix(), 292)
	store := NewPersistentCodexTurnTicketStore(path, 292, time.Hour)
	store.Store("auth-a", "gpt-5.5", NewCodexTurnTicket(state, time.Now(), time.Hour))

	info, errStat := os.Stat(path)
	if errStat != nil {
		t.Fatalf("persistent store was not created: %v", errStat)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("persistent store mode = %o, want 600", got)
	}

	restarted := NewPersistentCodexTurnTicketStore(path, 292, time.Hour)
	if got := restarted.Lookup("auth-a", "gpt-5.5"); got == nil || got.State != state {
		t.Fatalf("restart did not restore the healthy ticket: %#v", got)
	}
	if restarted.restoredCount() != 1 {
		t.Fatalf("restored count = %d, want 1", restarted.restoredCount())
	}
	if matches, errGlob := filepath.Glob(path + ".*.tmp"); errGlob != nil || len(matches) != 0 {
		t.Fatalf("atomic persistence left temp files: matches=%v err=%v", matches, errGlob)
	}
}

func TestPersistentCodexTurnTicketStoreThrottlesRefreshCheckpoints(t *testing.T) {
	path := filepath.Join(t.TempDir(), codexTurnTicketPersistenceFile)
	now := time.Now().Truncate(time.Second)
	firstState := testTurnState(t, now.Add(-2*time.Minute).Unix(), 292)
	secondState := testTurnState(t, now.Add(-119*time.Second).Unix(), 292)
	thirdState := testTurnState(t, now.Add(-30*time.Second).Unix(), 292)
	store := NewPersistentCodexTurnTicketStore(path, 292, time.Hour)
	store.Store("auth-a", "gpt-5.5", NewCodexTurnTicket(firstState, now, time.Hour))
	store.Store("auth-a", "gpt-5.5", NewCodexTurnTicket(secondState, now, time.Hour))

	readPersistedState := func() string {
		t.Helper()
		data, errRead := os.ReadFile(path)
		if errRead != nil {
			t.Fatalf("read persistent store: %v", errRead)
		}
		var disk codexTurnTicketDiskFile
		if errUnmarshal := json.Unmarshal(data, &disk); errUnmarshal != nil {
			t.Fatalf("parse persistent store: %v", errUnmarshal)
		}
		if len(disk.Tickets) != 1 || disk.Tickets[0].CodexTurnTicket == nil {
			t.Fatalf("unexpected persistent store records: %+v", disk.Tickets)
		}
		return disk.Tickets[0].State
	}

	if got := readPersistedState(); got != firstState {
		t.Fatalf("one-second refresh rewrote checkpoint: got state len=%d", len(got))
	}
	if got := store.Lookup("auth-a", "gpt-5.5"); got == nil || got.State != secondState {
		t.Fatal("checkpoint throttling prevented the in-memory ticket from refreshing")
	}

	store.Store("auth-a", "gpt-5.5", NewCodexTurnTicket(thirdState, now, time.Hour))
	if got := readPersistedState(); got != thirdState {
		t.Fatalf("advanced refresh was not checkpointed: got state len=%d", len(got))
	}
}

// TestCodexTurnTicketInjectorOverwritesClientValue covers the reason injection runs last:
// a client-supplied degraded turn-state must not win over a harvested healthy one.
func TestCodexTurnTicketInjectorOverwritesClientValue(t *testing.T) {
	cfg := turnTicketTestConfig()
	store := NewCodexTurnTicketStore()
	state := testTurnState(t, time.Now().Unix(), 292)
	store.Store("auth-a", "gpt-5.5", NewCodexTurnTicket(state, time.Now(), time.Hour))
	injector := NewCodexTurnTicketInjector(store, turnTicketTestConfigProvider(cfg))

	headers := http.Header{}
	headers.Set("X-Codex-Turn-State", strings.Repeat("z", 312))
	injector.Apply(turnTicketTestAuth("auth-a"), "gpt-5.5", headers)
	if got := headers.Get(CodexTurnStateHeader); got != state {
		t.Fatalf("injected value length = %d, want the harvested state (len %d)", len(got), len(state))
	}
	if values := headers.Values(CodexTurnStateHeader); len(values) != 1 {
		t.Fatalf("header has %d values, want exactly 1", len(values))
	}
}

// TestCodexTurnTicketInjectorLeavesHeaderAloneWithoutTicket keeps pass-through behaviour:
// with no ticket the client's own value must reach the upstream unchanged.
func TestCodexTurnTicketInjectorLeavesHeaderAloneWithoutTicket(t *testing.T) {
	injector := NewCodexTurnTicketInjector(NewCodexTurnTicketStore(), turnTicketTestConfigProvider(turnTicketTestConfig()))
	headers := http.Header{}
	clientValue := strings.Repeat("c", 312)
	headers.Set("X-Codex-Turn-State", clientValue)
	injector.Apply(turnTicketTestAuth("auth-a"), "gpt-5.5", headers)
	if got := headers.Get(CodexTurnStateHeader); got != clientValue {
		t.Fatalf("header = %d chars, want the untouched client value (%d chars)", len(got), len(clientValue))
	}
}

func TestCodexTurnTicketInjectorRespectsModelAndAuthScope(t *testing.T) {
	cfg := turnTicketTestConfig()
	store := NewCodexTurnTicketStore()
	state := testTurnState(t, time.Now().Unix(), 292)
	store.Store("auth-a", "gpt-5.5", NewCodexTurnTicket(state, time.Now(), time.Hour))
	injector := NewCodexTurnTicketInjector(store, turnTicketTestConfigProvider(cfg))

	for _, tc := range []struct {
		name  string
		auth  *cliproxyauth.Auth
		model string
	}{
		{name: "other credential", auth: turnTicketTestAuth("auth-b"), model: "gpt-5.5"},
		{name: "other model", auth: turnTicketTestAuth("auth-a"), model: "gpt-5.6-sol"},
		{name: "ungated model", auth: turnTicketTestAuth("auth-a"), model: "gpt-5.4"},
	} {
		headers := http.Header{}
		injector.Apply(tc.auth, tc.model, headers)
		if got := headers.Get(CodexTurnStateHeader); got != "" {
			t.Fatalf("%s: header = %q, want no injection", tc.name, got)
		}
	}
}

func TestCodexTurnTicketInjectorDisabledConfigIsNoOp(t *testing.T) {
	cfg := turnTicketTestConfig()
	cfg.Codex.TurnTicket.Enabled = false
	store := NewCodexTurnTicketStore()
	state := testTurnState(t, time.Now().Unix(), 292)
	store.Store("auth-a", "gpt-5.5", NewCodexTurnTicket(state, time.Now(), time.Hour))
	headers := http.Header{}
	NewCodexTurnTicketInjector(store, turnTicketTestConfigProvider(cfg)).Apply(turnTicketTestAuth("auth-a"), "gpt-5.5", headers)
	if got := headers.Get(CodexTurnStateHeader); got != "" {
		t.Fatalf("disabled feature injected %q", got)
	}
}

func TestCodexTurnTicketInjectorRejectsWrongLengthTicket(t *testing.T) {
	cfg := turnTicketTestConfig()
	store := NewCodexTurnTicketStore()
	// A degraded 312 token must never be replayed as if it were healthy.
	degraded := testTurnState(t, time.Now().Unix(), 312)
	store.Store("auth-a", "gpt-5.5", NewCodexTurnTicket(degraded, time.Now(), time.Hour))
	headers := http.Header{}
	NewCodexTurnTicketInjector(store, turnTicketTestConfigProvider(cfg)).Apply(turnTicketTestAuth("auth-a"), "gpt-5.5", headers)
	if got := headers.Get(CodexTurnStateHeader); got != "" {
		t.Fatalf("a %d-char token was injected, want rejection", len(got))
	}
}

func TestHarvestCodexTurnStatePassivelyStoresHealthyHeader(t *testing.T) {
	cfg := turnTicketTestConfig()
	store := NewCodexTurnTicketStore()
	harvester := NewCodexTurnTicketHarvester(store, turnTicketTestConfigProvider(cfg), nil)
	state := testTurnState(t, time.Now().Unix(), 292)
	headers := http.Header{}
	headers.Set(CodexTurnStateHeader, state)
	harvester.HarvestCodexTurnStatePassively(turnTicketTestAuth("auth-a"), "gpt-5.5", headers)
	if got := store.Lookup("auth-a", "gpt-5.5"); got == nil || got.State != state {
		t.Fatalf("passive harvest did not store the ticket: %#v", got)
	}
	if stats := harvester.Stats(292); stats.Harvested != 1 {
		t.Fatalf("harvested counter = %d, want 1", stats.Harvested)
	}
}

func TestHarvestCodexTurnStatePassivelyIgnoresDegradedAndScopedOut(t *testing.T) {
	cfg := turnTicketTestConfig()
	store := NewCodexTurnTicketStore()
	harvester := NewCodexTurnTicketHarvester(store, turnTicketTestConfigProvider(cfg), nil)

	degraded := http.Header{}
	degraded.Set(CodexTurnStateHeader, testTurnState(t, time.Now().Unix(), 312))
	harvester.HarvestCodexTurnStatePassively(turnTicketTestAuth("auth-a"), "gpt-5.5", degraded)
	if store.Lookup("auth-a", "gpt-5.5") != nil {
		t.Fatal("a degraded token was stored as a healthy ticket")
	}

	healthy := http.Header{}
	healthy.Set(CodexTurnStateHeader, testTurnState(t, time.Now().Unix(), 292))
	harvester.HarvestCodexTurnStatePassively(turnTicketTestAuth("auth-a"), "gpt-5.6-sol", healthy)
	if store.Lookup("auth-a", "gpt-5.6-sol") != nil {
		t.Fatal("a model outside the configured scope was stored")
	}
	if stats := harvester.Stats(292); stats.Harvested != 0 {
		t.Fatalf("harvested counter = %d, want 0", stats.Harvested)
	}
}

// TestCodexTurnTicketProbeUsesHarvestProxyAndIdentity asserts the probe reaches the fake
// upstream through the harvest proxy, carries the credential's token, and is dressed as
// the official client, since the upstream only mints turn-state for recognized callers.
func TestCodexTurnTicketProbeUsesHarvestProxyAndIdentity(t *testing.T) {
	var seenPath atomic.Value
	var seenAuth atomic.Value
	var seenSession atomic.Value
	var seenVersion atomic.Value
	var seenUserAgent atomic.Value
	var seenOriginator atomic.Value
	var seenAccountID atomic.Value
	var seenBeta atomic.Value

	state := testTurnState(t, time.Now().Unix(), 292)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath.Store(r.URL.Path)
		seenAuth.Store(r.Header.Get("Authorization"))
		seenSession.Store(r.Header.Get("session_id"))
		seenVersion.Store(r.Header.Get("Version"))
		seenUserAgent.Store(r.Header.Get("User-Agent"))
		seenOriginator.Store(r.Header.Get("Originator"))
		seenAccountID.Store(r.Header.Get("Chatgpt-Account-Id"))
		seenBeta.Store(r.Header.Get("OpenAI-Beta"))
		w.Header().Set(CodexTurnStateHeader, state)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: {}\n\n"))
	}))
	defer upstream.Close()

	var proxyHits atomic.Int64
	proxyURL := newRecordingForwardProxy(t, upstream.URL, &proxyHits)

	auth := turnTicketTestAuth("auth-a")
	auth.Attributes = map[string]string{"base_url": upstream.URL}
	auth.Metadata["account_id"] = "acct-123"

	effective := EffectiveCodexTurnTicketConfig(turnTicketTestConfig())
	effective.HarvestProxyURLs = []string{proxyURL}
	got, status, errProbe := ProbeCodexTurnState(context.Background(), auth, "gpt-5.5", effective)
	if errProbe != nil {
		t.Fatalf("ProbeCodexTurnState returned error: %v", errProbe)
	}
	if status != http.StatusOK {
		t.Fatalf("probe status = %d, want 200", status)
	}
	if got != state {
		t.Fatalf("probe state length = %d, want %d", len(got), len(state))
	}
	if proxyHits.Load() == 0 {
		t.Fatal("the probe bypassed the harvest proxy")
	}
	if path, _ := seenPath.Load().(string); path != "/responses" {
		t.Fatalf("probe path = %q, want /responses", path)
	}
	if value, _ := seenAuth.Load().(string); value != "Bearer test-access-token" {
		t.Fatalf("probe Authorization = %q, want the credential's bearer token", value)
	}
	if value, _ := seenSession.Load().(string); strings.TrimSpace(value) == "" {
		t.Fatal("probe did not send a session_id")
	}
	if value, _ := seenVersion.Load().(string); strings.TrimSpace(value) == "" {
		t.Fatal("probe did not send a Version header")
	}
	if value, _ := seenUserAgent.Load().(string); !strings.HasPrefix(value, "codex_cli_rs/") {
		t.Fatalf("probe User-Agent = %q, want the official Codex client", value)
	}
	if value, _ := seenOriginator.Load().(string); value != "codex_cli_rs" {
		t.Fatalf("probe Originator = %q, want codex_cli_rs", value)
	}
	if value, _ := seenAccountID.Load().(string); value != "acct-123" {
		t.Fatalf("probe ChatGPT-Account-Id = %q, want the credential's account", value)
	}
	if value, _ := seenBeta.Load().(string); strings.TrimSpace(value) == "" {
		t.Fatal("probe did not send OpenAI-Beta")
	}
}

func TestCodexTurnTicketProbeUsesExplicitDirectEgress(t *testing.T) {
	state := testTurnState(t, time.Now().Unix(), 292)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(CodexTurnStateHeader, state)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	auth := turnTicketTestAuth("auth-a")
	auth.Attributes = map[string]string{"base_url": upstream.URL}
	effective := EffectiveCodexTurnTicketConfig(turnTicketTestConfig())
	effective.HarvestProxyURLs = []string{"direct"}

	got, status, errProbe := ProbeCodexTurnState(context.Background(), auth, "gpt-5.5", effective)
	if errProbe != nil {
		t.Fatalf("direct ProbeCodexTurnState returned error: %v", errProbe)
	}
	if status != http.StatusOK || got != state {
		t.Fatalf("direct probe result = status %d, state length %d; want 200 and %d", status, len(got), len(state))
	}
}

func TestCodexTurnTicketActiveProbeLogsDetailedRedactedOutcome(t *testing.T) {
	hook := logtest.NewLocal(log.StandardLogger())
	defer hook.Reset()

	state := testTurnState(t, time.Now().Unix(), 292)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(CodexTurnStateHeader, state)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	var proxyHits atomic.Int64
	proxyURL := newRecordingForwardProxy(t, upstream.URL, &proxyHits)
	parsedProxy, errParse := url.Parse(proxyURL)
	if errParse != nil {
		t.Fatalf("parse proxy URL: %v", errParse)
	}
	parsedProxy.User = url.UserPassword("probe-user", "proxy-secret")

	cfg := turnTicketTestConfig()
	cfg.Codex.TurnTicket.HarvestProxyURLs = []string{parsedProxy.String()}
	cfg.ProxyURL = parsedProxy.String()
	auth := turnTicketTestAuth("sensitive-auth-id")
	auth.Attributes = map[string]string{"base_url": upstream.URL}
	auth.Metadata["email"] = "kaycee.rempel@mail.com"
	auth.Metadata["access_token"] = "secret-access-token"

	harvester := NewCodexTurnTicketHarvester(NewCodexTurnTicketStore(), turnTicketTestConfigProvider(cfg), func() []*cliproxyauth.Auth {
		return []*cliproxyauth.Auth{auth}
	})
	harvester.probeAll(context.Background())

	var entry *log.Entry
	for _, candidate := range hook.AllEntries() {
		if candidate.Message == "codex turn ticket: active probe completed" {
			entry = candidate
		}
	}
	if entry == nil {
		t.Fatalf("active probe completion log missing; logs=%#v", hook.AllEntries())
	}
	for key, want := range map[string]any{
		"auth_hint":           "ka***@mail.com",
		"model":               "gpt-5.5",
		"result":              "healthy_ticket",
		"http_status":         http.StatusOK,
		"state_length":        292,
		"healthy":             true,
		"next_action":         "cooldown",
		"retry_after_seconds": 3300,
	} {
		if got := entry.Data[key]; got != want {
			t.Errorf("log field %s = %#v, want %#v", key, got, want)
		}
	}
	if got, _ := entry.Data["egress"].(string); !strings.Contains(got, "redacted@") || strings.Contains(got, "proxy-secret") {
		t.Fatalf("logged egress = %q, want credential-redacted proxy", got)
	}
	if expiresAt, ok := entry.Data["ticket_expires_at"].(string); !ok || strings.TrimSpace(expiresAt) == "" {
		t.Fatal("healthy probe log omitted ticket_expires_at")
	}
	encoded, errMarshal := json.Marshal(map[string]any{"message": entry.Message, "fields": entry.Data})
	if errMarshal != nil {
		t.Fatalf("marshal log entry: %v", errMarshal)
	}
	for _, leaked := range []string{"kaycee.rempel@mail.com", "sensitive-auth-id", "proxy-secret", "secret-access-token", state} {
		if strings.Contains(string(encoded), leaked) {
			t.Fatalf("active probe log leaked %q: %s", leaked, encoded)
		}
	}
}

func TestCodexTurnTicketActiveProbeLogsRetryAndBackoffOutcomes(t *testing.T) {
	tests := []struct {
		name          string
		status        int
		stateLength   int
		wantResult    string
		wantAction    string
		wantRetrySecs int
	}{
		{name: "degraded ticket", status: http.StatusOK, stateLength: 312, wantResult: "unhealthy_ticket", wantAction: "retry_next_cycle", wantRetrySecs: 60},
		{name: "missing ticket", status: http.StatusOK, wantResult: "missing_ticket", wantAction: "retry_next_cycle", wantRetrySecs: 60},
		{name: "ordinary HTTP error", status: http.StatusBadGateway, wantResult: "http_error", wantAction: "retry_next_cycle", wantRetrySecs: 60},
		{name: "upstream rejection", status: http.StatusTooManyRequests, wantResult: "rejected", wantAction: "backoff", wantRetrySecs: 600},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hook := logtest.NewLocal(log.StandardLogger())
			defer hook.Reset()

			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.stateLength > 0 {
					w.Header().Set(CodexTurnStateHeader, testTurnState(t, time.Now().Unix(), tt.stateLength))
				}
				w.WriteHeader(tt.status)
			}))
			defer upstream.Close()

			cfg := turnTicketTestConfig()
			cfg.Codex.TurnTicket.HarvestProxyURLs = []string{"direct"}
			cfg.ProxyURL = "direct"
			auth := turnTicketTestAuth("auth-a")
			auth.Attributes = map[string]string{"base_url": upstream.URL}
			harvester := NewCodexTurnTicketHarvester(NewCodexTurnTicketStore(), turnTicketTestConfigProvider(cfg), func() []*cliproxyauth.Auth {
				return []*cliproxyauth.Auth{auth}
			})
			harvester.probeAll(context.Background())

			var entry *log.Entry
			for _, candidate := range hook.AllEntries() {
				if candidate.Message == "codex turn ticket: active probe completed" {
					entry = candidate
				}
			}
			if entry == nil {
				t.Fatalf("active probe completion log missing; logs=%#v", hook.AllEntries())
			}
			if got := entry.Data["result"]; got != tt.wantResult {
				t.Errorf("result = %#v, want %q", got, tt.wantResult)
			}
			if got := entry.Data["next_action"]; got != tt.wantAction {
				t.Errorf("next_action = %#v, want %q", got, tt.wantAction)
			}
			if got := entry.Data["retry_after_seconds"]; got != tt.wantRetrySecs {
				t.Errorf("retry_after_seconds = %#v, want %d", got, tt.wantRetrySecs)
			}
			if got := entry.Data["state_length"]; got != tt.stateLength {
				t.Errorf("state_length = %#v, want %d", got, tt.stateLength)
			}
			if got := entry.Data["egress"]; got != "direct" {
				t.Errorf("egress = %#v, want direct", got)
			}
		})
	}
}

func TestCodexTurnTicketProbeUpgradesVersionForNewestModels(t *testing.T) {
	headers := http.Header{}
	applyCodexTurnTicketProbeIdentity(headers, turnTicketTestAuth("auth-a"), "gpt-6-astra")
	got := headers.Get("Version")
	// The catalog default may already meet the minimum, so assert the floor rather than an
	// exact match; what must never happen is advertising something older.
	if codexTurnTicketVersionLess(got, codexTurnTicketAstraMinVersion) {
		t.Fatalf("Version = %q, want at least %q for a newest-model probe", got, codexTurnTicketAstraMinVersion)
	}
	if ua := headers.Get("User-Agent"); !strings.Contains(ua, "/"+got) {
		t.Fatalf("User-Agent %q does not advertise the Version header %q", ua, got)
	}
	// The advertised version must always agree between Version and User-Agent, or the
	// upstream sees a client contradicting itself.
	plain := http.Header{}
	applyCodexTurnTicketProbeIdentity(plain, turnTicketTestAuth("auth-a"), "gpt-5.5")
	if ua := plain.Get("User-Agent"); !strings.Contains(ua, "/"+plain.Get("Version")) {
		t.Fatalf("ordinary-model User-Agent %q disagrees with Version %q", ua, plain.Get("Version"))
	}
	if !codexTurnTicketNeedsMinimumVersion("gpt-6-astra") || codexTurnTicketNeedsMinimumVersion("gpt-5.5") {
		t.Fatal("minimum-version gating does not match the model families it names")
	}
}

func TestCodexTurnTicketProbeReportsRejectionStatus(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer upstream.Close()
	var proxyHits atomic.Int64
	proxyURL := newRecordingForwardProxy(t, upstream.URL, &proxyHits)

	auth := turnTicketTestAuth("auth-a")
	auth.Attributes = map[string]string{"base_url": upstream.URL}
	effective := EffectiveCodexTurnTicketConfig(turnTicketTestConfig())
	effective.HarvestProxyURLs = []string{proxyURL}
	state, status, errProbe := ProbeCodexTurnState(context.Background(), auth, "gpt-5.5", effective)
	if errProbe != nil {
		t.Fatalf("unexpected error: %v", errProbe)
	}
	if status != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 so the caller can back off", status)
	}
	if state != "" {
		t.Fatalf("state = %q, want empty on rejection", state)
	}
}

func TestCodexTurnTicketProbeSkipsWithoutEgressOrToken(t *testing.T) {
	effective := EffectiveCodexTurnTicketConfig(turnTicketTestConfig())
	effective.HarvestProxyURLs = nil
	if _, _, errProbe := ProbeCodexTurnState(context.Background(), turnTicketTestAuth("auth-a"), "gpt-5.5", effective); errProbe == nil {
		t.Fatal("a probe without a harvest egress must be skipped, not attempted")
	}
	effective.HarvestProxyURLs = []string{"http://127.0.0.1:1"}
	noToken := &cliproxyauth.Auth{ID: "auth-a", Provider: "codex"}
	if _, _, errProbe := ProbeCodexTurnState(context.Background(), noToken, "gpt-5.5", effective); errProbe == nil {
		t.Fatal("a probe without a credential token must be skipped")
	}
}

func TestCodexTurnTicketProbeClientSupportsExplicitDirect(t *testing.T) {
	client, errClient := codexTurnTicketProbeClient(context.Background(), nil, "direct", 0)
	if errClient != nil {
		t.Fatalf("explicit direct harvest egress was rejected: %v", errClient)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport == nil {
		t.Fatalf("direct client transport = %T, want *http.Transport", client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("explicit direct harvest egress must bypass environment proxies")
	}
	if !transport.DisableKeepAlives {
		t.Fatal("direct probes must keep the one-connection-per-probe isolation")
	}
}

func TestCodexTurnTicketProbeClientRejectsInvalidEgress(t *testing.T) {
	if _, errClient := codexTurnTicketProbeClient(context.Background(), nil, "ftp://example.com:21", 0); errClient == nil {
		t.Fatal("probes must reject an unsupported proxy scheme")
	}
}

// TestCodexTurnTicketHarvesterBacksOffOnRejection covers the rate rule that matters most:
// a rejected bucket stops probing instead of retrying on the next cycle.
func TestCodexTurnTicketHarvesterBacksOffOnRejection(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer upstream.Close()
	var proxyHits atomic.Int64
	proxyURL := newRecordingForwardProxy(t, upstream.URL, &proxyHits)

	cfg := turnTicketTestConfig()
	cfg.Codex.TurnTicket.HarvestProxyURLs = []string{proxyURL}
	cfg.Codex.TurnTicket.ProbeCooldownSeconds = 3300
	cfg.Codex.TurnTicket.RejectBackoffSeconds = 600
	auth := turnTicketTestAuth("auth-a")
	auth.Attributes = map[string]string{"base_url": upstream.URL}

	store := NewCodexTurnTicketStore()
	harvester := NewCodexTurnTicketHarvester(store, turnTicketTestConfigProvider(cfg), func() []*cliproxyauth.Auth { return []*cliproxyauth.Auth{auth} })

	harvester.probeAll(context.Background())
	if got := calls.Load(); got != 1 {
		t.Fatalf("first cycle made %d probes, want 1", got)
	}
	// The next cycles must not touch the upstream again while the backoff is armed.
	harvester.probeAll(context.Background())
	harvester.probeAll(context.Background())
	if got := calls.Load(); got != 1 {
		t.Fatalf("backoff did not hold: %d probes were made, want 1", got)
	}
	if stats := harvester.Stats(292); stats.Probed != 1 {
		t.Fatalf("probed counter = %d, want 1", stats.Probed)
	}
	if stats := harvester.Stats(292); stats.Harvested != 0 {
		t.Fatalf("harvested counter = %d, want 0", stats.Harvested)
	}
}

// TestCodexTurnTicketHarvesterCooldownHoldsHealthyBuckets verifies the steady state: a
// bucket holding a fresh ticket is neither re-probed by probeAll nor by the cooldown gate.
func TestCodexTurnTicketHarvesterCooldownHoldsHealthyBuckets(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set(CodexTurnStateHeader, testTurnState(t, time.Now().Unix(), 292))
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	var proxyHits atomic.Int64
	proxyURL := newRecordingForwardProxy(t, upstream.URL, &proxyHits)

	cfg := turnTicketTestConfig()
	cfg.Codex.TurnTicket.HarvestProxyURLs = []string{proxyURL}
	auth := turnTicketTestAuth("auth-a")
	auth.Attributes = map[string]string{"base_url": upstream.URL}

	store := NewCodexTurnTicketStore()
	harvester := NewCodexTurnTicketHarvester(store, turnTicketTestConfigProvider(cfg), func() []*cliproxyauth.Auth { return []*cliproxyauth.Auth{auth} })
	harvester.probeAll(context.Background())
	if got := calls.Load(); got != 1 {
		t.Fatalf("first cycle made %d probes, want 1", got)
	}
	if store.Lookup("auth-a", "gpt-5.5") == nil {
		t.Fatal("the healthy probe result was not stored")
	}
	harvester.probeAll(context.Background())
	if got := calls.Load(); got != 1 {
		t.Fatalf("a fresh bucket was re-probed: %d probes, want 1", got)
	}
}

// A 312 response is a miss, not a successful harvest. It must be retried on the next
// cycle instead of consuming the 55-minute healthy-ticket cooldown.
func TestCodexTurnTicketHarvesterRetriesDegradedMissNextCycle(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set(CodexTurnStateHeader, testTurnState(t, time.Now().Unix(), 312))
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	var proxyHits atomic.Int64
	proxyURL := newRecordingForwardProxy(t, upstream.URL, &proxyHits)

	cfg := turnTicketTestConfig()
	cfg.Codex.TurnTicket.HarvestProxyURLs = []string{proxyURL}
	cfg.Codex.TurnTicket.ProbeCooldownSeconds = 3300
	auth := turnTicketTestAuth("auth-a")
	auth.Attributes = map[string]string{"base_url": upstream.URL}
	harvester := NewCodexTurnTicketHarvester(NewCodexTurnTicketStore(), turnTicketTestConfigProvider(cfg), func() []*cliproxyauth.Auth {
		return []*cliproxyauth.Auth{auth}
	})

	harvester.probeAll(context.Background())
	harvester.probeAll(context.Background())
	if got := calls.Load(); got != 4 {
		t.Fatalf("degraded miss made %d probes across two cycles, want 4 (business + harvest)", got)
	}
	observation := harvester.observation("auth-a", "gpt-5.5")
	if observation.StatusCode != http.StatusOK || observation.StateLength != 312 || observation.Healthy {
		t.Fatalf("degraded observation = %+v, want HTTP 200 / length 312 / unhealthy", observation)
	}
}

func TestCodexTurnTicketHarvesterProbesOnlyScopedOAuthCredentials(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	var proxyHits atomic.Int64
	proxyURL := newRecordingForwardProxy(t, upstream.URL, &proxyHits)

	cfg := turnTicketTestConfig()
	cfg.Codex.TurnTicket.HarvestProxyURLs = []string{proxyURL}
	cfg.Codex.TurnTicket.AuthIDs = []string{"auth-a"}

	apiKeyAuth := &cliproxyauth.Auth{
		ID:         "auth-key",
		Provider:   "codex",
		Attributes: map[string]string{"api_key": "sk-test", "auth_kind": "apikey"},
	}
	foreign := &cliproxyauth.Auth{ID: "auth-b", Provider: "claude", Metadata: map[string]any{"access_token": "t"}}
	scoped := turnTicketTestAuth("auth-a")
	scoped.Attributes = map[string]string{"base_url": upstream.URL}

	store := NewCodexTurnTicketStore()
	harvester := NewCodexTurnTicketHarvester(store, turnTicketTestConfigProvider(cfg), func() []*cliproxyauth.Auth {
		return []*cliproxyauth.Auth{apiKeyAuth, foreign, scoped}
	})
	harvester.probeAll(context.Background())
	if got := calls.Load(); got != 1 {
		t.Fatalf("made %d probes, want only the single scoped OAuth credential", got)
	}
}

func TestCodexTurnTicketHarvesterProbesTransientErrorsAndSkipsDisabledCredentials(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	var proxyHits atomic.Int64
	proxyURL := newRecordingForwardProxy(t, upstream.URL, &proxyHits)

	cfg := turnTicketTestConfig()
	cfg.Codex.TurnTicket.HarvestProxyURLs = []string{proxyURL}
	active := turnTicketTestAuth("active")
	active.Attributes = map[string]string{"base_url": upstream.URL}
	transientError := turnTicketTestAuth("transient-error")
	transientError.Status = cliproxyauth.StatusError
	transientError.Unavailable = true
	transientError.Attributes = map[string]string{"base_url": upstream.URL}
	disabled := turnTicketTestAuth("disabled")
	disabled.Disabled = true
	disabled.Status = cliproxyauth.StatusDisabled
	disabled.Attributes = map[string]string{"base_url": upstream.URL}

	harvester := NewCodexTurnTicketHarvester(NewCodexTurnTicketStore(), turnTicketTestConfigProvider(cfg), func() []*cliproxyauth.Auth {
		return []*cliproxyauth.Auth{active, transientError, disabled}
	})
	harvester.probeAll(context.Background())
	if got := calls.Load(); got != 2 {
		t.Fatalf("probe count = %d, want active and transient-error credentials", got)
	}
}

// TestCodexTurnTicketHarvesterStartsWhileDisabledForHotReload pins the reload contract:
// the loop must be running even while the feature is off, because enabling it later is a
// config-only change that must not require a service restart.
func TestCodexTurnTicketHarvesterStartsWhileDisabledForHotReload(t *testing.T) {
	store := NewCodexTurnTicketStore()
	disabled := &config.Config{}
	harvester := NewCodexTurnTicketHarvester(store, turnTicketTestConfigProvider(disabled), nil)
	defer harvester.Stop()
	harvester.Start(context.Background())
	if !harvester.Running() {
		t.Fatal("the harvester loop must run while disabled so a reload can enable it in place")
	}
	// A disabled cycle must not probe anything, and must not require a harvest egress.
	harvester.probeAll(context.Background())
	if stats := harvester.Stats(292); stats.Probed != 0 {
		t.Fatalf("probed counter = %d while disabled, want 0", stats.Probed)
	}
}

// TestCodexTurnTicketHarvesterPicksUpEnabledConfigHotReload proves the reload actually
// reaches the probe loop: the same harvester instance must begin probing once the live
// config flips enabled, without being restarted or rebuilt.
func TestCodexTurnTicketHarvesterPicksUpEnabledConfigHotReload(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set(CodexTurnStateHeader, testTurnState(t, time.Now().Unix(), 292))
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	var proxyHits atomic.Int64
	proxyURL := newRecordingForwardProxy(t, upstream.URL, &proxyHits)

	auth := turnTicketTestAuth("auth-a")
	auth.Attributes = map[string]string{"base_url": upstream.URL}
	store := NewCodexTurnTicketStore()

	current := &config.Config{}
	current.Codex.TurnTicket.Models = []string{"gpt-5.5"}
	provider := func() *config.Config { return current }
	harvester := NewCodexTurnTicketHarvester(store, provider, func() []*cliproxyauth.Auth {
		return []*cliproxyauth.Auth{auth}
	})

	harvester.probeAll(context.Background())
	if got := calls.Load(); got != 0 {
		t.Fatalf("a disabled cycle made %d probes, want 0", got)
	}

	// Simulate the hot reload: the service swaps the live config pointer, and the next
	// cycle must see the new value without the harvester being rebuilt.
	reloaded := &config.Config{}
	reloaded.Codex.TurnTicket.Enabled = true
	reloaded.Codex.TurnTicket.HarvestProxyURLs = []string{proxyURL}
	reloaded.Codex.TurnTicket.Models = []string{"gpt-5.5"}
	current = reloaded

	harvester.probeAll(context.Background())
	if got := calls.Load(); got != 1 {
		t.Fatalf("after hot reload the harvester made %d probes, want 1", got)
	}
	if store.Lookup("auth-a", "gpt-5.5") == nil {
		t.Fatal("the hot-reload probe result was not stored")
	}
}

func TestCodexTurnTicketHarvesterStartStopIsIdempotent(t *testing.T) {
	cfg := turnTicketTestConfig()
	cfg.Codex.TurnTicket.ProbeIntervalSeconds = 3600
	store := NewCodexTurnTicketStore()
	harvester := NewCodexTurnTicketHarvester(store, turnTicketTestConfigProvider(cfg), nil)
	// Point the probe at an unroutable address so the initial cycle returns immediately
	// without touching the network in a way the test depends on.
	harvester.Start(context.Background())
	harvester.Start(context.Background())
	harvester.Stop()
	harvester.Stop()
	if harvester.running {
		t.Fatal("harvester is still marked running after Stop")
	}
}

func TestProcessWideTurnTicketWiring(t *testing.T) {
	cfg := turnTicketTestConfig()
	process := ConfigureCodexTurnTickets(turnTicketTestConfigProvider(cfg), nil)
	if process == nil || CurrentCodexTurnTickets() != process {
		t.Fatal("ConfigureCodexTurnTickets did not install the process-wide state")
	}
	state := testTurnState(t, time.Now().Unix(), 292)
	process.Store.Store("auth-a", "gpt-5.5", NewCodexTurnTicket(state, time.Now(), time.Hour))

	headers := http.Header{}
	ApplyCodexTurnTicket(turnTicketTestAuth("auth-a"), "gpt-5.5", headers)
	if got := headers.Get(CodexTurnStateHeader); got != state {
		t.Fatalf("process-wide injection length = %d, want %d", len(got), len(state))
	}

	response := http.Header{}
	fresh := testTurnState(t, time.Now().Unix(), 292)
	response.Set(CodexTurnStateHeader, fresh)
	HarvestCodexTurnStateOnResponse(turnTicketTestAuth("auth-b"), "gpt-5.5", response)
	if got := process.Store.Lookup("auth-b", "gpt-5.5"); got == nil {
		t.Fatal("process-wide passive harvest did not store the ticket")
	}
	if summary := DescribeCodexTurnTickets(); !strings.Contains(summary, "harvested=") {
		t.Fatalf("summary %q does not report counters", summary)
	}
}

// TestProcessWideTurnTicketWiringFollowsConfigReload is the regression for the reload
// bug: the process-wide injector used to hold the startup *config.Config pointer, so a
// config reload that enabled the feature never reached injection.
func TestProcessWideTurnTicketWiringFollowsConfigReload(t *testing.T) {
	current := &config.Config{}
	current.Codex.TurnTicket.Models = []string{"gpt-5.5"}
	process := ConfigureCodexTurnTickets(func() *config.Config { return current }, nil)
	defer ConfigureCodexTurnTickets(nil, nil)

	state := testTurnState(t, time.Now().Unix(), 292)
	process.Store.Store("auth-a", "gpt-5.5", NewCodexTurnTicket(state, time.Now(), time.Hour))

	// While the live config is disabled the stored ticket must not be injected.
	headers := http.Header{}
	ApplyCodexTurnTicket(turnTicketTestAuth("auth-a"), "gpt-5.5", headers)
	if got := headers.Get(CodexTurnStateHeader); got != "" {
		t.Fatalf("a ticket was injected while the live config was disabled: %q", got)
	}

	// Hot-reload the live config to enabled: injection must start on the very next call.
	reloaded := &config.Config{}
	reloaded.Codex.TurnTicket.Enabled = true
	reloaded.Codex.TurnTicket.Models = []string{"gpt-5.5"}
	current = reloaded

	headers = http.Header{}
	ApplyCodexTurnTicket(turnTicketTestAuth("auth-a"), "gpt-5.5", headers)
	if got := headers.Get(CodexTurnStateHeader); got != state {
		t.Fatalf("hot reload did not enable injection: got %d chars, want the stored ticket", len(got))
	}
}

func TestCodexTurnTicketFailClosedExecutionGuard(t *testing.T) {
	cfg := turnTicketTestConfig()
	process := ConfigureCodexTurnTickets(turnTicketTestConfigProvider(cfg), nil)
	defer ConfigureCodexTurnTickets(nil, nil)
	auth := turnTicketTestAuth("auth-a")

	if CodexTurnTicketAllowsExecution(auth, "gpt-5.5") {
		t.Fatal("fail-closed guard admitted a gated bucket without a healthy ticket")
	}
	if !CodexTurnTicketAllowsExecution(auth, "gpt-4o") {
		t.Fatal("fail-closed guard blocked an unrelated model")
	}
	state := testTurnState(t, time.Now().Unix(), 292)
	process.Store.Store(auth.ID, "gpt-5.5", NewCodexTurnTicket(state, time.Now(), time.Hour))
	if !CodexTurnTicketAllowsExecution(auth, "gpt-5.5") {
		t.Fatal("fail-closed guard rejected a bucket with a healthy ticket")
	}

	disabled := false
	cfg.Codex.TurnTicket.FailClosed = &disabled
	if !CodexTurnTicketAllowsExecution(turnTicketTestAuth("auth-b"), "gpt-5.5") {
		t.Fatal("explicit fail-closed=false did not restore pass-through behavior")
	}
}

// TestSnapshotCodexTurnTicketsReportsRedactedState covers the management-facing counter
// export: it must report configuration and counts without leaking credentials or tokens.
func TestSnapshotCodexTurnTicketsReportsRedactedState(t *testing.T) {
	cfg := turnTicketTestConfig()
	cfg.Codex.TurnTicket.HarvestProxyURLs = []string{"direct", "http://user:secret@127.0.0.1:8080"}
	auth := turnTicketTestAuth("sensitive-auth-id")
	auth.Metadata["email"] = "kaycee.rempel@mail.com"
	process := ConfigureCodexTurnTickets(turnTicketTestConfigProvider(cfg), func() []*cliproxyauth.Auth {
		return []*cliproxyauth.Auth{auth}
	})
	defer ConfigureCodexTurnTickets(nil, nil)
	state := testTurnState(t, time.Now().Unix(), 292)
	process.Store.Store(auth.ID, "gpt-5.5", NewCodexTurnTicket(state, time.Now(), time.Hour))

	snapshot := SnapshotCodexTurnTickets()
	if !snapshot.Configured || !snapshot.Enabled {
		t.Fatalf("snapshot did not report the enabled feature: %+v", snapshot)
	}
	if snapshot.Buckets != 1 || snapshot.HealthyTickets != 1 {
		t.Fatalf("snapshot occupancy = %d buckets / %d healthy, want 1/1", snapshot.Buckets, snapshot.HealthyTickets)
	}
	if snapshot.HarvestProxyCount != 2 || len(snapshot.HarvestProxyURLs) != 2 {
		t.Fatalf("snapshot harvest egresses = %d / %v, want 2 redacted entries", snapshot.HarvestProxyCount, snapshot.HarvestProxyURLs)
	}
	for _, egress := range snapshot.HarvestProxyURLs {
		if strings.Contains(egress, "secret") {
			t.Fatalf("snapshot leaked harvest proxy credentials: %q", egress)
		}
	}
	if len(snapshot.BucketStates) != 1 {
		t.Fatalf("bucket state count = %d, want 1", len(snapshot.BucketStates))
	}
	bucket := snapshot.BucketStates[0]
	if bucket.AuthHint != "ka***@mail.com" || bucket.Model != "gpt-5.5" || bucket.TicketState != "healthy" || bucket.TicketLength != 292 {
		t.Fatalf("unexpected redacted bucket state: %+v", bucket)
	}
	encoded, errMarshal := json.Marshal(snapshot)
	if errMarshal != nil {
		t.Fatalf("marshal snapshot: %v", errMarshal)
	}
	for _, leaked := range []string{state, auth.ID, "kaycee.rempel@mail.com", "secret"} {
		if strings.Contains(string(encoded), leaked) {
			t.Fatalf("snapshot leaked %q: %s", leaked, encoded)
		}
	}
	if summary := DescribeCodexTurnTickets(); strings.Contains(summary, "secret") || strings.Contains(summary, state) {
		t.Fatalf("summary leaked material: %q", summary)
	}
}

func TestSnapshotCodexTurnTicketForAuthReportsPerModelHealthAndExpiry(t *testing.T) {
	cfg := turnTicketTestConfig()
	cfg.Codex.TurnTicket.Models = []string{"gpt-5.5", "gpt-6-astra"}
	auth := turnTicketTestAuth("auth-ticket-health")
	process := ConfigureCodexTurnTickets(turnTicketTestConfigProvider(cfg), func() []*cliproxyauth.Auth {
		return []*cliproxyauth.Auth{auth}
	})
	defer ConfigureCodexTurnTickets(nil, nil)

	now := time.Now().Truncate(time.Second)
	state := testTurnState(t, now.Unix(), 292)
	ticket := NewCodexTurnTicket(state, now, time.Hour)
	process.Store.Store(auth.ID, "gpt-5.5", ticket)

	snapshot := SnapshotCodexTurnTicketForAuth(auth)
	if snapshot == nil {
		t.Fatal("credential snapshot is nil")
	}
	if !snapshot.Configured || !snapshot.Enabled || snapshot.TargetLength != 292 {
		t.Fatalf("unexpected credential configuration: %+v", snapshot)
	}
	if snapshot.State != "partial" || snapshot.HealthyModels != 1 || snapshot.TotalModels != 2 {
		t.Fatalf("unexpected credential aggregate: %+v", snapshot)
	}
	if !snapshot.EarliestExpiresAt.Equal(ticket.ExpiresAt) {
		t.Fatalf("earliest expiry = %s, want %s", snapshot.EarliestExpiresAt, ticket.ExpiresAt)
	}
	if len(snapshot.ModelStates) != 2 || snapshot.ModelStates[0].TicketState != "healthy" || snapshot.ModelStates[1].TicketState != "missing" {
		t.Fatalf("unexpected model states: %+v", snapshot.ModelStates)
	}
}

func TestSnapshotCodexTurnTicketForAuthIgnoresNonCodexCredentials(t *testing.T) {
	auth := turnTicketTestAuth("non-codex")
	auth.Provider = "claude"
	if snapshot := SnapshotCodexTurnTicketForAuth(auth); snapshot != nil {
		t.Fatalf("non-Codex snapshot = %+v, want nil", snapshot)
	}
}

func TestDescribeCodexTurnTicketsNeverLeaksTokenMaterial(t *testing.T) {
	cfg := turnTicketTestConfig()
	process := ConfigureCodexTurnTickets(turnTicketTestConfigProvider(cfg), nil)
	state := testTurnState(t, time.Now().Unix(), 292)
	process.Store.Store("auth-a", "gpt-5.5", NewCodexTurnTicket(state, time.Now(), time.Hour))
	if summary := DescribeCodexTurnTickets(); strings.Contains(summary, state) || strings.Contains(summary, "auth-a") {
		t.Fatalf("summary %q leaked token or credential material", summary)
	}
}

func TestEffectiveCodexTurnTicketConfigDefaults(t *testing.T) {
	effective := EffectiveCodexTurnTicketConfig(nil)
	if effective.TargetLength != 292 || effective.TTLSeconds != 3600 || effective.RefreshBeforeSeconds != 600 {
		t.Fatalf("unexpected defaults: %+v", effective)
	}
	if effective.Enabled {
		t.Fatal("the feature must be off by default")
	}
	if !effective.FailClosed {
		t.Fatal("fail-closed must default to true")
	}
	if len(effective.Models) == 0 {
		t.Fatal("default models must be populated so a bare enable is useful")
	}
	for _, model := range CodexTurnTicketDefaults {
		if !codexTurnTicketModelGated(effective, model) {
			t.Fatalf("default model %q is not gated", model)
		}
	}
	if codexTurnTicketModelGated(effective, "") || codexTurnTicketModelGated(effective, "gpt-4o") {
		t.Fatal("unrelated models must not be gated")
	}
}

func TestEffectiveCodexTurnTicketConfigNormalizesHarvestEgressPool(t *testing.T) {
	cfg := &config.Config{}
	cfg.Codex.TurnTicket.HarvestProxyURLs = []string{
		" direct ",
		"",
		" socks5h://proxy.example.com:1080 ",
	}
	effective := EffectiveCodexTurnTicketConfig(cfg)
	if len(effective.HarvestProxyURLs) != 2 || effective.HarvestProxyURLs[0] != "direct" || effective.HarvestProxyURLs[1] != "socks5h://proxy.example.com:1080" {
		t.Fatalf("normalized harvest egresses = %v", effective.HarvestProxyURLs)
	}
	allowed := map[string]bool{"direct": true, "socks5h://proxy.example.com:1080": true}
	for i := 0; i < 32; i++ {
		if selected := chooseCodexTurnTicketHarvestEgress(effective.HarvestProxyURLs); !allowed[selected] {
			t.Fatalf("selected harvest egress %q is outside the configured pool", selected)
		}
	}
}

func TestExtractCodexTurnStateAndHealthCheck(t *testing.T) {
	state := testTurnState(t, time.Now().Unix(), 292)
	headers := http.Header{}
	headers.Set(CodexTurnStateHeader, "  "+state+"  ")
	if got := ExtractCodexTurnState(headers); got != state {
		t.Fatalf("extracted length = %d, want %d", len(got), len(state))
	}
	if !IsHealthyCodexTurnState(state, 292) {
		t.Fatal("a 292 token was not recognized as healthy")
	}
	if IsHealthyCodexTurnState(testTurnState(t, time.Now().Unix(), 312), 292) {
		t.Fatal("a 312 token was accepted as healthy")
	}
	if IsHealthyCodexTurnState("short", 292) {
		t.Fatal("a non-Fernet value was accepted as healthy")
	}
	if ExtractCodexTurnState(nil) != "" {
		t.Fatal("nil headers must extract an empty value")
	}
}

func TestCodexTurnTicketConcurrentAccessIsRaceFree(t *testing.T) {
	cfg := turnTicketTestConfig()
	store := NewCodexTurnTicketStore()
	harvester := NewCodexTurnTicketHarvester(store, turnTicketTestConfigProvider(cfg), nil)
	injector := NewCodexTurnTicketInjector(store, turnTicketTestConfigProvider(cfg))
	auth := turnTicketTestAuth("auth-a")
	state := testTurnState(t, time.Now().Unix(), 292)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				headers := http.Header{}
				headers.Set(CodexTurnStateHeader, state)
				harvester.HarvestCodexTurnStatePassively(auth, "gpt-5.5", headers)
				injector.Apply(auth, "gpt-5.5", http.Header{})
				_ = store.Lookup("auth-a", "gpt-5.5")
				_ = harvester.Stats(292)
			}
		}()
	}
	wg.Wait()
}

// newRecordingForwardProxy starts a forward proxy that tunnels absolute-form requests to
// the target server and counts the requests it saw, so a test can prove the probe really
// left through the configured egress rather than connecting directly.
func newRecordingForwardProxy(t *testing.T, target string, hits *atomic.Int64) string {
	t.Helper()
	targetURL, errParse := url.Parse(target)
	if errParse != nil {
		t.Fatalf("parse target URL: %v", errParse)
	}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			t.Errorf("proxy received CONNECT, want an absolute-form forward request")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		hits.Add(1)
		// Rewrite the absolute-form request into a relative one against the real upstream.
		cloned := r.Clone(r.Context())
		cloned.URL.Scheme = targetURL.Scheme
		cloned.URL.Host = targetURL.Host
		cloned.RequestURI = ""
		cloned.Header.Del("Proxy-Connection")
		resp, errDo := http.DefaultClient.Do(cloned)
		if errDo != nil {
			t.Errorf("proxy forward failed: %v", errDo)
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(resp.StatusCode)
	}))
	t.Cleanup(proxy.Close)
	return proxy.URL
}

func TestCodexTurnTicketProbeBodyIsMinimalAndNamesTheModel(t *testing.T) {
	body := codexTurnTicketProbeBody("gpt-6-astra")
	var decoded struct {
		Model  string `json:"model"`
		Store  bool   `json:"store"`
		Stream bool   `json:"stream"`
		Input  []any  `json:"input"`
	}
	if errUnmarshal := json.Unmarshal(body, &decoded); errUnmarshal != nil {
		t.Fatalf("probe body is not valid JSON: %v", errUnmarshal)
	}
	if decoded.Model != "gpt-6-astra" {
		t.Fatalf("probe model = %q, want gpt-6-astra", decoded.Model)
	}
	if decoded.Store || !decoded.Stream {
		t.Fatalf("probe must be a non-stored stream, got store=%v stream=%v", decoded.Store, decoded.Stream)
	}
	if len(decoded.Input) != 1 {
		t.Fatalf("probe input has %d items, want exactly 1", len(decoded.Input))
	}
}

func TestCodexTurnTicketBaseURLPrefersCredentialAttribute(t *testing.T) {
	auth := turnTicketTestAuth("auth-a")
	if got := codexTurnTicketBaseURL(auth); got != codexTurnTicketDefaultBaseURL {
		t.Fatalf("base URL = %q, want the default", got)
	}
	auth.Attributes = map[string]string{"base_url": "https://example.test/backend"}
	if got := codexTurnTicketBaseURL(auth); got != "https://example.test/backend" {
		t.Fatalf("base URL = %q, want the credential's base_url", got)
	}
}
