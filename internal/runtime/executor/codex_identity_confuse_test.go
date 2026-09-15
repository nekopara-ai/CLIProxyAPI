package executor

import (
	"bytes"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
)

// The identifiers below are copied verbatim from a captured Codex CLI request
// so the fixtures keep the exact shape an upstream can fingerprint.
const (
	codexTestRawInstallationID = "40753ab5-98a1-49b6-9fcd-1d0ca03e936e"
	codexTestRawSessionID      = "01a0a3ce-5a73-7b03-816d-d4c79fb02f4b"
	codexTestRawTurnID         = "01a0a3ce-5ad5-7382-bf9e-8077aa60ef3c"
	codexTestRawContextWindow  = "01a0a3ce-5a73-7b03-816d-d4de608c3bff"
)

func codexTestConfuseConfig() *config.Config {
	return &config.Config{
		Routing: config.RoutingConfig{Strategy: "weighted-round-robin", SessionAffinity: true},
		Codex:   config.CodexConfig{IdentityConfuse: true},
	}
}

func codexTestConfuseAuth(id string) *cliproxyauth.Auth {
	return &cliproxyauth.Auth{ID: id, Provider: "codex"}
}

// codexTestTurnMetadataJSON mirrors the turn metadata a native Codex CLI sends:
// session, thread, turn, installation and context window identifiers together
// with fields the confusion layer must leave untouched.
func codexTestTurnMetadataJSON() string {
	return `{"installation_id":"` + codexTestRawInstallationID + `"` +
		`,"session_id":"` + codexTestRawSessionID + `"` +
		`,"thread_id":"` + codexTestRawSessionID + `"` +
		`,"agent_name":"/home/user"` +
		`,"turn_id":"` + codexTestRawTurnID + `"` +
		`,"window_id":"` + codexTestRawSessionID + `:0"` +
		`,"window_number":0` +
		`,"context_window_id":"` + codexTestRawContextWindow + `"` +
		`,"request_kind":"turn"` +
		`,"root_turn_id":"` + codexTestRawTurnID + `"}`
}

func codexTestUserPayload() []byte {
	return []byte(`{"model":"gpt-5-codex","prompt_cache_key":"` + codexTestRawSessionID +
		`","client_metadata":{"x-codex-installation-id":"` + codexTestRawInstallationID + `"}}`)
}

func codexTestRequestBody(turnMetadata string) []byte {
	return []byte(`{"model":"gpt-5-codex","stream":true,"prompt_cache_key":"` + codexTestRawSessionID +
		`","client_metadata":{"x-codex-turn-metadata":` + strconv.Quote(turnMetadata) +
		`,"session_id":"` + codexTestRawSessionID +
		`","root_turn_id":"` + codexTestRawTurnID +
		`","turn_id":"` + codexTestRawTurnID +
		`","thread_id":"` + codexTestRawSessionID +
		`","x-codex-window-id":"` + codexTestRawSessionID + `:0"` +
		`,"x-codex-installation-id":"` + codexTestRawInstallationID + `"}}`)
}

func codexTestClientHeaders(turnMetadata string) http.Header {
	headers := http.Header{}
	headers.Set("Session-Id", codexTestRawSessionID)
	headers.Set("Thread-Id", codexTestRawSessionID)
	headers.Set("X-Client-Request-Id", codexTestRawSessionID)
	headers.Set("X-Codex-Window-Id", codexTestRawSessionID+":0")
	headers.Set("X-Codex-Turn-Metadata", turnMetadata)
	return headers
}

// TestCodexIdentityConfuseKeepsEverySurfaceConsistent is the regression guard
// for the leak that shipped upstream: the real installation id stayed in the
// turn metadata while only client_metadata was rewritten, and the session,
// thread and turn ids survived in the body while the headers carried confused
// values. A native client agrees with itself, so every surface must agree here.
func TestCodexIdentityConfuseKeepsEverySurfaceConsistent(t *testing.T) {
	cfg := codexTestConfuseConfig()
	auth := codexTestConfuseAuth("auth-a")
	turnMetadata := codexTestTurnMetadataJSON()

	body, state := applyCodexIdentityConfuseBody(cfg, auth, codexTestUserPayload(), codexTestRequestBody(turnMetadata))
	headers := codexTestClientHeaders(turnMetadata)
	applyCodexIdentityConfuseHeaders(headers, &state)

	for _, raw := range []string{
		codexTestRawInstallationID,
		codexTestRawSessionID,
		codexTestRawTurnID,
		codexTestRawContextWindow,
	} {
		if bytes.Contains(body, []byte(raw)) {
			t.Fatalf("upstream body still carries raw identifier %s: %s", raw, body)
		}
		for name, values := range headers {
			for _, value := range values {
				if strings.Contains(value, raw) {
					t.Fatalf("upstream header %s still carries raw identifier %s: %s", name, raw, value)
				}
			}
		}
	}

	sessionID := gjson.GetBytes(body, "prompt_cache_key").String()
	if sessionID == "" {
		t.Fatalf("body lost prompt_cache_key: %s", body)
	}
	bodyTurnMetadata := gjson.GetBytes(body, "client_metadata.x-codex-turn-metadata").String()
	if bodyTurnMetadata != headers.Get("X-Codex-Turn-Metadata") {
		t.Fatalf("body and header turn metadata diverged: body=%s header=%s", bodyTurnMetadata, headers.Get("X-Codex-Turn-Metadata"))
	}

	for _, check := range []struct {
		name string
		got  string
		want string
	}{
		{"header Session-Id", headers.Get("Session-Id"), sessionID},
		{"header Thread-Id", headers.Get("Thread-Id"), sessionID},
		{"header X-Client-Request-Id", headers.Get("X-Client-Request-Id"), sessionID},
		{"header X-Codex-Window-Id", headers.Get("X-Codex-Window-Id"), sessionID + ":0"},
		{"client_metadata.session_id", gjson.GetBytes(body, "client_metadata.session_id").String(), sessionID},
		{"client_metadata.thread_id", gjson.GetBytes(body, "client_metadata.thread_id").String(), sessionID},
		{"client_metadata.x-codex-window-id", gjson.GetBytes(body, "client_metadata.x-codex-window-id").String(), sessionID + ":0"},
		{"turn metadata session_id", gjson.Get(bodyTurnMetadata, "session_id").String(), sessionID},
		{"turn metadata thread_id", gjson.Get(bodyTurnMetadata, "thread_id").String(), sessionID},
		{"turn metadata window_id", gjson.Get(bodyTurnMetadata, "window_id").String(), sessionID + ":0"},
	} {
		if check.got != check.want {
			t.Fatalf("%s = %q, want %q", check.name, check.got, check.want)
		}
	}

	installationID := gjson.GetBytes(body, "client_metadata.x-codex-installation-id").String()
	if installationID == "" || installationID == codexTestRawInstallationID {
		t.Fatalf("installation id was not confused: %q", installationID)
	}
	if got := gjson.Get(bodyTurnMetadata, "installation_id").String(); got != installationID {
		t.Fatalf("turn metadata installation_id = %q, want %q", got, installationID)
	}

	turnID := gjson.GetBytes(body, "client_metadata.turn_id").String()
	if turnID == "" || turnID == codexTestRawTurnID {
		t.Fatalf("turn id was not confused: %q", turnID)
	}
	if got := gjson.GetBytes(body, "client_metadata.root_turn_id").String(); got != turnID {
		t.Fatalf("client_metadata.root_turn_id = %q, want %q", got, turnID)
	}
	if got := gjson.Get(bodyTurnMetadata, "turn_id").String(); got != turnID {
		t.Fatalf("turn metadata turn_id = %q, want %q", got, turnID)
	}
	if got := gjson.Get(bodyTurnMetadata, "root_turn_id").String(); got != turnID {
		t.Fatalf("turn metadata root_turn_id = %q, want %q", got, turnID)
	}

	contextWindowID := gjson.Get(bodyTurnMetadata, "context_window_id").String()
	if contextWindowID == "" || contextWindowID == codexTestRawContextWindow || contextWindowID == sessionID {
		t.Fatalf("context_window_id = %q, want a distinct confused identifier", contextWindowID)
	}

	// The confusion layer must not invent or drop unrelated metadata.
	if got := gjson.Get(bodyTurnMetadata, "agent_name").String(); got != "/home/user" {
		t.Fatalf("agent_name = %q, want it preserved", got)
	}
	if got := gjson.Get(bodyTurnMetadata, "window_number").Int(); got != 0 {
		t.Fatalf("window_number = %d, want it preserved", got)
	}
}

func TestCodexIdentityConfuseIsDeterministicAndRepeatable(t *testing.T) {
	cfg := codexTestConfuseConfig()
	auth := codexTestConfuseAuth("auth-a")
	turnMetadata := codexTestTurnMetadataJSON()

	first, _ := applyCodexIdentityConfuseBody(cfg, auth, codexTestUserPayload(), codexTestRequestBody(turnMetadata))
	second, _ := applyCodexIdentityConfuseBody(cfg, auth, codexTestUserPayload(), codexTestRequestBody(turnMetadata))
	if !bytes.Equal(first, second) {
		t.Fatalf("confusion is not deterministic:\n%s\n%s", first, second)
	}

	headers := codexTestClientHeaders(turnMetadata)
	state := codexIdentityConfuseState{}
	_, state = applyCodexIdentityConfuseBody(cfg, auth, codexTestUserPayload(), codexTestRequestBody(turnMetadata))
	applyCodexIdentityConfuseHeaders(headers, &state)
	once := headers.Clone()
	applyCodexIdentityConfuseHeaders(headers, &state)
	if once.Get("Session-Id") != headers.Get("Session-Id") ||
		once.Get("X-Codex-Window-Id") != headers.Get("X-Codex-Window-Id") ||
		once.Get("X-Codex-Turn-Metadata") != headers.Get("X-Codex-Turn-Metadata") {
		t.Fatalf("re-applying the header rewrite changed the result:\n%v\n%v", once, headers)
	}
}

// TestCodexIdentityConfuseSeparatesUpstreamAccounts proves the same local
// client renders different identifiers per upstream account, which is the whole
// point of the confusion layer: no upstream can correlate two accounts back to
// one machine.
func TestCodexIdentityConfuseSeparatesUpstreamAccounts(t *testing.T) {
	cfg := codexTestConfuseConfig()
	turnMetadata := codexTestTurnMetadataJSON()

	render := func(authID string) []byte {
		body, _ := applyCodexIdentityConfuseBody(cfg, codexTestConfuseAuth(authID), codexTestUserPayload(), codexTestRequestBody(turnMetadata))
		return body
	}
	first := render("auth-a")
	second := render("auth-b")

	for _, path := range []string{
		"prompt_cache_key",
		"client_metadata.x-codex-installation-id",
		"client_metadata.turn_id",
		"client_metadata.x-codex-turn-metadata",
	} {
		if gjson.GetBytes(first, path).String() == gjson.GetBytes(second, path).String() {
			t.Fatalf("%s is identical across upstream accounts", path)
		}
	}
}

func TestCodexIdentityConfuseResponsePayloadRoundTripsEveryIdentifier(t *testing.T) {
	cfg := codexTestConfuseConfig()
	auth := codexTestConfuseAuth("auth-a")
	_, state := applyCodexIdentityConfuseBody(cfg, auth, codexTestUserPayload(), codexTestRequestBody(codexTestTurnMetadataJSON()))

	clientPayload := []byte(`{"installation_id":"` + codexTestRawInstallationID +
		`","session_id":"` + codexTestRawSessionID +
		`","turn_id":"` + codexTestRawTurnID +
		`","context_window_id":"` + codexTestRawContextWindow + `"}`)

	upstreamPayload := applyCodexIdentityConfuseResponsePayload(clientPayload, state)
	for _, raw := range []string{
		codexTestRawInstallationID,
		codexTestRawSessionID,
		codexTestRawTurnID,
		codexTestRawContextWindow,
	} {
		if bytes.Contains(upstreamPayload, []byte(raw)) {
			t.Fatalf("upstream payload still carries %s: %s", raw, upstreamPayload)
		}
	}

	restored := applyCodexIdentityExposeResponsePayload(upstreamPayload, state)
	if !bytes.Equal(restored, clientPayload) {
		t.Fatalf("round trip changed the payload:\n got %s\nwant %s", restored, clientPayload)
	}
}
