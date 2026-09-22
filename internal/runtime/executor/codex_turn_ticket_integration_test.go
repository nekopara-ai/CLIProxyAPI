package executor

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

// integrationTurnState builds a Fernet-shaped turn-state token of the requested length.
// The bytes past the nine-byte prefix are not a real ciphertext; the feature only ever
// reads that prefix, so this is exactly the shape the production code handles.
func integrationTurnState(t *testing.T, issueUnix int64, length int) string {
	t.Helper()
	payload := make([]byte, 0, length)
	payload = append(payload, 0x80)
	stamp := make([]byte, 8)
	binary.BigEndian.PutUint64(stamp, uint64(issueUnix))
	payload = append(payload, stamp...)
	for i := 0; i < length; i++ {
		payload = append(payload, 0)
	}
	for trim := len(payload); trim >= 9; trim-- {
		if candidate := base64.RawURLEncoding.EncodeToString(payload[:trim]); len(candidate) == length {
			return candidate
		}
	}
	t.Fatalf("could not build a %d-character turn state", length)
	return ""
}

func turnTicketIntegrationConfig(model string) *config.Config {
	cfg := &config.Config{}
	cfg.Codex.TurnTicket.Enabled = true
	cfg.Codex.TurnTicket.Models = []string{model}
	return cfg
}

func turnTicketLegacyIntegrationConfig(model string) *config.Config {
	cfg := turnTicketIntegrationConfig(model)
	legacy := false
	cfg.Codex.TurnTicket.AdaptiveInjection = &legacy
	return cfg
}

// TestCodexExecutorStreamInjectsHarvestedTurnTicket exercises the real executor path: a
// credential with a stored healthy ticket must send that ticket upstream even when the
// client supplied a degraded one, and the upstream's healthy response token must be
// captured passively for the next request.
func TestCodexExecutorStreamInjectsHarvestedTurnTicket(t *testing.T) {
	healthy := integrationTurnState(t, time.Now().Unix(), 292)
	degraded := integrationTurnState(t, time.Now().Unix(), 312)
	fresh := integrationTurnState(t, time.Now().Unix(), 292)

	var seen atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Store(r.Header.Get(helps.CodexTurnStateHeader))
		w.Header().Set(helps.CodexTurnStateHeader, fresh)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"object\":\"response\",\"status\":\"completed\",\"output\":[]}}\n\n"))
	}))
	defer server.Close()

	cfg := turnTicketLegacyIntegrationConfig("gpt-5.5")
	process := helps.ConfigureCodexTurnTickets(func() *config.Config { return cfg }, nil)
	defer helps.ConfigureCodexTurnTickets(nil, nil)
	process.Store.Store("integration-auth", "gpt-5.5", helps.NewCodexTurnTicket(healthy, time.Now(), time.Hour))

	auth := &cliproxyauth.Auth{ID: "integration-auth", Provider: "codex", Attributes: map[string]string{
		"base_url": server.URL,
		"api_key":  "integration-token",
	}}
	clientHeaders := http.Header{}
	clientHeaders.Set(helps.CodexTurnStateHeader, degraded)

	executor := NewCodexExecutor(&config.Config{})
	result, err := executor.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "gpt-5.5",
		Payload: []byte(`{"model":"gpt-5.5","input":"hello"}`),
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("openai-response"),
		Stream:       true,
		Headers:      clientHeaders,
	})
	if err != nil {
		t.Fatalf("ExecuteStream error: %v", err)
	}
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("stream error: %v", chunk.Err)
		}
	}

	got, _ := seen.Load().(string)
	if got != healthy {
		t.Fatalf("upstream saw turn-state length %d, want the harvested %d-character ticket", len(got), len(healthy))
	}
	if got == degraded {
		t.Fatal("the client-supplied degraded turn-state reached the upstream")
	}
	if captured := process.Store.Lookup("integration-auth", "gpt-5.5"); captured == nil || captured.State != fresh {
		t.Fatalf("passive harvest did not refresh the bucket: %#v", captured)
	}
}

// TestCodexExecutorStreamLeavesTurnStateAloneWhenDisabled proves the feature is inert on
// the real request path until an operator opts in: without a stored ticket the client's
// own header is forwarded unchanged.
func TestCodexExecutorStreamLeavesTurnStateAloneWhenDisabled(t *testing.T) {
	clientState := integrationTurnState(t, time.Now().Unix(), 312)

	var seen atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Store(r.Header.Get(helps.CodexTurnStateHeader))
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"object\":\"response\",\"status\":\"completed\",\"output\":[]}}\n\n"))
	}))
	defer server.Close()

	disabled := &config.Config{}
	process := helps.ConfigureCodexTurnTickets(func() *config.Config { return disabled }, nil)
	defer helps.ConfigureCodexTurnTickets(nil, nil)
	// A ticket exists in the store, but the feature is disabled, so it must not be replayed.
	process.Store.Store("integration-auth", "gpt-5.5", helps.NewCodexTurnTicket(integrationTurnState(t, time.Now().Unix(), 292), time.Now(), time.Hour))

	auth := &cliproxyauth.Auth{ID: "integration-auth", Provider: "codex", Attributes: map[string]string{
		"base_url": server.URL,
		"api_key":  "integration-token",
	}}
	clientHeaders := http.Header{}
	clientHeaders.Set(helps.CodexTurnStateHeader, clientState)

	executor := NewCodexExecutor(&config.Config{})
	result, err := executor.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "gpt-5.5",
		Payload: []byte(`{"model":"gpt-5.5","input":"hello"}`),
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("openai-response"),
		Stream:       true,
		Headers:      clientHeaders,
	})
	if err != nil {
		t.Fatalf("ExecuteStream error: %v", err)
	}
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("stream error: %v", chunk.Err)
		}
	}

	got, _ := seen.Load().(string)
	if got != clientState {
		t.Fatalf("upstream saw turn-state %q, want the passthrough client value", got)
	}
	if strings.Contains(got, "gAAAAA") && got != clientState {
		t.Fatalf("a stored ticket was injected while the feature was disabled")
	}
}

func TestCodexExecutorStreamInjectsImportedTeamTicket(t *testing.T) {
	healthy := integrationTurnState(t, time.Now().Unix(), 332)
	degraded := integrationTurnState(t, time.Now().Unix(), 356)
	fresh := integrationTurnState(t, time.Now().Unix(), 332)

	var seen atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Store(r.Header.Get(helps.CodexTurnStateHeader))
		w.Header().Set(helps.CodexTurnStateHeader, fresh)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"object\":\"response\",\"status\":\"completed\",\"output\":[]}}\n\n"))
	}))
	defer server.Close()

	cfg := turnTicketLegacyIntegrationConfig("gpt-5.5")
	process := helps.ConfigureCodexTurnTickets(func() *config.Config { return cfg }, nil)
	defer helps.ConfigureCodexTurnTickets(nil, nil)
	process.Store.Store("integration-auth", "gpt-5.5", helps.NewCodexTurnTicket(healthy, time.Now(), time.Hour))

	auth := &cliproxyauth.Auth{ID: "integration-auth", Provider: "codex", Attributes: map[string]string{
		"base_url": server.URL,
	}}
	auth.Metadata = map[string]any{"access_token": "opaque-imported-fixture", "account_id": "workspace-fixture", "codex_turn_ticket_plan": "team"}
	clientHeaders := http.Header{}
	clientHeaders.Set(helps.CodexTurnStateHeader, degraded)

	executor := NewCodexExecutor(&config.Config{})
	result, err := executor.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "gpt-5.5",
		Payload: []byte(`{"model":"gpt-5.5","input":"hello"}`),
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("openai-response"),
		Stream:       true,
		Headers:      clientHeaders,
	})
	if err != nil {
		t.Fatalf("ExecuteStream error: %v", err)
	}
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("stream error: %v", chunk.Err)
		}
	}

	got, _ := seen.Load().(string)
	if got != healthy {
		t.Fatalf("upstream saw turn-state length %d, want the harvested %d-character ticket", len(got), len(healthy))
	}
	if got == degraded {
		t.Fatal("the client-supplied degraded turn-state reached the upstream")
	}
	if captured := process.Store.Lookup("integration-auth", "gpt-5.5"); captured == nil || captured.State != fresh {
		t.Fatalf("passive harvest did not refresh the bucket: %#v", captured)
	}
}
