package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	_ "github.com/router-for-me/CLIProxyAPI/v7/internal/translator"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

const (
	codexOverloadEvent      = `{"type":"error","error":{"type":"service_unavailable_error","code":"server_is_overloaded","message":"Our servers are currently overloaded. Please try again later.","param":null},"sequence_number":2}`
	codexInvalidEvent       = `{"type":"error","error":{"type":"invalid_request_error","code":"invalid_value","message":"Invalid input."},"sequence_number":2}`
	codexCreatedEvent       = `{"type":"response.created","response":{"id":"resp_1","model":"gpt-5.6-terra"}}`
	codexInProgressEvent    = `{"type":"response.in_progress","response":{"id":"resp_1"}}`
	codexOutputAddedEvent   = `{"type":"response.output_item.added","item":{"id":"msg_1","type":"message","role":"assistant","content":[]},"output_index":0}`
	codexCompletedEventBody = `{"type":"response.completed","response":{"id":"resp_1","status":"completed","output":[{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"output_text","text":"hello"}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`
)

func codexBufferingConfig(enabled bool) *config.Config {
	return &config.Config{Codex: config.CodexConfig{StreamBootstrapBuffering: enabled}}
}

func codexTestAuth(baseURL string) *cliproxyauth.Auth {
	return &cliproxyauth.Auth{Attributes: map[string]string{"base_url": baseURL, "api_key": "test"}}
}

func codexTestRequest() (cliproxyexecutor.Request, cliproxyexecutor.Options) {
	return cliproxyexecutor.Request{
			Model:   "gpt-5.6-terra",
			Payload: []byte(`{"model":"gpt-5.6-terra","input":"hello"}`),
		}, cliproxyexecutor.Options{
			SourceFormat: sdktranslator.FromString("openai-response"),
			Stream:       true,
		}
}

// codexSSEServer streams the supplied event payloads as an HTTP 200 SSE response.
func codexSSEServer(events ...string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for _, event := range events {
			eventType := "message"
			if parsed := strings.SplitN(event, `"type":"`, 2); len(parsed) == 2 {
				eventType = strings.SplitN(parsed[1], `"`, 2)[0]
			}
			_, _ = w.Write([]byte("event: " + eventType + "\n"))
			_, _ = w.Write([]byte("data: " + event + "\n\n"))
		}
	}))
}

// codexWebsocketServer echoes the supplied frames after receiving the client request frame.
func codexWebsocketServer(t *testing.T, frames ...string) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade websocket: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()
		if _, _, errRead := conn.ReadMessage(); errRead != nil {
			t.Errorf("read websocket message: %v", errRead)
			return
		}
		for _, frame := range frames {
			_ = conn.WriteMessage(websocket.TextMessage, []byte(frame))
		}
	}))
}

func codexWebsocketRequest() (cliproxyexecutor.Request, cliproxyexecutor.Options) {
	return cliproxyexecutor.Request{
			Model:   "gpt-5.6-terra",
			Payload: []byte(`{"model":"gpt-5.6-terra","input":[{"type":"message","role":"user","content":"hello"}]}`),
		}, cliproxyexecutor.Options{
			SourceFormat: sdktranslator.FromString("openai-response"),
		}
}

// drainChunks collects every payload and the first error from a stream result.
func drainChunks(result *cliproxyexecutor.StreamResult) (string, error) {
	var payloads [][]byte
	var streamErr error
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			if streamErr == nil {
				streamErr = chunk.Err
			}
			continue
		}
		payloads = append(payloads, chunk.Payload)
	}
	return string(bytes.Join(payloads, []byte("\n"))), streamErr
}

// An overload rejection smuggled into an HTTP 200 stream must fail the whole attempt before any
// downstream chunk escapes, so the conductor can retry on another credential. A nil StreamResult
// is the invariant: with no channel there is no way for the buffered handshake to reach the client.
func TestCodexExecutor_BootstrapBuffering_OverloadFailsAttemptWithoutLeakingHandshake(t *testing.T) {
	server := codexSSEServer(codexCreatedEvent, codexInProgressEvent, codexOverloadEvent)
	defer server.Close()

	req, opts := codexTestRequest()
	result, err := NewCodexExecutor(codexBufferingConfig(true)).ExecuteStream(context.Background(), codexTestAuth(server.URL), req, opts)

	if err == nil {
		t.Fatal("expected ExecuteStream to fail the attempt on an overload rejection")
	}
	if result != nil {
		t.Fatal("expected nil result so no buffered handshake chunk can reach the client")
	}
	if got := statusCodeFromTestError(t, err); got != http.StatusServiceUnavailable {
		t.Fatalf("status code = %d, want %d (upstream hides 503 behind HTTP 200)", got, http.StatusServiceUnavailable)
	}
}

// A non-overload terminal failure must keep the original in-stream delivery semantics: the
// buffered handshake is flushed first and the error arrives as a stream chunk, so the conductor
// sees a committed stream and does not burn another credential on a request-level fault.
func TestCodexExecutor_BootstrapBuffering_NonOverloadStaysInStream(t *testing.T) {
	server := codexSSEServer(codexCreatedEvent, codexInProgressEvent, codexInvalidEvent)
	defer server.Close()

	req, opts := codexTestRequest()
	result, err := NewCodexExecutor(codexBufferingConfig(true)).ExecuteStream(context.Background(), codexTestAuth(server.URL), req, opts)

	if err != nil {
		t.Fatalf("non-overload failure must not fail the attempt synchronously: %v", err)
	}
	if result == nil {
		t.Fatal("expected a stream result for in-stream error delivery")
	}
	combined, streamErr := drainChunks(result)
	if streamErr == nil {
		t.Fatal("expected the invalid-request failure to arrive as an in-stream chunk error")
	}
	if !strings.Contains(combined, "response.created") {
		t.Fatalf("buffered handshake must be flushed before the in-stream error: %s", combined)
	}
	if got := statusCodeFromTestError(t, streamErr); got != http.StatusBadRequest {
		t.Fatalf("status code = %d, want %d", got, http.StatusBadRequest)
	}
}

// Once the buffer limit is exceeded the stream is released and overload probing stops, which
// bounds how long the downstream response headers can stay uncommitted.
func TestCodexExecutor_BootstrapBuffering_BufferLimitReleasesStream(t *testing.T) {
	events := make([]string, 0, codexBootstrapMaxBufferedEvents+2)
	for i := 0; i < codexBootstrapMaxBufferedEvents+1; i++ {
		events = append(events, fmt.Sprintf(`{"type":"response.in_progress","response":{"id":"resp_%d"}}`, i))
	}
	events = append(events, codexOverloadEvent)
	server := codexSSEServer(events...)
	defer server.Close()

	req, opts := codexTestRequest()
	result, err := NewCodexExecutor(codexBufferingConfig(true)).ExecuteStream(context.Background(), codexTestAuth(server.URL), req, opts)

	if err != nil {
		t.Fatalf("expected the stream to be released once the buffer limit is hit: %v", err)
	}
	if result == nil {
		t.Fatal("expected a stream result after the buffer limit released the stream")
	}
	_, streamErr := drainChunks(result)
	if streamErr == nil {
		t.Fatal("expected the overload error to be delivered in-stream after the limit was hit")
	}
}

// Buffered handshake events must be replayed in upstream order ahead of the first generated event.
func TestCodexExecutor_BootstrapBuffering_FlushesInOrderOnFirstOutput(t *testing.T) {
	server := codexSSEServer(codexCreatedEvent, codexInProgressEvent, codexOutputAddedEvent, codexCompletedEventBody)
	defer server.Close()

	req, opts := codexTestRequest()
	result, err := NewCodexExecutor(codexBufferingConfig(true)).ExecuteStream(context.Background(), codexTestAuth(server.URL), req, opts)
	if err != nil {
		t.Fatalf("unexpected ExecuteStream error: %v", err)
	}

	combined, streamErr := drainChunks(result)
	if streamErr != nil {
		t.Fatalf("unexpected chunk error: %v", streamErr)
	}
	createdAt := strings.Index(combined, "response.created")
	addedAt := strings.Index(combined, "response.output_item.added")
	if createdAt < 0 || addedAt < 0 {
		t.Fatalf("missing handshake or first generated event: %s", combined)
	}
	if createdAt > addedAt {
		t.Fatalf("buffered handshake must be replayed before the first generated event: %s", combined)
	}
}

// With the feature disabled the overload rejection keeps its legacy in-stream delivery.
func TestCodexExecutor_BootstrapBuffering_DefaultDisabledPassthrough(t *testing.T) {
	server := codexSSEServer(codexCreatedEvent, codexOverloadEvent)
	defer server.Close()

	req, opts := codexTestRequest()
	result, err := NewCodexExecutor(&config.Config{}).ExecuteStream(context.Background(), codexTestAuth(server.URL), req, opts)
	if err != nil {
		t.Fatalf("default unbuffered ExecuteStream returned error at call time: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result in default unbuffered mode")
	}
	_, streamErr := drainChunks(result)
	if streamErr == nil {
		t.Fatal("expected stream error in chunks for default unbuffered mode")
	}
	// Disabling the feature must restore the previous behaviour exactly, status classification
	// included: the 503 restoration is scoped to the buffered failover path, so an unbuffered
	// overload still classifies as a bad gateway and keeps its old cooldown treatment.
	if got := statusCodeFromTestError(t, streamErr); got != http.StatusBadGateway {
		t.Fatalf("status code = %d, want %d while buffering is disabled", got, http.StatusBadGateway)
	}
}

// A cancelled downstream request must surface the context error rather than being recorded as an
// upstream failure that penalises the credential.
func TestCodexExecutor_BootstrapBuffering_ContextCancelDuringBootstrap(t *testing.T) {
	server := codexSSEServer(codexCreatedEvent)
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req, opts := codexTestRequest()
	_, err := NewCodexExecutor(codexBufferingConfig(true)).ExecuteStream(ctx, codexTestAuth(server.URL), req, opts)
	if err == nil {
		t.Fatal("expected an error for a cancelled bootstrap")
	}
	if !strings.Contains(err.Error(), context.Canceled.Error()) {
		t.Fatalf("expected the context cancellation to surface, got: %v", err)
	}
}

func TestCodexExecutor_BootstrapBuffering_CleanEOFBeforeOutputIsLifecycle408(t *testing.T) {
	server := codexSSEServer(codexCreatedEvent, codexInProgressEvent)
	defer server.Close()

	req, opts := codexTestRequest()
	result, err := NewCodexExecutor(codexBufferingConfig(true)).ExecuteStream(context.Background(), codexTestAuth(server.URL), req, opts)
	if err == nil {
		t.Fatal("expected clean EOF before generated output to fail the uncommitted attempt")
	}
	if result != nil {
		t.Fatal("expected nil result so buffered handshake metadata cannot reach the client")
	}
	if got := statusCodeFromTestError(t, err); got != http.StatusRequestTimeout {
		t.Fatalf("status code = %d, want %d", got, http.StatusRequestTimeout)
	}

	var lifecycleErr cliproxyexecutor.ConnectionLifecycleError
	if !errors.As(err, &lifecycleErr) || lifecycleErr == nil || !lifecycleErr.IsConnectionLifecycle() {
		t.Fatalf("error type = %T, want a connection lifecycle marker", err)
	}
	var requestScopedErr cliproxyexecutor.RequestScopedError
	if errors.As(err, &requestScopedErr) {
		t.Fatalf("precommit EOF error type = %T, must not be request-scoped", err)
	}
}

func TestCodexExecutor_CleanEOFWithBufferingDisabledStaysRequestScopedInStream(t *testing.T) {
	server := codexSSEServer(codexCreatedEvent, codexInProgressEvent)
	defer server.Close()

	req, opts := codexTestRequest()
	result, err := NewCodexExecutor(codexBufferingConfig(false)).ExecuteStream(context.Background(), codexTestAuth(server.URL), req, opts)
	if err != nil {
		t.Fatalf("default unbuffered EOF must not fail synchronously: %v", err)
	}
	if result == nil {
		t.Fatal("expected stream result while buffering is disabled")
	}
	_, streamErr := drainChunks(result)
	assertRequestScopedIncompleteStreamError(t, streamErr)
}

func TestCodexExecutor_BootstrapBuffering_CleanEOFAfterOutputStaysRequestScopedInStream(t *testing.T) {
	server := codexSSEServer(codexCreatedEvent, codexInProgressEvent, codexOutputAddedEvent)
	defer server.Close()

	req, opts := codexTestRequest()
	result, err := NewCodexExecutor(codexBufferingConfig(true)).ExecuteStream(context.Background(), codexTestAuth(server.URL), req, opts)
	if err != nil {
		t.Fatalf("postcommit EOF must not fail synchronously: %v", err)
	}
	if result == nil {
		t.Fatal("expected stream result after the first generated output event")
	}
	combined, streamErr := drainChunks(result)
	if !strings.Contains(combined, "response.output_item.added") {
		t.Fatalf("generated output event was not delivered before EOF: %s", combined)
	}
	assertRequestScopedIncompleteStreamError(t, streamErr)
}

func assertRequestScopedIncompleteStreamError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an incomplete-stream error")
	}
	if got := statusCodeFromTestError(t, err); got != http.StatusRequestTimeout {
		t.Fatalf("status code = %d, want %d", got, http.StatusRequestTimeout)
	}
	var requestScopedErr cliproxyexecutor.RequestScopedError
	if !errors.As(err, &requestScopedErr) || requestScopedErr == nil || !requestScopedErr.IsRequestScoped() {
		t.Fatalf("error type = %T, want request-scoped marker", err)
	}
	var lifecycleErr cliproxyexecutor.ConnectionLifecycleError
	if errors.As(err, &lifecycleErr) {
		t.Fatalf("committed EOF error type = %T, must not carry a lifecycle retry marker", err)
	}
}

func TestCodexManager_BootstrapBuffering_PrecommitEOFFailsOverWithoutCooling(t *testing.T) {
	var firstCalls atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		firstCalls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		writeCodexSSETestEvent(w, codexCreatedEvent)
		writeCodexSSETestEvent(w, codexInProgressEvent)
	}))
	defer first.Close()

	var secondCalls atomic.Int32
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		secondCalls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		writeCodexSSETestEvent(w, codexCreatedEvent)
		writeCodexSSETestEvent(w, codexOutputAddedEvent)
		writeCodexSSETestEvent(w, codexCompletedEventBody)
	}))
	defer second.Close()

	manager, firstAuth := newCodexEOFTestManager(t, "codex-precommit-eof", true, first.URL, second.URL)
	req, opts := codexTestRequest()
	result, err := manager.ExecuteStream(context.Background(), []string{"codex"}, req, opts)
	if err != nil {
		t.Fatalf("precommit EOF did not fail over to the second credential: %v", err)
	}
	if result == nil {
		t.Fatal("expected stream result from the second credential")
	}
	combined, streamErr := drainChunks(result)
	if streamErr != nil {
		t.Fatalf("second credential stream error: %v", streamErr)
	}
	if !strings.Contains(combined, "response.completed") {
		t.Fatalf("second credential did not complete the stream: %s", combined)
	}
	if got := firstCalls.Load(); got != 1 {
		t.Fatalf("first credential calls = %d, want 1", got)
	}
	if got := secondCalls.Load(); got != 1 {
		t.Fatalf("second credential calls = %d, want 1", got)
	}

	firstState, ok := manager.GetByID(firstAuth.ID)
	if !ok || firstState == nil {
		t.Fatal("first credential is no longer registered")
	}
	if firstState.Unavailable || !firstState.NextRetryAfter.IsZero() {
		t.Fatalf("connection lifecycle failure cooled credential: unavailable=%v next_retry_after=%v", firstState.Unavailable, firstState.NextRetryAfter)
	}
	if state := firstState.ModelStates[req.Model]; state != nil && (state.Unavailable || !state.NextRetryAfter.IsZero()) {
		t.Fatalf("connection lifecycle failure cooled model: unavailable=%v next_retry_after=%v", state.Unavailable, state.NextRetryAfter)
	}
}

func TestCodexManager_BootstrapBuffering_PostcommitEOFDoesNotTrySecondCredential(t *testing.T) {
	var firstCalls atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		firstCalls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		writeCodexSSETestEvent(w, codexCreatedEvent)
		writeCodexSSETestEvent(w, codexOutputAddedEvent)
	}))
	defer first.Close()

	var secondCalls atomic.Int32
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		secondCalls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		writeCodexSSETestEvent(w, codexCreatedEvent)
		writeCodexSSETestEvent(w, codexOutputAddedEvent)
		writeCodexSSETestEvent(w, codexCompletedEventBody)
	}))
	defer second.Close()

	manager, _ := newCodexEOFTestManager(t, "codex-postcommit-eof", true, first.URL, second.URL)
	req, opts := codexTestRequest()
	result, err := manager.ExecuteStream(context.Background(), []string{"codex"}, req, opts)
	if err != nil {
		t.Fatalf("postcommit EOF must be returned through the selected stream: %v", err)
	}
	if result == nil {
		t.Fatal("expected committed stream from the first credential")
	}
	combined, streamErr := drainChunks(result)
	if !strings.Contains(combined, "response.output_item.added") {
		t.Fatalf("first credential output was not delivered: %s", combined)
	}
	assertRequestScopedIncompleteStreamError(t, streamErr)
	if got := firstCalls.Load(); got != 1 {
		t.Fatalf("first credential calls = %d, want 1", got)
	}
	if got := secondCalls.Load(); got != 0 {
		t.Fatalf("second credential calls = %d, want 0 after output was committed", got)
	}
}

func writeCodexSSETestEvent(w http.ResponseWriter, event string) {
	eventType := "message"
	if parsed := strings.SplitN(event, `"type":"`, 2); len(parsed) == 2 {
		eventType = strings.SplitN(parsed[1], `"`, 2)[0]
	}
	_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventType, event)
}

func newCodexEOFTestManager(t *testing.T, idPrefix string, buffering bool, firstURL, secondURL string) (*cliproxyauth.Manager, *cliproxyauth.Auth) {
	t.Helper()

	manager := cliproxyauth.NewManager(nil, nil, nil)
	manager.SetRetryConfig(0, 0, 2)
	manager.RegisterExecutor(NewCodexExecutor(codexBufferingConfig(buffering)))

	auths := []*cliproxyauth.Auth{
		{
			ID:       idPrefix + "-a",
			Provider: "codex",
			Status:   cliproxyauth.StatusActive,
			Attributes: map[string]string{
				"api_key":  "test-a",
				"base_url": firstURL,
				"priority": "100",
			},
		},
		{
			ID:       idPrefix + "-b",
			Provider: "codex",
			Status:   cliproxyauth.StatusActive,
			Attributes: map[string]string{
				"api_key":  "test-b",
				"base_url": secondURL,
				"priority": "90",
			},
		},
	}

	modelRegistry := registry.GetGlobalRegistry()
	for _, auth := range auths {
		modelRegistry.RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: "gpt-5.6-terra"}})
		if _, err := manager.Register(context.Background(), auth); err != nil {
			t.Fatalf("register auth %s: %v", auth.ID, err)
		}
	}
	t.Cleanup(func() {
		for _, auth := range auths {
			modelRegistry.UnregisterClient(auth.ID)
		}
	})

	return manager, auths[0]
}

func TestCodexWebsocketsExecutor_BootstrapBuffering_OverloadFailsAttempt(t *testing.T) {
	server := codexWebsocketServer(t, codexCreatedEvent, codexInProgressEvent, codexOverloadEvent)
	defer server.Close()

	req, opts := codexWebsocketRequest()
	result, err := NewCodexWebsocketsExecutor(codexBufferingConfig(true)).ExecuteStream(context.Background(), codexTestAuth(server.URL), req, opts)

	if err == nil {
		t.Fatal("expected ExecuteStream to fail the attempt on a websocket overload rejection")
	}
	if result != nil {
		t.Fatal("expected nil result so no buffered handshake frame can reach the client")
	}
	if got := statusCodeFromTestError(t, err); got != http.StatusServiceUnavailable {
		t.Fatalf("status code = %d, want %d", got, http.StatusServiceUnavailable)
	}
}

// The websocket transport prefixes response events with private metadata frames. Frame order
// below matches live wire capture: codex.rate_limits and codex.response.metadata both arrive
// *before* response.created, making the first generated event the fifth frame. They must be
// treated as handshake events, otherwise a fixed 3-event window would release the stream at
// response.created and never observe the rejection.
func TestCodexWebsocketsExecutor_BootstrapBuffering_PrivateHandshakeFramesDoNotExhaustWindow(t *testing.T) {
	server := codexWebsocketServer(t,
		`{"type":"codex.rate_limits","rate_limits":{"primary":{"used_percent":1}}}`,
		`{"type":"codex.response.metadata","metadata":{"conversation_id":"conv_1"}}`,
		codexCreatedEvent,
		codexInProgressEvent,
		codexOverloadEvent,
	)
	defer server.Close()

	req, opts := codexWebsocketRequest()
	result, err := NewCodexWebsocketsExecutor(codexBufferingConfig(true)).ExecuteStream(context.Background(), codexTestAuth(server.URL), req, opts)

	if err == nil {
		t.Fatal("expected the overload rejection to be caught past the private handshake frames")
	}
	if result != nil {
		t.Fatal("expected nil result so no buffered frame can reach the client")
	}
	if got := statusCodeFromTestError(t, err); got != http.StatusServiceUnavailable {
		t.Fatalf("status code = %d, want %d", got, http.StatusServiceUnavailable)
	}
}

func TestCodexWebsocketsExecutor_BootstrapBuffering_NonOverloadStaysInStream(t *testing.T) {
	server := codexWebsocketServer(t, codexCreatedEvent, codexInProgressEvent, codexInvalidEvent)
	defer server.Close()

	req, opts := codexWebsocketRequest()
	result, err := NewCodexWebsocketsExecutor(codexBufferingConfig(true)).ExecuteStream(context.Background(), codexTestAuth(server.URL), req, opts)

	if err != nil {
		t.Fatalf("non-overload failure must not fail the attempt synchronously: %v", err)
	}
	if result == nil {
		t.Fatal("expected a stream result for in-stream error delivery")
	}
	combined, streamErr := drainChunks(result)
	if streamErr == nil {
		t.Fatal("expected the invalid-request failure to arrive as an in-stream chunk error")
	}
	if !strings.Contains(combined, "response.created") {
		t.Fatalf("buffered handshake must be flushed before the in-stream error: %s", combined)
	}
}

func TestCodexWebsocketsExecutor_BootstrapBuffering_FlushesInOrderOnFirstOutput(t *testing.T) {
	server := codexWebsocketServer(t,
		codexCreatedEvent,
		codexInProgressEvent,
		codexOutputAddedEvent,
		`{"type":"response.completed","response":{"id":"resp_1","output":[],"usage":{"input_tokens":0,"output_tokens":0,"total_tokens":0}}}`,
	)
	defer server.Close()

	req, opts := codexWebsocketRequest()
	result, err := NewCodexWebsocketsExecutor(codexBufferingConfig(true)).ExecuteStream(context.Background(), codexTestAuth(server.URL), req, opts)
	if err != nil {
		t.Fatalf("unexpected ExecuteStream error: %v", err)
	}

	combined, streamErr := drainChunks(result)
	if streamErr != nil {
		t.Fatalf("unexpected chunk error: %v", streamErr)
	}
	createdAt := strings.Index(combined, "response.created")
	addedAt := strings.Index(combined, "response.output_item.added")
	if createdAt < 0 || addedAt < 0 {
		t.Fatalf("missing handshake or first generated event: %s", combined)
	}
	if createdAt > addedAt {
		t.Fatalf("buffered handshake must be replayed before the first generated event: %s", combined)
	}
}

func TestCodexWebsocketsExecutor_BootstrapBuffering_DefaultDisabledPassthrough(t *testing.T) {
	server := codexWebsocketServer(t, codexCreatedEvent, codexOverloadEvent)
	defer server.Close()

	req, opts := codexWebsocketRequest()
	result, err := NewCodexWebsocketsExecutor(&config.Config{}).ExecuteStream(context.Background(), codexTestAuth(server.URL), req, opts)
	if err != nil {
		t.Fatalf("default unbuffered ExecuteStream returned error at call time: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result in default unbuffered mode")
	}
	_, streamErr := drainChunks(result)
	if streamErr == nil {
		t.Fatal("expected stream error in chunks for default unbuffered mode")
	}
	if got := statusCodeFromTestError(t, streamErr); got != http.StatusBadGateway {
		t.Fatalf("status code = %d, want %d while buffering is disabled", got, http.StatusBadGateway)
	}
}

// The 503 restoration is scoped to the buffered failover path, so this only covers which
// rejections are eligible to replace the whole attempt.
func TestIsCodexOverloadBootstrapFailureRejectsRequestFaults(t *testing.T) {
	notOverload := []string{
		`{"error":{"type":"invalid_request_error","code":"invalid_value"}}`,
		`{"error":{"type":"authentication_error","code":"invalid_api_key"}}`,
		`{"error":{"type":"upstream_error","code":"unknown"}}`,
	}
	for _, body := range notOverload {
		if isCodexOverloadBootstrapFailure([]byte(body)) {
			t.Fatalf("request-level fault must not trigger bootstrap failover: %s", body)
		}
	}
	if !isCodexOverloadBootstrapFailure([]byte(`{"error":{"type":"rate_limit_error","code":"rate_limit_exceeded"}}`)) {
		t.Fatal("rate limit rejections should be eligible for bootstrap failover")
	}
}

// codexWebsocketServerHoldingConnection behaves like codexWebsocketServer but keeps the upstream
// connection open after writing the frames, so the executor's own teardown path is the only
// source of session invalidation. With the plain helper the connection closes immediately, the
// reader goroutine observes EOF first and reports upstream_disconnected, which both masks the
// path under test and can make a disconnect assertion pass for the wrong reason.
func codexWebsocketServerHoldingConnection(t *testing.T, frames ...string) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade websocket: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()
		if _, _, errRead := conn.ReadMessage(); errRead != nil {
			t.Errorf("read websocket message: %v", errRead)
			return
		}
		for _, frame := range frames {
			_ = conn.WriteMessage(websocket.TextMessage, []byte(frame))
		}
		for {
			if _, _, errRead := conn.ReadMessage(); errRead != nil {
				return
			}
		}
	}))
}

// executeWebsocketStreamInSession runs ExecuteStream bound to a named execution session and
// reports whether the upstream teardown was signalled to the downstream handler.
//
// The downstream Responses WebSocket handler subscribes to UpstreamDisconnectChan and closes
// the client connection as soon as a disconnect is published. A bootstrap overload is retried
// on another credential, so publishing there would tear down the client connection before the
// retry can deliver anything, and the client would observe an abnormal close with zero frames.
func executeWebsocketStreamInSession(t *testing.T, frames ...string) (notified bool, err error) {
	t.Helper()

	server := codexWebsocketServerHoldingConnection(t, frames...)
	defer server.Close()

	exec := NewCodexWebsocketsExecutor(codexBufferingConfig(true))
	exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}

	const sessionID = "bootstrap-session"
	disconnectCh := exec.UpstreamDisconnectChan(sessionID)
	if disconnectCh == nil {
		t.Fatal("expected a disconnect channel")
	}

	req, opts := codexWebsocketRequest()
	opts.Metadata = map[string]any{cliproxyexecutor.ExecutionSessionMetadataKey: sessionID}
	_, err = exec.ExecuteStream(context.Background(), codexTestAuth(server.URL), req, opts)

	select {
	case <-disconnectCh:
		notified = true
	default:
	}
	return notified, err
}

func TestCodexWebsocketsExecutor_BootstrapOverload_DoesNotNotifyDownstreamDisconnect(t *testing.T) {
	notified, err := executeWebsocketStreamInSession(t, codexCreatedEvent, codexInProgressEvent, codexOverloadEvent)

	if err == nil {
		t.Fatal("expected the overload rejection to fail the attempt")
	}
	if got := statusCodeFromTestError(t, err); got != http.StatusServiceUnavailable {
		t.Fatalf("status code = %d, want %d", got, http.StatusServiceUnavailable)
	}
	if notified {
		t.Fatal("bootstrap overload must not signal a downstream disconnect: the conductor still has to retry on another credential, and signalling closes the client connection with zero frames delivered")
	}
}

// A non-overload terminal failure is delivered in-stream and genuinely ends the session, so it
// must keep signalling the disconnect exactly as it did before buffering existed.
func TestCodexWebsocketsExecutor_BootstrapNonOverload_StillNotifiesDownstreamDisconnect(t *testing.T) {
	notified, err := executeWebsocketStreamInSession(t, codexCreatedEvent, codexInProgressEvent, codexInvalidEvent)

	if err != nil {
		t.Fatalf("non-overload failures stay in-stream, got err = %v", err)
	}
	if !notified {
		t.Fatal("a terminal failure that is delivered in-stream must still signal the downstream disconnect")
	}
}
