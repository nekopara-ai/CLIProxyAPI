package helps

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps/codexmint"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/proxyutil"
	"golang.org/x/net/proxy"
)

func codexGatewayPayload(model string, ws bool) []byte {
	body := map[string]any{"model": model, "instructions": "", "store": false,
		"input":     []any{map[string]any{"type": "message", "role": "user", "content": []any{map[string]any{"type": "input_text", "text": "ping"}}}},
		"reasoning": map[string]any{"effort": "low"}, "tool_choice": "auto", "parallel_tool_calls": false}
	if ws {
		body["type"] = "response.create"
	} else {
		body["stream"] = true
	}
	data, _ := json.Marshal(body)
	return data
}

// Probe connections are dedicated synthetic requests, built using CPA's existing
// identity and proxy utilities. No business forwarding, retry or body translation
// implementation is replaced by this adapter.
func probeCodexGateway(ctx context.Context, auth *cliproxyauth.Auth, request codexmint.Request, transport, egress string, e CodexTurnTicketConfig) (codexmint.Attempt, error) {
	endpoint := strings.TrimSuffix(codexTurnTicketBaseURL(auth), "/") + "/responses"
	headers := http.Header{"Authorization": {"Bearer " + codexAuthAccessToken(auth)}, "Accept-Encoding": {"identity"}}
	applyCodexTurnTicketProbeIdentity(headers, auth, request.Model, e.Identity)
	if request.Pair != nil {
		headers.Set("Cookie", request.Pair.Cookie())
	}
	if transport == "websocket" {
		return probeCodexGatewayWS(ctx, endpoint, headers, request.Model, egress)
	}
	headers.Set("Content-Type", "application/json")
	headers.Set("Accept", "text/event-stream")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(codexGatewayPayload(request.Model, false)))
	if err != nil {
		return codexmint.Attempt{}, errors.New("invalid_probe_endpoint")
	}
	req.Header = headers
	req.Close = true
	client, err := codexTurnTicketProbeClient(ctx, auth, egress, time.Duration(e.ProbeTimeoutSeconds)*time.Second)
	if err != nil {
		return codexmint.Attempt{}, errors.New("probe_client")
	}
	privateClient := *client
	privateClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := privateClient.Do(req)
	if err != nil {
		return codexmint.Attempt{}, errors.New("probe_transport")
	}
	defer func() { _ = resp.Body.Close() }()
	result := codexmint.Attempt{Status: resp.StatusCode, Header: resp.Header.Clone(), State: ExtractCodexTurnState(resp.Header)}
	if resp.StatusCode != http.StatusOK {
		return result, nil
	}
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0]))
	if contentType != "text/event-stream" && contentType != "application/octet-stream" {
		return result, errors.New("probe_content_type")
	}
	event, err := codexmint.ReadCreated(resp.Body)
	result.Model, result.ResponseID, result.Failure, result.Terminal = event.Model, event.ID, event.Failure, event.Terminal
	if event.Status != 0 {
		result.Status = event.Status
	}
	return result, err
}

func probeCodexGatewayWS(ctx context.Context, endpoint string, headers http.Header, model, egress string) (codexmint.Attempt, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return codexmint.Attempt{}, errors.New("invalid_probe_endpoint")
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return codexmint.Attempt{}, errors.New("invalid_probe_endpoint")
	}
	headers.Set("OpenAI-Beta", "responses_websockets=2026-02-06")
	timeout := 25 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	dialer := websocket.Dialer{HandshakeTimeout: timeout, EnableCompression: false}
	setting, err := proxyutil.Parse(egress)
	if err != nil {
		return codexmint.Attempt{}, errors.New("probe_proxy")
	}
	if setting.Mode == proxyutil.ModeInherit {
		proxyURL, proxyErr := http.ProxyFromEnvironment(&http.Request{URL: mustCodexHTTPURL(u)})
		if proxyErr != nil {
			return codexmint.Attempt{}, errors.New("probe_proxy")
		}
		if proxyURL != nil {
			egress = proxyURL.String()
		} else {
			egress = "direct"
		}
	}
	d, _, err := proxyutil.BuildDialer(egress)
	if err != nil {
		return codexmint.Attempt{}, errors.New("probe_proxy")
	}
	if d != nil {
		contextDialer, ok := d.(proxy.ContextDialer)
		if !ok {
			return codexmint.Attempt{}, errors.New("probe_proxy_context")
		}
		dialer.NetDialContext = contextDialer.DialContext
	} else {
		dialer.NetDialContext = (&net.Dialer{}).DialContext
	}
	conn, resp, err := dialer.DialContext(ctx, u.String(), headers)
	result := codexmint.Attempt{}
	if resp != nil {
		result.Status = resp.StatusCode
		result.Header = resp.Header.Clone()
		result.State = ExtractCodexTurnState(resp.Header)
	}
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return result, errors.New("probe_websocket_handshake")
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	conn.SetReadLimit(codexmint.ScanLimit)
	if err = conn.WriteMessage(websocket.TextMessage, codexGatewayPayload(model, true)); err != nil {
		return result, errors.New("probe_websocket_write")
	}
	scanned := 0
	for messages := 0; messages < 64; messages++ {
		kind, data, readErr := conn.ReadMessage()
		if readErr != nil {
			return result, errors.New("probe_websocket_read")
		}
		scanned += len(data)
		if scanned > 4*codexmint.ScanLimit || kind != websocket.TextMessage {
			return result, errors.New("probe_websocket_limit")
		}
		event, eventErr := codexmint.ParseEvent(data, "")
		if eventErr != nil {
			return result, eventErr
		}
		if event.Failure != "" {
			result.Failure = event.Failure
			result.Terminal = event.Terminal
			result.Status = event.Status
			return result, nil
		}
		if event.State != "" {
			result.State = event.State
		}
		if event.ID != "" {
			result.Model = event.Model
			result.ResponseID = event.ID
		}
		// Metadata and created may arrive in either order. Both are required.
		if result.ResponseID != "" && result.State != "" {
			return result, nil
		}
	}
	return result, errors.New("probe_websocket_limit")
}
func mustCodexHTTPURL(u *url.URL) *url.URL {
	copyURL := *u
	if u.Scheme == "wss" {
		copyURL.Scheme = "https"
	} else {
		copyURL.Scheme = "http"
	}
	return &copyURL
}
