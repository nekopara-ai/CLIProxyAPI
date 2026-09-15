package executor

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func codexHygieneAuth() *cliproxyauth.Auth {
	return &cliproxyauth.Auth{ID: "auth-hygiene", Provider: "codex"}
}

func codexHygieneClientHeaders() http.Header {
	headers := http.Header{}
	headers.Set("Connection", "keep-alive")
	headers.Set("Keep-Alive", "timeout=5")
	headers.Set("Proxy-Connection", "keep-alive")
	headers.Set("Transfer-Encoding", "chunked")
	return headers
}

// TestCodexUpstreamRequestDropsConnectionSpecificHeaders guards the protocol
// violation that shipped upstream: the executor forced "Connection: Keep-Alive"
// onto an HTTP/2 request, which Go forwards verbatim even though RFC 9113
// forbids connection-specific fields. A downstream client must not be able to
// smuggle one in either.
func TestCodexUpstreamRequestDropsConnectionSpecificHeaders(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/codex/responses", nil)
	applyCodexHeaders(request, codexHygieneAuth(), "oauth-token", true, &config.Config{}, codexHygieneClientHeaders())

	for _, name := range connectionSpecificUpstreamHeaders {
		if got := request.Header.Get(name); got != "" {
			t.Fatalf("upstream header %s = %q, want it dropped", name, got)
		}
	}
}
