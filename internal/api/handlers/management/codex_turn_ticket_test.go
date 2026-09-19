package management

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
)

// TestGetCodexTurnTicketReportsRedactedState covers the management-facing counter export:
// the endpoint must report the effective configuration and harvest counters without
// leaking token material, credential identifiers, or harvest proxy credentials.
func TestGetCodexTurnTicketReportsRedactedState(t *testing.T) {
	const accessToken = "test-access-token-must-not-leak"
	cfg := &config.Config{}
	cfg.Codex.TurnTicket.Enabled = true
	cfg.Codex.TurnTicket.Models = []string{"gpt-5.5"}
	cfg.Codex.TurnTicket.HarvestProxyURLs = []string{"direct", "http://user:proxy-secret@127.0.0.1:8080"}
	process := helps.ConfigureCodexTurnTickets(func() *config.Config { return cfg }, nil)
	defer helps.ConfigureCodexTurnTickets(nil, nil)
	process.Store.Store("auth-a", "gpt-5.5", helps.NewCodexTurnTicket(testManagementTurnState(t), time.Now(), time.Hour))

	rec := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(rec)
	ginCtx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/codex-turn-ticket", nil)

	h := &Handler{}
	h.GetCodexTurnTicket(ginCtx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	for _, leaked := range []string{accessToken, "proxy-secret", "auth-a", "gAAAAA"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("management payload leaked %q: %s", leaked, body)
		}
	}

	var snapshot helps.CodexTurnTicketSnapshot
	if errUnmarshal := json.Unmarshal(rec.Body.Bytes(), &snapshot); errUnmarshal != nil {
		t.Fatalf("unmarshal payload: %v", errUnmarshal)
	}
	if !snapshot.Configured || !snapshot.Enabled {
		t.Fatalf("snapshot did not report the enabled feature: %+v", snapshot)
	}
	if snapshot.Buckets != 1 || snapshot.HealthyTickets != 1 {
		t.Fatalf("snapshot occupancy = %d buckets / %d healthy, want 1/1", snapshot.Buckets, snapshot.HealthyTickets)
	}
	if snapshot.HarvestProxyCount != 2 || len(snapshot.HarvestProxyURLs) != 2 {
		t.Fatalf("snapshot did not report both configured harvest egresses: %+v", snapshot)
	}
}

// TestGetCodexTurnTicketReportsUnconfiguredState keeps the endpoint useful when the
// subsystem has not been wired at all, for example in a process that never ran Run.
func TestGetCodexTurnTicketReportsUnconfiguredState(t *testing.T) {
	defer helps.ConfigureCodexTurnTickets(nil, nil)

	rec := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(rec)
	ginCtx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/codex-turn-ticket", nil)

	h := &Handler{}
	h.GetCodexTurnTicket(ginCtx)

	var snapshot helps.CodexTurnTicketSnapshot
	if errUnmarshal := json.Unmarshal(rec.Body.Bytes(), &snapshot); errUnmarshal != nil {
		t.Fatalf("unmarshal payload: %v", errUnmarshal)
	}
	if snapshot.Configured {
		t.Fatalf("snapshot reported a configured subsystem: %+v", snapshot)
	}
}

// testManagementTurnState builds a syntactically valid Fernet-shaped turn-state token.
func testManagementTurnState(t *testing.T) string {
	t.Helper()
	const wantLength = 292
	payload := make([]byte, 0, wantLength)
	payload = append(payload, 0x80)
	stamp := make([]byte, 8)
	now := uint64(time.Now().Unix())
	for i := 7; i >= 0; i-- {
		stamp[i] = byte(now)
		now >>= 8
	}
	payload = append(payload, stamp...)
	for i := 0; i < wantLength; i++ {
		payload = append(payload, 0)
	}
	for trim := len(payload); trim >= 9; trim-- {
		candidate := base64.RawURLEncoding.EncodeToString(payload[:trim])
		if len(candidate) == wantLength {
			return candidate
		}
	}
	t.Fatalf("could not build a %d-character turn state", wantLength)
	return ""
}
