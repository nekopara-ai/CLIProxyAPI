package management

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestPutConfigYAMLReloadsRuntimeWithoutFileWatcher(t *testing.T) {
	h := &Handler{cfg: &config.Config{Port: 18001}, configFilePath: filepath.Join(t.TempDir(), "config.yaml")}
	reloads, done := captureConfigReload(h)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPut, "/v0/management/config.yaml", strings.NewReader("port: 18002\ncodex:\n  turn-ticket:\n    enabled: true\n    routing-cookie-ttl-seconds: 240\n    routing-refresh-before-seconds: 60\n"))
	h.PutConfigYAML(c)
	if w.Code != http.StatusOK {
		t.Fatalf("save failed: status=%d body=%s", w.Code, w.Body.String())
	}
	reloaded := waitForAsyncReload(t, reloads)
	waitForReloadDone(t, done)
	if reloaded.Port != 18002 || reloaded.Codex.TurnTicket.RoutingCookieTTLSeconds != 240 || reloaded.Codex.TurnTicket.RoutingRefreshBeforeSeconds != 60 {
		t.Fatalf("runtime did not receive the complete saved configuration: %+v", reloaded.Codex.TurnTicket)
	}
}
