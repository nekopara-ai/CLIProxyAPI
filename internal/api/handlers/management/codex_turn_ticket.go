package management

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
)

// GetCodexTurnTicket reports the Codex turn-ticket subsystem state: whether the feature
// is enabled, the effective model scope, and how many tickets have been harvested.
//
// The payload is deliberately redacted. It contains counters and configuration shape
// only, never token material or credential identifiers, and harvest proxy URLs are
// reported in credential-stripped form.
func (h *Handler) GetCodexTurnTicket(c *gin.Context) {
	c.JSON(http.StatusOK, helps.SnapshotCodexTurnTickets())
}
