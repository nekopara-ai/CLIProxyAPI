package helps

import (
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
)

// CodexRequestTurnState observes final outbound headers without retaining the
// token itself. injected must come from the injector for this exact attempt.
func CodexRequestTurnState(headers http.Header, injected bool) *usage.CodexTurnStateObservation {
	length := len(strings.TrimSpace(headers.Get(CodexTurnStateHeader)))
	if length > 64*1024 {
		return nil
	}
	source := "none"
	if length > 0 {
		source = "passthrough"
		if injected {
			source = "cache"
		}
	}
	return &usage.CodexTurnStateObservation{RequestLength: length, RequestSource: source}
}

func (r *UsageReporter) SetCodexTurnState(observation *usage.CodexTurnStateObservation) {
	if r == nil {
		return
	}
	if observation == nil {
		r.codexTurnState.Store(nil)
		return
	}
	copied := *observation
	r.codexTurnState.Store(&copied)
}
