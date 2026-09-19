package helps

import (
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
)

func TestCodexRequestTurnStateRecordsSourceAndExplicitNone(t *testing.T) {
	for _, tc := range []struct {
		length   int
		injected bool
		source   string
	}{{292, true, "cache"}, {312, false, "passthrough"}, {0, false, "none"}, {0, true, "none"}} {
		headers := http.Header{}
		if tc.length > 0 {
			headers.Set(CodexTurnStateHeader, strings.Repeat("x", tc.length))
		}
		got := CodexRequestTurnState(headers, tc.injected)
		if got == nil || got.RequestLength != tc.length || got.RequestSource != tc.source {
			t.Fatalf("observation = %+v", got)
		}
		if got.RequestScope != "" {
			t.Fatal("HTTP request unexpectedly classified as a websocket connection")
		}
	}
	if got := CodexRequestTurnState(http.Header{CodexTurnStateHeader: []string{strings.Repeat("x", 65537)}}, false); got != nil {
		t.Fatal("oversized header should be unknown")
	}
}

func TestUsageReporterSnapshotsTicketObservation(t *testing.T) {
	reporter := &UsageReporter{}
	observation := &usage.CodexTurnStateObservation{RequestLength: 292, RequestSource: "cache"}
	reporter.SetCodexTurnState(observation)
	observation.RequestLength = 312
	if got := reporter.codexTurnState.Load(); got == nil || got.RequestLength != 292 {
		t.Fatal("reporter retained a mutable caller-owned observation")
	}
	otherAttempt := &UsageReporter{}
	if otherAttempt.codexTurnState.Load() != nil {
		t.Fatal("a new credential attempt inherited another attempt's ticket")
	}
	reporter.SetCodexTurnState(nil)
	if reporter.codexTurnState.Load() != nil {
		t.Fatal("unknown connection did not clear prior request metadata")
	}
}
