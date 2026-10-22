package fingerprint

import (
	"testing"
	"time"
)

func TestOpaqueCodexLegacyExpiryDoesNotDeferFingerprint(t *testing.T) {
	h := setup(t)
	h.cfg.Fingerprint.Models = []string{"gpt-6-sol"}
	h.a.Metadata["access_token"] = "opaque-imported-token"
	h.a.Metadata["expired"] = h.now.Add(-24 * time.Hour).Format(time.RFC3339)
	h.cycle()
	s := h.m.Snapshot(h.a)
	ms := s.ModelStates["gpt-6-sol"]
	if h.calls != 3 || ms.Wait != nil || ms.Result == nil || ms.Result.Status != "match" {
		t.Fatalf("valid opaque credential did not reach probe: calls=%d state=%+v", h.calls, ms)
	}
}
