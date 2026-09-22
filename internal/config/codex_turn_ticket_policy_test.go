package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCodexTicketPolicyConfigSaveReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	input := `codex:
  turn-ticket:
    enabled: false
    personal-healthy-length: 780
    personal-degraded-length: 312
    team-healthy-length: 900
    team-degraded-length: 356
    block-on-degraded: false
    unknown-state-action: harvest
    validation-ticket-policy: healthy-or-empty
    routing-expiry-margin-seconds: 0
    require-model-match: false
    routing-cookie-names: []
    reject-status-codes: []
    harvest-reject-status-codes: [403, 503]
`
	if err := os.WriteFile(path, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = SaveConfigPreserveComments(path, cfg); err != nil {
		t.Fatal(err)
	}
	again, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	p := again.Codex.TurnTicket
	if p.Enabled || p.PersonalHealthyLength != 780 || p.TeamHealthyLength != 900 || p.PersonalDegradedLength != 312 || p.TeamDegradedLength != 356 || p.BlockOnDegraded == nil || *p.BlockOnDegraded || p.RequireModelMatch == nil || *p.RequireModelMatch || p.RoutingExpiryMarginSeconds == nil || *p.RoutingExpiryMarginSeconds != 0 || p.RejectStatusCodes == nil || len(p.RejectStatusCodes) != 0 || p.RoutingCookieNames == nil || len(p.RoutingCookieNames) != 0 || len(p.HarvestRejectStatusCodes) != 2 {
		t.Fatalf("policy changed on save: %+v", p)
	}
}

func TestCodexTicketPolicyRejectInvalidReload(t *testing.T) {
	for _, line := range []string{"personal-healthy-length: 312", "team-degraded-length: 780", "unknown-state-action: typo", "validation-ticket-policy: typo", "routing-expiry-margin-seconds: -1", "reject-status-codes: [200]", "routing-cookie-names: ['bad name']"} {
		t.Run(line, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte("codex:\n  turn-ticket:\n    "+line+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadConfig(path); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
}
