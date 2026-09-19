package management

import (
	"encoding/json"
	"testing"
)

func TestNormalizeAuthFileTicketPlan(t *testing.T) {
	for _, raw := range []string{`"team"`, `"pro"`, `"auto"`, `null`, `" TEAM "`} {
		fields, err := normalizeAuthFilePatchFields(map[string]json.RawMessage{"codex_turn_ticket_plan": json.RawMessage(raw)})
		if err != nil || fields["codex_turn_ticket_plan"] == nil {
			t.Fatalf("valid plan %s: %v", raw, err)
		}
	}
	for _, raw := range []string{`332`, `true`, `"business"`, `{}`} {
		if _, err := normalizeAuthFilePatchFields(map[string]json.RawMessage{"codex_turn_ticket_plan": json.RawMessage(raw)}); err == nil {
			t.Fatalf("accepted invalid plan %s", raw)
		}
	}
	if _, err := normalizeAuthFilePatchFields(map[string]json.RawMessage{"codex_turn_ticket_plan.nested": json.RawMessage(`"team"`)}); err == nil {
		t.Fatal("accepted nested policy")
	}
}
