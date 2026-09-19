package redisqueue

import (
	"context"
	"encoding/json"
	"testing"

	coreusage "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
)

func TestUsageQueueCarriesCodexRequestTicketWithoutResponseHeader(t *testing.T) {
	withEnabledQueue(t, func() {
		for _, observation := range []*coreusage.CodexTurnStateObservation{
			{RequestLength: 292, RequestSource: "cache"},
			{RequestLength: 312, RequestSource: "passthrough"},
			{RequestLength: 0, RequestSource: "none"},
			{RequestLength: 292, RequestSource: "cache", RequestScope: "websocket_handshake"},
			nil,
		} {
			(&usageQueuePlugin{}).HandleUsage(context.Background(), coreusage.Record{
				Provider: "codex", Model: "fixture-model", AuthIndex: "fixture-auth", CodexTurnState: observation,
			})
			payload := popSinglePayload(t)
			requireStringField(t, payload, "auth_index", "fixture-auth")
			requireMissingField(t, payload, "response_headers")
			if observation == nil {
				requireMissingField(t, payload, "codex_turn_state")
				continue
			}
			encoded, err := json.Marshal(payload["codex_turn_state"])
			if err != nil {
				t.Fatal(err)
			}
			var got coreusage.CodexTurnStateObservation
			if err := json.Unmarshal(encoded, &got); err != nil {
				t.Fatal(err)
			}
			if got != *observation {
				t.Fatalf("queue observation = %+v, want %+v", got, observation)
			}
		}
	})
}
