package helps

import (
	"context"
	"net/http"
	"testing"

	"github.com/gorilla/websocket"
)

func TestGatewayWebSocketRouteFromMetadataNotHandshake(t *testing.T) {
	cfg, auth, p := gatewayFixture(t, func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = conn.Close() }()
		if _, _, err := conn.ReadMessage(); err != nil {
			t.Error(err)
			return
		}
		_ = conn.WriteJSON(map[string]any{"type": "response.created", "response": map[string]string{"id": "resp_mock", "model": "A"}})
		headers := gatewayTestHeaders("unified-88")
		_ = conn.WriteJSON(map[string]any{"type": "codex.response.metadata", "headers": map[string]any{
			"x-codex-turn-state": []string{headers.Get(CodexTurnStateHeader)}, "set-cookie": headers.Values("Set-Cookie"),
		}})
	})
	auth.Attributes["websockets"] = "true"
	cfg.Codex.TurnTicket.MintTransports = []string{"websocket"}
	p.Harvester.probeAll(context.Background())
	if !ApplyCodexTurnTicket(auth, "A", http.Header{}, WithCodexMintTransport(context.Background(), "websocket")) {
		t.Fatal("metadata cookie array not used for WS acquisition")
	}
	if ApplyCodexTurnTicket(auth, "A", http.Header{}) {
		t.Fatal("WS route leaked into SSE scope")
	}
}
