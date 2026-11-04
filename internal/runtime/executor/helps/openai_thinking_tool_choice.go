package helps

import (
	"github.com/MoeForge/moego/ojson"
	"net/http"
	"strings"
)

// OpenAIThinkingToolChoiceFallback preserves an explicit tool constraint when
// an OpenAI-compatible upstream rejects it in thinking mode. It also handles
// upstreams that enable thinking by default, without a client thinking field.
func OpenAIThinkingToolChoiceFallback(payload []byte, status int, errorBody []byte) ([]byte, bool) {
	if status != http.StatusBadRequest || !ojson.ValidBytes(errorBody) || !ojson.ValidBytes(payload) {
		return payload, false
	}
	message := ojson.GetBytes(errorBody, "error.message")
	if message.Type != ojson.String || !strings.Contains(strings.ToLower(message.String()), "thinking mode does not support this tool_choice") {
		return payload, false
	}
	choice := ojson.GetBytes(payload, "tool_choice")
	constrained := choice.Type == ojson.String && (choice.String() == "required" || choice.String() == "none")
	if choice.IsObject() {
		constrained = choice.Get("type").String() == "function" && choice.Get("function.name").String() != ""
	}
	if !constrained || ojson.GetBytes(payload, "thinking.type").String() == "disabled" {
		return payload, false
	}
	// Replace the whole object so a budget or adaptive setting cannot survive.
	fallback, err := ojson.SetRawBytes(payload, "thinking", []byte(`{"type":"disabled"}`))
	if err != nil {
		return payload, false
	}
	for _, path := range []string{"reasoning_effort", "reasoning", "enable_thinking", "thinking_budget"} {
		fallback, err = ojson.DeleteBytes(fallback, path)
		if err != nil {
			return payload, false
		}
	}
	return fallback, true
}
