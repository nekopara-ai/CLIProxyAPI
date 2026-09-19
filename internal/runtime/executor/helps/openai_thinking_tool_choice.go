package helps

import (
	"net/http"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// OpenAIThinkingToolChoiceFallback preserves an explicit tool constraint when
// an OpenAI-compatible upstream rejects it in thinking mode. It also handles
// upstreams that enable thinking by default, without a client thinking field.
func OpenAIThinkingToolChoiceFallback(payload []byte, status int, errorBody []byte) ([]byte, bool) {
	if status != http.StatusBadRequest || !gjson.ValidBytes(errorBody) || !gjson.ValidBytes(payload) {
		return payload, false
	}
	message := gjson.GetBytes(errorBody, "error.message")
	if message.Type != gjson.String || !strings.Contains(strings.ToLower(message.String()), "thinking mode does not support this tool_choice") {
		return payload, false
	}
	choice := gjson.GetBytes(payload, "tool_choice")
	constrained := choice.Type == gjson.String && (choice.String() == "required" || choice.String() == "none")
	if choice.IsObject() {
		constrained = choice.Get("type").String() == "function" && choice.Get("function.name").String() != ""
	}
	if !constrained || gjson.GetBytes(payload, "thinking.type").String() == "disabled" {
		return payload, false
	}
	// Replace the whole object so a budget or adaptive setting cannot survive.
	fallback, err := sjson.SetRawBytes(payload, "thinking", []byte(`{"type":"disabled"}`))
	if err != nil {
		return payload, false
	}
	for _, path := range []string{"reasoning_effort", "reasoning", "enable_thinking", "thinking_budget"} {
		fallback, err = sjson.DeleteBytes(fallback, path)
		if err != nil {
			return payload, false
		}
	}
	return fallback, true
}
