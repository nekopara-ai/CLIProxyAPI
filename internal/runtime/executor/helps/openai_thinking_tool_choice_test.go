package helps

import (
	"testing"

	"github.com/tidwall/gjson"
)

func TestOpenAIThinkingToolChoiceFallbackDefaultAndGuards(t *testing.T) {
	errorBody := []byte(`{"error":{"message":"Thinking mode does not support this tool_choice"}}`)
	for _, tc := range []struct {
		name    string
		payload string
		want    bool
	}{
		{"implicit thinking", `{"tool_choice":"required","messages":[]}`, true},
		{"budget removed", `{"tool_choice":"required","thinking":{"type":"enabled","budget_tokens":1024},"reasoning_effort":"high","reasoning":{"effort":"high"}}`, true},
		{"already disabled", `{"tool_choice":"required","thinking":{"type":"disabled"}}`, false},
		{"missing choice", `{"thinking":{"type":"enabled"}}`, false},
		{"null choice", `{"tool_choice":null}`, false},
		{"unknown choice", `{"tool_choice":"invalid"}`, false},
		{"invalid function", `{"tool_choice":{"type":"function"}}`, false},
		{"invalid JSON", `{"tool_choice":"required"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fallback, ok := OpenAIThinkingToolChoiceFallback([]byte(tc.payload), 400, errorBody)
			if ok != tc.want {
				t.Fatalf("fallback = %v, want %v", ok, tc.want)
			}
			if !ok {
				if string(fallback) != tc.payload {
					t.Fatal("ineligible payload changed")
				}
				return
			}
			if got := gjson.GetBytes(fallback, "thinking").Raw; got != `{"type":"disabled"}` {
				t.Errorf("thinking = %s", got)
			}
			for _, path := range []string{"reasoning_effort", "reasoning"} {
				if gjson.GetBytes(fallback, path).Exists() {
					t.Errorf("%s survived", path)
				}
			}
		})
	}
	for _, body := range []string{`{"error":{"message":"Thinking mode does not support this tool_choice"}`, `{"message":"Thinking mode does not support this tool_choice"}`, `{"error":{"message":123}}`} {
		if _, ok := OpenAIThinkingToolChoiceFallback([]byte(`{"tool_choice":"required"}`), 400, []byte(body)); ok {
			t.Errorf("malformed error accepted: %s", body)
		}
	}
}
