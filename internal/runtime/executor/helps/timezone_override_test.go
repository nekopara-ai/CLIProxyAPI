package helps

import (
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/tidwall/gjson"
)

func TestApplyTimezoneOverrideRewritesCodexAndClaudeFields(t *testing.T) {
	now := time.Date(2026, 9, 15, 1, 0, 0, 0, time.UTC)
	cfg := &config.Config{TimezoneOverride: "America/New_York"}
	payload := []byte(`{
		"input": [
			{
				"type": "message",
				"role": "user",
				"content": [
					{"type": "input_text", "text": "<environment_context>\n  <cwd>/repo</cwd>\n  <current_date>2026-07-27</current_date>\n  <timezone>Etc/UTC</timezone>\n</environment_context>"},
					{"type": "input_text", "text": "keep <timezone>Asia/Shanghai</timezone> in user code"}
				]
			},
			{
				"type": "additional_tools",
				"tools": [
					{"type": "web_search", "user_location": {"type": "approximate", "city": "Beijing", "timezone": "Asia/Shanghai"}}
				]
			}
		],
		"tools": [
			{"type": "web_search", "user_location": {"type": "approximate", "timezone": "Etc/UTC"}},
			{"type": "function", "name": "get_time", "parameters": {"properties": {"timezone": {"type": "string"}}}}
		],
		"messages": [
			{"role": "user", "content": [{"type": "text", "text": "<system-reminder>\nAs you answer the user's questions, you can use the following context:\n# currentDate\nToday's date is 2026-07-27.\n</system-reminder>"}]}
		]
	}`)

	out := ApplyTimezoneOverrideAt(cfg, payload, now)
	envText := gjson.GetBytes(out, "input.0.content.0.text").String()
	if got := extractXMLTag(envText, "timezone"); got != "America/New_York" {
		t.Fatalf("environment timezone = %q, want America/New_York; env=%q", got, envText)
	}
	if got := extractXMLTag(envText, "current_date"); got != "2026-09-14" {
		t.Fatalf("environment current_date = %q, want 2026-09-14; env=%q", got, envText)
	}
	userText := gjson.GetBytes(out, "input.0.content.1.text").String()
	if userText != "keep <timezone>Asia/Shanghai</timezone> in user code" {
		t.Fatalf("user text rewritten: %q", userText)
	}
	if got := gjson.GetBytes(out, "tools.0.user_location.timezone").String(); got != "America/New_York" {
		t.Fatalf("tools user_location.timezone = %q", got)
	}
	if got := gjson.GetBytes(out, "input.1.tools.0.user_location.timezone").String(); got != "America/New_York" {
		t.Fatalf("additional_tools user_location.timezone = %q", got)
	}
	if gjson.GetBytes(out, "tools.1.parameters.properties.timezone.type").String() != "string" {
		t.Fatalf("tool schema timezone property was rewritten: %s", out)
	}
	reminder := gjson.GetBytes(out, "messages.0.content.0.text").String()
	if !containsDate(reminder, "2026-09-14") || containsDate(reminder, "2026-07-27") {
		t.Fatalf("claude currentDate reminder = %q", reminder)
	}
}

func TestApplyTimezoneOverrideNoopsWhenUnsetOrInvalid(t *testing.T) {
	payload := []byte(`{"tools":[{"type":"web_search","user_location":{"timezone":"Etc/UTC"}}]}`)
	if got := string(ApplyTimezoneOverride(&config.Config{}, payload)); got != string(payload) {
		t.Fatalf("empty override changed payload: %s", got)
	}
	if got := string(ApplyTimezoneOverride(&config.Config{TimezoneOverride: "not/a-timezone"}, payload)); got != string(payload) {
		t.Fatalf("invalid override changed payload: %s", got)
	}
	if TimezoneOverrideLocation(&config.Config{TimezoneOverride: "America/New_York"}) == nil {
		t.Fatal("valid override location is nil")
	}
}

func TestApplyTimezoneOverrideInsertsMissingEnvironmentTags(t *testing.T) {
	now := time.Date(2026, 9, 15, 1, 0, 0, 0, time.UTC)
	cfg := &config.Config{TimezoneOverride: "Pacific/Honolulu"}
	payload := []byte(`{"input":[{"content":[{"text":"<environment_context>\n  <cwd>/repo</cwd>\n</environment_context>"}]}]}`)
	out := ApplyTimezoneOverrideAt(cfg, payload, now)
	envText := gjson.GetBytes(out, "input.0.content.0.text").String()
	if got := extractXMLTag(envText, "timezone"); got != "Pacific/Honolulu" {
		t.Fatalf("inserted timezone = %q; env=%q", got, envText)
	}
	if got := extractXMLTag(envText, "current_date"); got != "2026-09-14" {
		t.Fatalf("inserted current_date = %q; env=%q", got, envText)
	}
}

func extractXMLTag(text, name string) string {
	open := "<" + name + ">"
	close := "</" + name + ">"
	from := indexOf(text, open)
	if from < 0 {
		return ""
	}
	from += len(open)
	to := indexOf(text[from:], close)
	if to < 0 {
		return ""
	}
	return text[from : from+to]
}

func containsDate(text, date string) bool {
	return indexOf(text, "Today's date is "+date+".") >= 0
}

func indexOf(text, sub string) int {
	for i := 0; i+len(sub) <= len(text); i++ {
		if text[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
