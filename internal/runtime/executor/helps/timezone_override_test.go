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

func TestApplyTimezoneOverrideRewritesConfiguredUserLocationTriple(t *testing.T) {
	now := time.Date(2026, 9, 15, 1, 0, 0, 0, time.UTC)
	cfg := &config.Config{
		TimezoneOverride:        "America/New_York",
		TimezoneOverrideCountry: "US",
		TimezoneOverrideRegion:  "New York",
		TimezoneOverrideCity:    "New York",
	}
	// tools.1 models a client that only ever sent a timezone: the rewrite must not
	// invent a country/region for it, because a claimed location is itself a signal.
	payload := []byte(`{
		"tools": [
			{"type": "web_search", "user_location": {"type": "approximate", "country": "CN", "region": "Shanghai", "city": "Shanghai", "timezone": "Asia/Shanghai"}},
			{"type": "web_search", "user_location": {"type": "approximate", "timezone": "Etc/UTC"}},
			{"type": "function", "name": "get_time", "parameters": {"properties": {"city": {"type": "string"}}}}
		],
		"input": [
			{"type": "additional_tools", "tools": [{"type": "web_search", "user_location": {"type": "approximate", "country": "CN", "city": "Beijing", "timezone": "Asia/Shanghai"}}]}
		]
	}`)

	out := ApplyTimezoneOverrideAt(cfg, payload, now)
	for _, tc := range []struct{ path, want string }{
		{"tools.0.user_location.timezone", "America/New_York"},
		{"tools.0.user_location.country", "US"},
		{"tools.0.user_location.region", "New York"},
		{"tools.0.user_location.city", "New York"},
		{"input.0.tools.0.user_location.timezone", "America/New_York"},
		{"input.0.tools.0.user_location.country", "US"},
		{"input.0.tools.0.user_location.city", "New York"},
	} {
		if got := gjson.GetBytes(out, tc.path).String(); got != tc.want {
			t.Fatalf("%s = %q, want %q; body=%s", tc.path, got, tc.want, out)
		}
	}
	for _, path := range []string{
		"tools.1.user_location.country",
		"tools.1.user_location.region",
		"tools.1.user_location.city",
		"input.0.tools.0.user_location.region",
	} {
		if gjson.GetBytes(out, path).Exists() {
			t.Fatalf("%s was invented by the rewrite; body=%s", path, out)
		}
	}
	if got := gjson.GetBytes(out, "tools.2.parameters.properties.city.type").String(); got != "string" {
		t.Fatalf("tool schema city property was rewritten: %s", out)
	}
	if again := ApplyTimezoneOverrideAt(cfg, out, now); string(again) != string(out) {
		t.Fatalf("second pass changed the body:\nfirst=%s\nsecond=%s", out, again)
	}
}

func TestApplyTimezoneOverrideLocationNeedsValidTimezone(t *testing.T) {
	cfg := &config.Config{TimezoneOverrideCountry: "US", TimezoneOverrideCity: "New York"}
	payload := []byte(`{"tools":[{"type":"web_search","user_location":{"type":"approximate","country":"CN","city":"Shanghai"}}]}`)
	if got := string(ApplyTimezoneOverride(cfg, payload)); got != string(payload) {
		t.Fatalf("location rewrite without a valid timezone changed payload: %s", got)
	}
	invalid := &config.Config{TimezoneOverride: "not/a-timezone", TimezoneOverrideCountry: "US", TimezoneOverrideCity: "New York"}
	if got := string(ApplyTimezoneOverride(invalid, payload)); got != string(payload) {
		t.Fatalf("location rewrite with an invalid timezone changed payload: %s", got)
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
