package helps

import (
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/tidwall/gjson"
)

const payloadFunnelTimezoneBody = `{
	"model": "deepseek-v4.1-flash",
	"input": [
		{
			"type": "message",
			"role": "user",
			"content": [
				{"type": "input_text", "text": "<environment_context>\n  <cwd>/repo</cwd>\n  <current_date>2026-09-15</current_date>\n  <timezone>Asia/Shanghai</timezone>\n</environment_context>"}
			]
		}
	],
	"tools": [
		{"type": "web_search", "user_location": {"type": "approximate", "city": "Shanghai", "timezone": "Asia/Shanghai"}}
	]
}`

// Every executor funnels its translated outbound body through
// ApplyPayloadConfigWithRequest, so the timezone rewrite must be applied there
// even when no payload rules are configured. This is the regression guard for
// providers that never called ApplyTimezoneOverride directly.
func TestApplyPayloadConfigWithRequestAppliesTimezoneOverrideWithoutPayloadRules(t *testing.T) {
	cfg := &config.Config{TimezoneOverride: "America/New_York"}
	out := ApplyPayloadConfigWithRequest(cfg, "deepseek-v4.1-flash", "openai", "responses", "", []byte(payloadFunnelTimezoneBody), nil, "deepseek-v4.1-flash", "/v1/responses", nil)

	envText := gjson.GetBytes(out, "input.0.content.0.text").String()
	if got := extractXMLTag(envText, "timezone"); got != "America/New_York" {
		t.Fatalf("environment timezone = %q, want America/New_York; body=%s", got, out)
	}
	if got := extractXMLTag(envText, "current_date"); got != timezoneDateForTest(t) {
		t.Fatalf("environment current_date = %q, want %q; body=%s", got, timezoneDateForTest(t), out)
	}
	if got := gjson.GetBytes(out, "tools.0.user_location.timezone").String(); got != "America/New_York" {
		t.Fatalf("tools user_location.timezone = %q, want America/New_York; body=%s", got, out)
	}
}

// The rewrite must not disturb payload-rule behavior or the tracked-path report.
func TestApplyPayloadConfigWithTrackedPathsKeepsRulesAndAppliesTimezoneOverride(t *testing.T) {
	cfg := &config.Config{
		TimezoneOverride: "America/New_York",
		Payload: config.PayloadConfig{
			Override: []config.PayloadRule{
				{
					Models: []config.PayloadModelRule{{
						Name: "deepseek-*",
					}},
					Params: map[string]any{"reasoning_effort": "high"},
				},
			},
		},
	}
	out, touched := ApplyPayloadConfigWithTrackedPaths(cfg, "deepseek-v4.1-flash", "openai", "responses", "", []byte(payloadFunnelTimezoneBody), nil, "deepseek-v4.1-flash", "/v1/responses", nil, "reasoning_effort")

	if got := gjson.GetBytes(out, "reasoning_effort").String(); got != "high" {
		t.Fatalf("payload rule reasoning_effort = %q, want high; body=%s", got, out)
	}
	if !touched["reasoning_effort"] {
		t.Fatalf("tracked path not reported: %#v", touched)
	}
	if got := gjson.GetBytes(out, "tools.0.user_location.timezone").String(); got != "America/New_York" {
		t.Fatalf("tools user_location.timezone = %q, want America/New_York; body=%s", got, out)
	}
}

func TestApplyPayloadConfigWithRequestLeavesTimezoneAloneWhenOverrideUnset(t *testing.T) {
	payload := []byte(payloadFunnelTimezoneBody)
	out := ApplyPayloadConfigWithRequest(&config.Config{}, "deepseek-v4.1-flash", "openai", "responses", "", payload, nil, "deepseek-v4.1-flash", "/v1/responses", nil)
	if string(out) != string(payload) {
		t.Fatalf("unset override changed payload:\n%s", out)
	}
	out = ApplyPayloadConfigWithRequest(&config.Config{TimezoneOverride: "not/a-timezone"}, "deepseek-v4.1-flash", "openai", "responses", "", payload, nil, "deepseek-v4.1-flash", "/v1/responses", nil)
	if string(out) != string(payload) {
		t.Fatalf("invalid override changed payload:\n%s", out)
	}
}

// The JSON pre-filter must not skip a body whose only timezone surface is a
// Claude currentDate reminder.
func TestApplyPayloadConfigWithTrackedPathsRewritesClaudeCurrentDateReminder(t *testing.T) {
	cfg := &config.Config{TimezoneOverride: "America/New_York"}
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"<system-reminder>\n# currentDate\nToday's date is 2026-09-15.\n</system-reminder>"}]}]}`)
	out := ApplyPayloadConfigWithRequest(cfg, "claude-sonnet-4-5", "claude", "claude", "", payload, nil, "claude-sonnet-4-5", "/v1/messages", nil)
	reminder := gjson.GetBytes(out, "messages.0.content.0.text").String()
	if !containsDate(reminder, timezoneDateForTest(t)) {
		t.Fatalf("claude currentDate reminder = %q, want date %s", reminder, timezoneDateForTest(t))
	}
}

// timezoneDateForTest returns today's date in the rewrite target timezone, which
// is what the production rewrite uses (time.Now().In(location)).
func timezoneDateForTest(t *testing.T) string {
	t.Helper()
	location, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatalf("load location: %v", err)
	}
	return time.Now().In(location).Format("2006-01-02")
}
