package api

import (
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/tidwall/gjson"
)

// /v1/alpha/search forwards its body without passing through an executor, so the
// shared payload funnel cannot rewrite it. The route must apply the configured
// timezone itself and must keep the prompt-cache sanitization intact.
func TestPrepareCodexAlphaSearchUpstreamBodyAppliesTimezoneOverride(t *testing.T) {
	cfg := &config.Config{TimezoneOverride: "America/New_York"}
	body := []byte(`{
		"model": "gpt-5.6-luna",
		"prompt_cache_key": "drop-me",
		"input": [
			{"type": "message", "role": "user", "content": [{"type": "input_text", "text": "<environment_context>\n  <current_date>2026-09-15</current_date>\n  <timezone>Asia/Shanghai</timezone>\n</environment_context>"}]}
		]
	}`)
	out := prepareCodexAlphaSearchUpstreamBody(cfg, body)

	if gjson.GetBytes(out, "prompt_cache_key").Exists() {
		t.Fatalf("prompt_cache_key was not sanitized: %s", out)
	}
	envText := gjson.GetBytes(out, "input.0.content.0.text").String()
	if got := alphaSearchXMLTag(envText, "timezone"); got != "America/New_York" {
		t.Fatalf("alpha search timezone = %q, want America/New_York; body=%s", got, out)
	}
	location, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatalf("load location: %v", err)
	}
	wantDate := time.Now().In(location).Format("2006-01-02")
	if got := alphaSearchXMLTag(envText, "current_date"); got != wantDate {
		t.Fatalf("alpha search current_date = %q, want %q; body=%s", got, wantDate, out)
	}
}

func TestPrepareCodexAlphaSearchUpstreamBodyNoopsWithoutOverride(t *testing.T) {
	body := []byte(`{"model":"gpt-5.6-luna","input":"plain"}`)
	out := prepareCodexAlphaSearchUpstreamBody(&config.Config{}, body)
	if string(out) != string(body) {
		t.Fatalf("unset override changed alpha search body: %s", out)
	}
}

func alphaSearchXMLTag(text, name string) string {
	open := "<" + name + ">"
	close := "</" + name + ">"
	from := 0
	for i := 0; i+len(open) <= len(text); i++ {
		if text[i:i+len(open)] == open {
			from = i + len(open)
			break
		}
	}
	if from == 0 {
		return ""
	}
	for i := from; i+len(close) <= len(text); i++ {
		if text[i:i+len(close)] == close {
			return text[from:i]
		}
	}
	return ""
}
