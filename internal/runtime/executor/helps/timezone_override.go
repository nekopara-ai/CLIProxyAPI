package helps

import (
	"bytes"
	"strconv"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const (
	environmentContextOpen  = "<environment_context>"
	environmentContextClose = "</environment_context>"
	claudeCurrentDateMarker = "# currentDate"
)

// TimezoneOverrideLocation returns the configured IANA timezone, or nil when
// timezone-override is empty or invalid. Invalid values are ignored so a typo
// cannot fail an otherwise valid upstream request.
func TimezoneOverrideLocation(cfg *config.Config) *time.Location {
	if cfg == nil {
		return nil
	}
	timezone := strings.TrimSpace(cfg.TimezoneOverride)
	if timezone == "" {
		return nil
	}
	location, err := time.LoadLocation(timezone)
	if err != nil {
		return nil
	}
	return location
}

// ApplyTimezoneOverride rewrites protocol-level timezone and local-date fields
// in a Codex or Claude upstream JSON body. Empty or invalid overrides are a no-op.
func ApplyTimezoneOverride(cfg *config.Config, payload []byte) []byte {
	return ApplyTimezoneOverrideAt(cfg, payload, time.Now())
}

// ApplyTimezoneOverrideAt is the testable form of ApplyTimezoneOverride.
func ApplyTimezoneOverrideAt(cfg *config.Config, payload []byte, now time.Time) []byte {
	if len(payload) == 0 {
		return payload
	}
	location := TimezoneOverrideLocation(cfg)
	if location == nil {
		return payload
	}
	if !payloadHasTimezoneSurface(payload) {
		return payload
	}
	target := timezoneOverrideTarget{
		timezone: strings.TrimSpace(cfg.TimezoneOverride),
		date:     now.In(location).Format("2006-01-02"),
		country:  strings.TrimSpace(cfg.TimezoneOverrideCountry),
		region:   strings.TrimSpace(cfg.TimezoneOverrideRegion),
		city:     strings.TrimSpace(cfg.TimezoneOverrideCity),
	}
	return rewriteTimezoneJSON(payload, target)
}

// timezoneOverrideTarget carries the replacement timezone and local date plus
// the optional location triple that keeps web_search user_location consistent
// with the timezone instead of contradicting it.
type timezoneOverrideTarget struct {
	timezone string
	date     string
	country  string
	region   string
	city     string
}

// payloadHasTimezoneSurface is a byte-level pre-filter for the JSON walk. The
// rewrite can only change three surfaces, so a body containing none of their
// markers is returned untouched. The markers are matched without their angle
// brackets because encoding/json may emit "\u003c" escapes; the bare names
// appear in both the literal and escaped encodings.
func payloadHasTimezoneSurface(payload []byte) bool {
	return bytes.Contains(payload, []byte("environment_context")) ||
		bytes.Contains(payload, []byte("user_location")) ||
		bytes.Contains(payload, []byte(claudeCurrentDateMarker))
}

func rewriteTimezoneJSON(payload []byte, target timezoneOverrideTarget) []byte {
	return rewriteTimezoneValue(payload, "", gjson.ParseBytes(payload), target)
}

func rewriteTimezoneValue(out []byte, path string, value gjson.Result, target timezoneOverrideTarget) []byte {
	switch {
	case value.IsArray():
		items := value.Array()
		for i := range items {
			out = rewriteTimezoneValue(out, joinJSONPath(path, strconv.Itoa(i)), items[i], target)
		}
	case value.IsObject():
		// Tool results are untrusted payloads, not environment instructions. Never
		// rewrite source code, historical examples, or nested JSON inside them.
		kind := value.Get("type").String()
		if kind == "function_call_output" || kind == "tool_result" || value.Get("role").String() == "tool" {
			return out
		}
		value.ForEach(func(key, child gjson.Result) bool {
			childPath := joinJSONPath(path, key.String())
			if key.String() == "user_location" && child.IsObject() {
				out = rewriteUserLocation(out, childPath, child, target)
			}
			out = rewriteTimezoneValue(out, childPath, child, target)
			return true
		})
	case value.Type == gjson.String:
		rewritten, changed := rewriteTimezoneText(value.String(), target.timezone, target.date)
		if changed {
			updated, errSet := sjson.SetBytes(out, path, rewritten)
			if errSet == nil {
				out = updated
			}
		}
	}
	return out
}

// rewriteUserLocation rewrites user_location.timezone and, when configured,
// country/region/city. Location fields are only replaced when the client already
// sent that field: a client that never claimed a location must not gain one,
// otherwise the rewrite itself becomes the anomaly.
func rewriteUserLocation(out []byte, childPath string, child gjson.Result, target timezoneOverrideTarget) []byte {
	current := child.Get("timezone")
	if !current.Exists() || current.Type != gjson.String || current.String() != target.timezone {
		updated, errSet := sjson.SetBytes(out, joinJSONPath(childPath, "timezone"), target.timezone)
		if errSet == nil {
			out = updated
		}
	}
	replacements := [...]struct{ field, value string }{
		{"country", target.country},
		{"region", target.region},
		{"city", target.city},
	}
	for _, replacement := range replacements {
		if replacement.value == "" {
			continue
		}
		existing := child.Get(replacement.field)
		if !existing.Exists() || existing.Type != gjson.String || existing.String() == replacement.value {
			continue
		}
		updated, errSet := sjson.SetBytes(out, joinJSONPath(childPath, replacement.field), replacement.value)
		if errSet == nil {
			out = updated
		}
	}
	return out
}

func joinJSONPath(base, key string) string {
	if base == "" {
		return key
	}
	if key == "" {
		return base
	}
	return base + "." + key
}

func rewriteTimezoneText(text, timezone, date string) (string, bool) {
	rewritten := rewriteEnvironmentContextTimezone(text, timezone, date)
	rewritten = rewriteClaudeCurrentDateReminder(rewritten, date)
	return rewritten, rewritten != text
}

func rewriteEnvironmentContextTimezone(text, timezone, date string) string {
	if !strings.Contains(text, environmentContextOpen) {
		return text
	}
	var builder strings.Builder
	remaining := text
	for {
		start := strings.Index(remaining, environmentContextOpen)
		if start < 0 {
			builder.WriteString(remaining)
			break
		}
		closeAt := strings.Index(remaining[start:], environmentContextClose)
		if closeAt < 0 {
			builder.WriteString(remaining)
			break
		}
		end := start + closeAt + len(environmentContextClose)
		builder.WriteString(remaining[:start])
		builder.WriteString(rewriteEnvironmentContextBlock(remaining[start:end], timezone, date))
		remaining = remaining[end:]
	}
	return builder.String()
}

func rewriteEnvironmentContextBlock(block, timezone, date string) string {
	block = replaceXMLTag(block, "timezone", timezone)
	block = replaceXMLTag(block, "current_date", date)
	if !strings.Contains(block, "<current_date>") {
		block = strings.Replace(block, environmentContextClose, "  <current_date>"+date+"</current_date>\n"+environmentContextClose, 1)
	}
	if !strings.Contains(block, "<timezone>") {
		block = strings.Replace(block, environmentContextClose, "  <timezone>"+timezone+"</timezone>\n"+environmentContextClose, 1)
	}
	return block
}

func replaceXMLTag(block, name, value string) string {
	open := "<" + name + ">"
	close := "</" + name + ">"
	start := 0
	for {
		from := strings.Index(block[start:], open)
		if from < 0 {
			return block
		}
		from += start
		to := strings.Index(block[from+len(open):], close)
		if to < 0 {
			return block
		}
		to = from + len(open) + to + len(close)
		block = block[:from] + open + value + close + block[to:]
		start = from + len(open) + len(value) + len(close)
	}
}

func rewriteClaudeCurrentDateReminder(text, date string) string {
	if !strings.Contains(text, claudeCurrentDateMarker) {
		return text
	}
	const prefix = "Today's date is "
	start := 0
	for {
		from := strings.Index(text[start:], prefix)
		if from < 0 {
			return text
		}
		from += start
		rest := text[from+len(prefix):]
		if len(rest) < 11 || rest[4] != '-' || rest[7] != '-' || rest[10] != '.' {
			start = from + len(prefix)
			continue
		}
		if !isDigits(rest[0:4]) || !isDigits(rest[5:7]) || !isDigits(rest[8:10]) {
			start = from + len(prefix)
			continue
		}
		replacement := prefix + date + "."
		text = text[:from] + replacement + rest[11:]
		start = from + len(replacement)
	}
}

func isDigits(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}
