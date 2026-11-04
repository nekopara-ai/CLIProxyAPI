package helps

import (
	"bytes"
	"github.com/MoeForge/moego/ojson"
	"strconv"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
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
	if len(payload) == 0 || !payloadHasTimezoneSurface(payload) {
		return payload
	}
	doc := ojson.NewDoc(payload)
	if !ApplyTimezoneOverrideAtDoc(cfg, doc, now) {
		return payload
	}
	return doc.Bytes()
}

// ApplyTimezoneOverrideDoc rewrites built-in environment metadata before user rules.
func ApplyTimezoneOverrideDoc(cfg *config.Config, doc *ojson.Doc) bool {
	return ApplyTimezoneOverrideAtDoc(cfg, doc, time.Now())
}

func ApplyTimezoneOverrideAtDoc(cfg *config.Config, doc *ojson.Doc, now time.Time) bool {
	location := TimezoneOverrideLocation(cfg)
	if doc == nil || location == nil {
		return false
	}
	target := timezoneOverrideTarget{timezone: strings.TrimSpace(cfg.TimezoneOverride), date: now.In(location).Format("2006-01-02"), country: strings.TrimSpace(cfg.TimezoneOverrideCountry), region: strings.TrimSpace(cfg.TimezoneOverrideRegion), city: strings.TrimSpace(cfg.TimezoneOverrideCity)}
	return rewriteTimezoneValueDoc(doc, "", doc.Get("@this"), target)
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

func rewriteTimezoneValueDoc(doc *ojson.Doc, path string, value ojson.Result, target timezoneOverrideTarget) bool {
	changed := false
	switch {
	case value.IsArray():
		for i, item := range value.Array() {
			changed = rewriteTimezoneValueDoc(doc, joinJSONPath(path, strconv.Itoa(i)), item, target) || changed
		}
	case value.IsObject():
		kind := value.Get("type").String()
		if kind == "function_call_output" || kind == "tool_result" || value.Get("role").String() == "tool" {
			return false
		}
		value.ForEach(func(key, child ojson.Result) bool {
			childPath := joinJSONPath(path, key.String())
			if key.String() == "user_location" && child.IsObject() {
				changed = rewriteUserLocationDoc(doc, childPath, child, target) || changed
			}
			changed = rewriteTimezoneValueDoc(doc, childPath, child, target) || changed
			return true
		})
	case value.Type == ojson.String:
		if rewritten, different := rewriteTimezoneText(value.String(), target.timezone, target.date); different {
			changed = doc.Set(path, rewritten) == nil
		}
	}
	return changed
}

func rewriteUserLocationDoc(doc *ojson.Doc, childPath string, child ojson.Result, target timezoneOverrideTarget) bool {
	changed := false
	current := child.Get("timezone")
	if !current.Exists() || current.Type != ojson.String || current.String() != target.timezone {
		changed = doc.Set(joinJSONPath(childPath, "timezone"), target.timezone) == nil
	}
	for _, replacement := range []struct{ field, value string }{{"country", target.country}, {"region", target.region}, {"city", target.city}} {
		existing := child.Get(replacement.field)
		if replacement.value == "" || !existing.Exists() || existing.Type != ojson.String || existing.String() == replacement.value {
			continue
		}
		changed = (doc.Set(joinJSONPath(childPath, replacement.field), replacement.value) == nil) || changed
	}
	return changed
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
