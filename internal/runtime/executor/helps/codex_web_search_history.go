package helps

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// EnsureCodexWebSearchHistoryTool preserves hosted search history while declaring
// the tool required by the Codex OAuth upstream to replay it. The behavior follows
// https://github.com/Wei-Shaw/sub2api/pull/7939; no historical item is removed.
// Callers must restrict this compatibility rewrite to OAuth /responses requests.
func EnsureCodexWebSearchHistoryTool(body []byte, lite bool) ([]byte, error) {
	if !bytes.Contains(body, []byte("web_search_call")) {
		return body, nil
	}
	input := gjson.GetBytes(body, "input")
	if !input.IsArray() {
		return body, nil
	}
	items := input.Array()
	topTools := gjson.GetBytes(body, "tools")
	if hasCodexWebSearchTool(topTools) {
		return body, nil
	}
	hasHistory, hasTools, additional := false, topTools.IsArray() && len(topTools.Array()) > 0, -1
	for i, item := range items {
		switch strings.TrimSpace(item.Get("type").String()) {
		case "web_search_call":
			hasHistory = true
		case "additional_tools":
			tools := item.Get("tools")
			if hasCodexWebSearchTool(tools) {
				return body, nil
			}
			hasTools = hasTools || (tools.IsArray() && len(tools.Array()) > 0)
			if additional < 0 {
				additional = i
			}
		}
	}
	if !hasHistory {
		return body, nil
	}
	const tool = `{"type":"web_search","external_web_access":false}`
	var next []byte
	var errSet error
	if !lite {
		path, value := "tools", "["+tool+"]"
		if topTools.IsArray() && len(topTools.Array()) > 0 {
			path, value = "tools.-1", tool
		}
		next, errSet = sjson.SetRawBytes(body, path, []byte(value))
	} else if additional >= 0 {
		path, value := "input."+strconv.Itoa(additional)+".tools", "["+tool+"]"
		if tools := items[additional].Get("tools"); tools.IsArray() && len(tools.Array()) > 0 {
			path, value = path+".-1", tool
		}
		next, errSet = sjson.SetRawBytes(body, path, []byte(value))
	} else {
		// Lite rejects top-level hosted tools. Keep the trailing v2 trigger last.
		at := len(items)
		if at > 0 && strings.TrimSpace(items[at-1].Get("type").String()) == "compaction_trigger" {
			at--
		}
		declaration := []byte(`{"type":"additional_tools","role":"developer","tools":[` + tool + `]}`)
		parts := make([][]byte, 0, len(items)+1)
		for i := 0; i <= len(items); i++ {
			if i == at {
				parts = append(parts, declaration)
			}
			if i < len(items) {
				parts = append(parts, []byte(items[i].Raw))
			}
		}
		raw := append([]byte{'['}, bytes.Join(parts, []byte{','})...)
		raw = append(raw, ']')
		next, errSet = sjson.SetRawBytes(body, "input", raw)
	}
	if errSet != nil {
		return nil, fmt.Errorf("declare Codex search history tool: %w", errSet)
	}
	if !hasTools {
		choice := gjson.GetBytes(body, "tool_choice")
		pinNone := !choice.Exists() || choice.Type == gjson.Null
		if choice.Type == gjson.String {
			switch strings.ToLower(strings.TrimSpace(choice.String())) {
			case "", "auto", "none":
				pinNone = true
			}
		}
		if pinNone {
			next, errSet = sjson.SetBytes(next, "tool_choice", "none")
			if errSet != nil {
				return nil, fmt.Errorf("preserve Codex no-tools choice: %w", errSet)
			}
		}
	}
	return next, nil
}

func hasCodexWebSearchTool(tools gjson.Result) bool {
	if !tools.IsArray() {
		return false
	}
	for _, tool := range tools.Array() {
		if strings.HasPrefix(strings.TrimSpace(tool.Get("type").String()), "web_search") {
			return true
		}
	}
	return false
}
