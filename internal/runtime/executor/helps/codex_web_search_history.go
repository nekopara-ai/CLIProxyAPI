package helps

import (
	"bytes"
	"fmt"
	"github.com/MoeForge/moego/ojson"
	"strconv"
	"strings"
)

// EnsureCodexWebSearchHistoryTool preserves hosted search history while declaring
// the tool required by the Codex OAuth upstream to replay it. The behavior follows
// https://github.com/Wei-Shaw/sub2api/pull/7939; no historical item is removed.
// Callers must restrict this compatibility rewrite to OAuth /responses requests.
func EnsureCodexWebSearchHistoryTool(body []byte, lite bool) ([]byte, error) {
	if !bytes.Contains(body, []byte("web_search_call")) {
		return body, nil
	}
	doc := ojson.NewDoc(body)
	if err := EnsureCodexWebSearchHistoryToolDoc(doc, lite); err != nil {
		return nil, err
	}
	return doc.Bytes(), nil
}

func EnsureCodexWebSearchHistoryToolDoc(doc *ojson.Doc, lite bool) error {
	if doc == nil || !strings.Contains(doc.Get("input").Raw, "web_search_call") {
		return nil
	}
	input := doc.Get("input")
	if !input.IsArray() {
		return nil
	}
	items := input.Array()
	topTools := doc.Get("tools")
	if hasCodexWebSearchTool(topTools) {
		return nil
	}
	hasHistory, hasTools, additional := false, topTools.IsArray() && len(topTools.Array()) > 0, -1
	for i, item := range items {
		switch strings.TrimSpace(item.Get("type").String()) {
		case "web_search_call":
			hasHistory = true
		case "additional_tools":
			tools := item.Get("tools")
			if hasCodexWebSearchTool(tools) {
				return nil
			}
			hasTools = hasTools || (tools.IsArray() && len(tools.Array()) > 0)
			if additional < 0 {
				additional = i
			}
		}
	}
	if !hasHistory {
		return nil
	}
	const tool = `{"type":"web_search","external_web_access":false}`
	var errSet error
	if !lite {
		path, value := "tools", "["+tool+"]"
		if topTools.IsArray() && len(topTools.Array()) > 0 {
			path, value = "tools.-1", tool
		}
		errSet = doc.SetRawBytes(path, []byte(value))
	} else if additional >= 0 {
		path, value := "input."+strconv.Itoa(additional)+".tools", "["+tool+"]"
		if tools := items[additional].Get("tools"); tools.IsArray() && len(tools.Array()) > 0 {
			path, value = path+".-1", tool
		}
		errSet = doc.SetRawBytes(path, []byte(value))
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
		errSet = doc.SetRawBytes("input", raw)
	}
	if errSet != nil {
		return fmt.Errorf("declare Codex search history tool: %w", errSet)
	}
	if !hasTools {
		choice := doc.Get("tool_choice")
		pinNone := !choice.Exists() || choice.Type == ojson.Null
		if choice.Type == ojson.String {
			switch strings.ToLower(strings.TrimSpace(choice.String())) {
			case "", "auto", "none":
				pinNone = true
			}
		}
		if pinNone {
			errSet = doc.Set("tool_choice", "none")
			if errSet != nil {
				return fmt.Errorf("preserve Codex no-tools choice: %w", errSet)
			}
		}
	}
	return nil
}

func hasCodexWebSearchTool(tools ojson.Result) bool {
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
