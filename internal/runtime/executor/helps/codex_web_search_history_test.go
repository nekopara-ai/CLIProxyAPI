package helps

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/tidwall/gjson"
)

func TestCodexWebSearchHistoryCompatibility(t *testing.T) {
	history := `[{"type":"message","role":"user","content":"Find docs"},{"type":"web_search_call","id":"ws_first","status":"completed","action":{"type":"search","query":"asyncio","sources":[{"url":"https://docs.python.org/3/library/asyncio.html"}]}},{"type":"web_search_call","id":"ws_second","action":{"type":"open_page","url":"https://docs.python.org/3/library/asyncio.html"}},{"type":"reasoning","encrypted_content":"opaque"},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Docs","annotations":[{"type":"url_citation","url":"https://docs.python.org/3/library/asyncio.html"}]}]},{"type":"function_call","name":"exec","call_id":"call_1","arguments":"{}"},{"type":"function_call_output","call_id":"call_1","output":"ok"},{"type":"compaction","encrypted_content":"sealed"}]`
	for _, lite := range []bool{false, true} {
		for _, tools := range []string{"", `,"tools":null`, `,"tools":[]`, `,"tools":[{"type":"function","name":"exec","parameters":{"type":"object"}}]`} {
			for _, choice := range []string{"", `,"tool_choice":null`, `,"tool_choice":"auto"`, `,"tool_choice":"none"`, `,"tool_choice":"required"`, `,"tool_choice":{"type":"function","name":"exec"}`} {
				for _, trigger := range []bool{false, true} {
					t.Run(stringifyHistoryCase(lite, tools, choice, trigger), func(t *testing.T) {
						input := history
						if trigger {
							input = history[:len(history)-1] + `,{"type":"compaction_trigger"}]`
						}
						body := []byte(`{"input":` + input + tools + choice + `,"future":{"keep":1234567890123456789}}`)
						got, err := EnsureCodexWebSearchHistoryTool(body, lite)
						if err != nil {
							t.Fatal(err)
						}
						var declaration gjson.Result
						if lite {
							declaration = gjson.GetBytes(got, `input.#(type=="additional_tools").tools.0`)
							if gjson.GetBytes(got, "tools").Raw != gjson.GetBytes(body, "tools").Raw {
								t.Fatal("Lite modified top-level tools")
							}
						} else {
							declaration = gjson.GetBytes(got, `tools.#(type=="web_search")`)
						}
						if declaration.Get("type").String() != "web_search" || declaration.Get("external_web_access").Type != gjson.False {
							t.Fatalf("missing cached-only declaration: %s", got)
						}
						var retained []json.RawMessage
						for _, item := range gjson.GetBytes(got, "input").Array() {
							if item.Get("type").String() != "additional_tools" {
								retained = append(retained, json.RawMessage(item.Raw))
							}
						}
						var original []json.RawMessage
						if err := json.Unmarshal([]byte(input), &original); err != nil {
							t.Fatal(err)
						}
						if !reflect.DeepEqual(retained, original) {
							t.Fatal("historical input changed")
						}
						if trigger {
							items := gjson.GetBytes(got, "input").Array()
							if items[len(items)-1].Get("type").String() != "compaction_trigger" {
								t.Fatal("trigger no longer last")
							}
						}
						wantChoice := gjson.GetBytes(body, "tool_choice").Raw
						if len(gjson.GetBytes(body, "tools").Array()) == 0 && (choice == "" || choice == `,"tool_choice":null` || choice == `,"tool_choice":"auto"` || choice == `,"tool_choice":"none"`) {
							wantChoice = `"none"`
						}
						if gjson.GetBytes(got, "tool_choice").Raw != wantChoice {
							t.Fatalf("choice changed unexpectedly: %s", got)
						}
						if gjson.GetBytes(got, "future").Raw != gjson.GetBytes(body, "future").Raw {
							t.Fatal("unknown field changed")
						}
						again, err := EnsureCodexWebSearchHistoryTool(got, lite)
						if err != nil || !bytes.Equal(got, again) {
							t.Fatal("rewrite is not idempotent")
						}
					})
				}
			}
		}
	}
}

func stringifyHistoryCase(lite bool, tools, choice string, trigger bool) string {
	data, _ := json.Marshal([]any{lite, tools, choice, trigger})
	return string(data)
}

func TestCodexWebSearchHistoryNoop(t *testing.T) {
	for _, body := range []string{
		`{"input":"web_search_call"}`,
		`{"input":[{"role":"user","content":"web_search_call"}],"tools":[]}`,
		`{"input":[{"type":"web_search_call"}],"tools":[{"type":"web_search_preview"}]}`,
		`{"input":[{"type":"web_search_call"},{"type":"additional_tools","tools":[{"type":"web_search"}]}]}`,
	} {
		for _, lite := range []bool{false, true} {
			got, err := EnsureCodexWebSearchHistoryTool([]byte(body), lite)
			if err != nil || string(got) != body {
				t.Fatalf("no-op body changed: %s, %v", got, err)
			}
		}
	}
}

func TestCodexWebSearchHistoryExtendsAdditionalTools(t *testing.T) {
	for _, tools := range []string{`[]`, `null`, `[{"type":"function","name":"exec"}]`} {
		body := []byte(`{"input":[{"type":"additional_tools","role":"developer","future":42,"tools":` + tools + `},{"type":"web_search_call"},{"type":"compaction_trigger"}],"tool_choice":"auto"}`)
		got, err := EnsureCodexWebSearchHistoryTool(body, true)
		if err != nil {
			t.Fatal(err)
		}
		if gjson.GetBytes(got, "input.#").Int() != 3 || gjson.GetBytes(got, "input.0.future").Int() != 42 || gjson.GetBytes(got, "input.2.type").String() != "compaction_trigger" {
			t.Fatalf("changed Lite input structure: %s", got)
		}
		if gjson.GetBytes(got, "input.0.tools.#").Int() != int64(len(gjson.Parse(tools).Array())+1) {
			t.Fatalf("did not extend existing tool array: %s", got)
		}
		if tools != `[]` && tools != `null` && gjson.GetBytes(got, "tool_choice").String() != "auto" {
			t.Fatal("disabled caller's function tools")
		}
	}
}
