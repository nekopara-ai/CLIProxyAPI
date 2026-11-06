package responses

import (
	"context"
	"testing"

	"github.com/MoeForge/moego/ojson"
)

func TestReasoningDeltasStreamBeforeLateSignature(t *testing.T) {
	for _, tail := range []struct {
		name string
		part string
	}{
		{"text", `{"text":"answer","thoughtSignature":"` + testResponsesGeminiThoughtSignature + `"}`},
		{"function", `{"functionCall":{"name":"read_marker","args":{}},"thoughtSignature":"` + testResponsesGeminiThoughtSignature + `"}`},
		{"signature_only", `{"text":"","thoughtSignature":"` + testResponsesGeminiThoughtSignature + `"}`},
	} {
		t.Run(tail.name, func(t *testing.T) {
			var state any
			var reasoningID string
			for _, text := range []string{"checking ", "constraints"} {
				chunk := []byte(`{"candidates":[{"content":{"parts":[{"thought":true,"text":"` + text + `"}]}}],"responseId":"latency"}`)
				events := ConvertGeminiResponseToOpenAIResponses(context.Background(), "gemini-4-argon-high", nil, nil, chunk, &state)
				var got string
				for _, event := range events {
					kind, data := parseSSEEvent(t, event)
					if kind == "response.reasoning_summary_text.delta" {
						got += data.Get("delta").String()
						if reasoningID != "" && reasoningID != data.Get("item_id").String() {
							t.Fatal("reasoning item changed between deltas")
						}
						reasoningID = data.Get("item_id").String()
					}
					if kind == "response.output_item.done" || kind == "response.completed" {
						t.Fatal("reasoning must not complete before its signature/terminal frame")
					}
				}
				if got != text {
					t.Fatalf("thought delta was buffered waiting for signature: got %q, want %q", got, text)
				}
			}
			chunk := []byte(`{"candidates":[{"content":{"parts":[` + tail.part + `]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":2,"thoughtsTokenCount":8,"totalTokenCount":20},"responseId":"latency"}`)
			events := ConvertGeminiResponseToOpenAIResponses(context.Background(), "gemini-4-argon-high", nil, nil, chunk, &state)
			var completed ojson.Result
			var doneSignature string
			for _, event := range events {
				kind, data := parseSSEEvent(t, event)
				if kind == "response.output_item.done" && data.Get("item.type").String() == "reasoning" {
					if data.Get("item.id").String() != reasoningID {
						t.Fatal("late signature was attached to a different reasoning item")
					}
					doneSignature = decodedResponsesCarrierSignature(t, data.Get("item.encrypted_content").String())
				}
				if kind == "response.completed" {
					completed = data.Get("response")
				}
			}
			if doneSignature != testResponsesGeminiThoughtSignature || !completed.Exists() {
				t.Fatal("late signature or completed response was lost")
			}
			if got := completed.Get("output.0.summary.0.text").String(); got != "checking constraints" {
				t.Fatalf("summary changed: %q", got)
			}
			if tail.name == "function" {
				request := ojson.NewDocString(`{"model":"gemini-4-argon-high","input":[]}`)
				if err := request.SetRawBytes("input", []byte(completed.Get("output").Raw)); err != nil {
					t.Fatal(err)
				}
				if err := request.Set("input.-1", map[string]any{"type": "function_call_output", "call_id": completed.Get("output.1.call_id").String(), "output": "ok"}); err != nil {
					t.Fatal(err)
				}
				translated, err := ConvertOpenAIResponsesRequestToGemini("gemini-4-argon-high", request.Bytes(), false)
				if err != nil {
					t.Fatal(err)
				}
				found := false
				ojson.GetBytes(translated, "contents").ForEach(func(_, content ojson.Result) bool {
					content.Get("parts").ForEach(func(_, part ojson.Result) bool {
						if part.Get("functionCall").Exists() && part.Get("thoughtSignature").String() == testResponsesGeminiThoughtSignature {
							found = true
						}
						return true
					})
					return true
				})
				if !found {
					t.Fatal("tool replay lost the late thought signature")
				}
			}
		})
	}
}
