package executor

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestDSHPromptReplaceOutbound(t *testing.T) {
	const paragraph = "Tokens prefixed with @ are paths the user explicitly referenced. Relative paths resolve from the workspace root; absolute paths identify files or directories on the host. A trailing slash marks a directory: list it when its contents matter. Anything else is a file: use the read tool when its contents are needed, and do not claim to have inspected it before reading. @“…” quotes a path containing spaces."
	for _, format := range []sdktranslator.Format{sdktranslator.FormatOpenAI, sdktranslator.FormatOpenAIResponse} {
		for _, operation := range []string{"execute", "stream", "count"} {
			t.Run(format.String()+"/"+operation, func(t *testing.T) {
				captured := make(chan []byte, 4)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
						w.WriteHeader(400)
						return
					}
					captured <- body
					if operation == "count" {
						_, _ = io.WriteString(w, `{"totalTokens":17}`)
						return
					}
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = fmt.Fprint(w, "data: {\"response\":{\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"OK\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":17,\"candidatesTokenCount\":1,\"totalTokenCount\":18}}}\n\n")
				}))
				defer server.Close()
				cfg := &config.Config{DisableCooling: true, Payload: config.PayloadConfig{Replace: []config.PayloadReplaceRule{{
					Models: []config.PayloadModelRule{{Name: "gemini-*", Protocol: "antigravity"}},
					Paths:  []string{"systemInstruction.parts.#(text)#.text", "system_instruction.parts.#(text)#.text"}, Old: paragraph,
				}}}}
				model := "gemini-4-carbon"
				doc := ojson.NewDoc([]byte(`{}`))
				_ = doc.Set("model", model)
				if format == sdktranslator.FormatOpenAI {
					_ = doc.Set("messages", []any{map[string]any{"role": "system", "content": "before\n" + paragraph + "\nafter"}, map[string]any{"role": "user", "content": paragraph}})
				} else {
					_ = doc.Set("instructions", "before\n"+paragraph+"\nafter")
					_ = doc.Set("input", []any{map[string]any{"role": "user", "content": paragraph}})
				}
				exec := NewAntigravityExecutor(cfg)
				auth := &cliproxyauth.Auth{ID: t.Name(), Provider: "antigravity", Attributes: map[string]string{"base_url": server.URL}, Metadata: map[string]any{"access_token": "synthetic", "project_id": "test", "expired": time.Now().Add(time.Hour).Format(time.RFC3339)}}
				req := cliproxyexecutor.Request{Model: model, Payload: doc.Bytes()}
				opts := cliproxyexecutor.Options{SourceFormat: format}
				switch operation {
				case "execute":
					if _, err := exec.Execute(context.Background(), auth, req, opts); err != nil {
						t.Fatal(err)
					}
				case "stream":
					result, err := exec.ExecuteStream(context.Background(), auth, req, opts)
					if err != nil {
						t.Fatal(err)
					}
					for chunk := range result.Chunks {
						if chunk.Err != nil {
							t.Fatal(chunk.Err)
						}
					}
				case "count":
					if _, err := exec.CountTokens(context.Background(), auth, req, opts); err != nil {
						t.Fatal(err)
					}
				}
				select {
				case wire := <-captured:
					out := ojson.NewDoc(wire)
					system := out.Get("request.systemInstruction").Raw
					if strings.Contains(system, "Tokens prefixed") || !strings.Contains(system, "before") || !strings.Contains(system, "after") {
						t.Fatalf("unexpected outbound system: %s", system)
					}
					if out.Get("request.contents.0.parts.0.text").String() != paragraph {
						t.Fatal("user paragraph changed")
					}
				default:
					t.Fatal("upstream did not receive a request")
				}
			})
		}
	}
}
