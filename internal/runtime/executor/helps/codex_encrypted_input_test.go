package helps

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/signature"
	"github.com/tidwall/gjson"
)

func TestValidateCodexEncryptedInput(t *testing.T) {
	envelope := make([]byte, 73)
	envelope[0] = 0x80
	valid := base64.RawURLEncoding.EncodeToString(envelope)
	for _, tc := range []struct {
		name, item, param string
	}{
		{"valid compaction", `{"type":"compaction","encrypted_content":"` + valid + `"}`, ""},
		{"padded envelope", `{"type":"compaction","encrypted_content":"` + base64.URLEncoding.EncodeToString(envelope) + `"}`, ""},
		{"opaque future envelope", `{"type":"compaction","encrypted_content":"bmV3LWVudmVsb3Bl"}`, ""},
		{"missing compaction", `{"type":"compaction"}`, "input[0].encrypted_content"},
		{"null compaction", `{"type":"compaction","encrypted_content":null}`, "input[0].encrypted_content"},
		{"number compaction", `{"type":"compaction","encrypted_content":42}`, "input[0].encrypted_content"},
		{"empty compaction", `{"type":"compaction","encrypted_content":""}`, "input[0].encrypted_content"},
		{"truncated envelope", `{"type":"compaction","encrypted_content":"gAAAA... (litellm_truncated)"}`, "input[0].encrypted_content"},
		{"short Fernet", `{"type":"compaction","encrypted_content":"gAAAAAAA"}`, "input[0].encrypted_content"},
		{"whitespace", `{"type":"compaction","encrypted_content":"` + valid + `\n"}`, "input[0].encrypted_content"},
		{"unicode ellipsis", `{"type":"compaction","encrypted_content":"gAAAA\u2026"}`, "input[0].encrypted_content"},
		{"tool explicit field", `{"type":"function_call_output","encrypted_content":false}`, "input[0].encrypted_content"},
		{"custom tool part", `{"type":"custom_tool_call_output","output":[{"type":"input_text","text":"ok"},{"type":"encrypted_content","encrypted_content":"bad!SECRET"}]}`, "input[0].output[1].encrypted_content"},
		{"tool part missing blob", `{"type":"function_call_output","output":[{"type":"encrypted_content"}]}`, "input[0].output[0].encrypted_content"},
		{"valid tool part", `{"type":"function_call_output","output":[{"type":"encrypted_content","encrypted_content":"` + valid + `"}]}`, ""},
		{"plain tool text", `{"type":"function_call_output","output":"gAAAA... (litellm_truncated)"}`, ""},
		{"plain text part", `{"type":"custom_tool_call_output","output":[{"type":"input_text","text":"bad!SECRET"}]}`, ""},
		{"unrelated message field", `{"role":"user","content":"hello","encrypted_content":"bad!SECRET"}`, ""},
		{"existing reasoning sanitizer", `{"type":"reasoning","encrypted_content":"bad!SECRET"}`, ""},
		{"escaped type", `{"type":"com\u0070action","encrypted_content":"bad!SECRET"}`, "input[0].encrypted_content"},
		{"oversized", `{"type":"compaction","encrypted_content":"` + strings.Repeat("A", signature.MaxGPTReasoningSignatureLen+1) + `"}`, "input[0].encrypted_content"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(`{"input":[` + tc.item + `]}`)
			before := bytes.Clone(body)
			err := ValidateCodexEncryptedInput(body)
			if !bytes.Equal(body, before) {
				t.Fatal("validator mutated context")
			}
			if tc.param == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var rejected *codexEncryptedInputError
			if !errors.As(err, &rejected) || rejected.StatusCode() != 400 || !rejected.IsRequestScoped() {
				t.Fatalf("expected request-scoped local 400, got %v", err)
			}
			if gjson.Get(err.Error(), "error.param").String() != tc.param || gjson.Get(err.Error(), "error.code").String() != "invalid_encrypted_content" {
				t.Fatalf("unexpected error: %v", err)
			}
			if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), valid) {
				t.Fatal("error leaked content")
			}
		})
	}
}
