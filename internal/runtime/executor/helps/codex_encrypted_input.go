package helps

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/signature"
	"github.com/tidwall/gjson"
)

// ValidateCodexEncryptedInput checks explicit encrypted context carriers, not
// ordinary tool text. It cannot authenticate ciphertext or establish its owner.
// Malformed tool/compaction state must not be silently dropped from a session.
func ValidateCodexEncryptedInput(body []byte) error {
	for index, item := range gjson.GetBytes(body, "input").Array() {
		path := fmt.Sprintf("input[%d]", index)
		switch item.Get("type").String() {
		case "compaction":
			if err := validateCodexEncryptedValue(item.Get("encrypted_content"), path+".encrypted_content"); err != nil {
				return err
			}
		case "function_call_output", "custom_tool_call_output":
			if value := item.Get("encrypted_content"); value.Exists() {
				if err := validateCodexEncryptedValue(value, path+".encrypted_content"); err != nil {
					return err
				}
			}
			for partIndex, part := range item.Get("output").Array() {
				if part.Get("type").String() != "encrypted_content" {
					continue
				}
				if err := validateCodexEncryptedValue(part.Get("encrypted_content"), fmt.Sprintf("%s.output[%d].encrypted_content", path, partIndex)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func validateCodexEncryptedValue(value gjson.Result, path string) error {
	reason := ""
	switch {
	case value.Type != gjson.String:
		reason = "expected a non-empty encrypted string"
	case value.Str == "":
		reason = "encrypted content is empty"
	case len(value.Str) > signature.MaxGPTReasoningSignatureLen:
		reason = "encrypted content exceeds the local validation limit"
	case strings.ContainsAny(value.Str, " \t\r\n"):
		reason = "encrypted content contains whitespace or a storage truncation marker"
	default:
		// Future opaque envelopes are not assumed to share Fernet's layout.
		// Apply its stronger shape check only when its known prefix is present.
		if strings.HasPrefix(value.Str, "gAAAA") {
			if _, err := signature.InspectGPTReasoningSignature(value.Str); err != nil {
				reason = "malformed encrypted envelope"
			}
		} else if _, err := base64.RawURLEncoding.Strict().DecodeString(value.Str); err != nil {
			if _, errPadded := base64.URLEncoding.Strict().DecodeString(value.Str); errPadded != nil {
				reason = "encrypted content is not valid base64url"
			}
		}
	}
	if reason == "" {
		return nil
	}
	return &codexEncryptedInputError{path: path, reason: reason}
}

type codexEncryptedInputError struct {
	path   string
	reason string
}

func (e *codexEncryptedInputError) Error() string {
	// Only generated paths and fixed reasons are exposed, never item IDs or blobs.
	body, _ := json.Marshal(map[string]any{"error": map[string]string{
		"type":    "invalid_request_error",
		"code":    "invalid_encrypted_content",
		"param":   e.path,
		"message": "CPA blocked malformed encrypted context before upstream dispatch: " + e.reason + ". Restore the original unmodified context or start a new conversation with a plain-text summary.",
	}})
	return string(body)
}

func (*codexEncryptedInputError) StatusCode() int       { return http.StatusBadRequest }
func (*codexEncryptedInputError) IsRequestScoped() bool { return true }
