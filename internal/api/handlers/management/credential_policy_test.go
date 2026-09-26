package management

import (
	"encoding/json"
	"testing"
)

func TestCredentialPolicyPatchValidation(t *testing.T) {
	for _, c := range []struct {
		key, value string
		valid      bool
	}{{"timezone_override", `"Asia/Tokyo"`, true}, {"timezone_override", `""`, true}, {"timezone_override", `null`, true}, {"timezone_override", `"invalid/zone"`, false}, {"timezone_override", `123`, false}, {"fingerprint", `{"enabled":false,"cooldown-seconds":120}`, true}, {"fingerprint", `null`, true}, {"fingerprint", `{"models":[]}`, false}, {"fingerprint.enabled", `true`, false}, {"fingerprint", `{"confidence":0}`, false}} {
		_, err := normalizeAuthFilePatchFields(map[string]json.RawMessage{c.key: json.RawMessage(c.value)})
		if (err == nil) != c.valid {
			t.Fatalf("%s=%s: %v", c.key, c.value, err)
		}
	}
}
