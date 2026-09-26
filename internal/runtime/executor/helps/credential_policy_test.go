package helps

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
)

func TestCredentialTimezoneInheritanceAndIsolation(t *testing.T) {
	tokyo := "Asia/Tokyo"
	off := ""
	cfg := &config.Config{TimezoneOverride: "America/New_York", TimezoneOverrideCountry: "US", CredentialPolicies: map[string]config.CredentialPolicy{"a.json": {Timezone: &tokyo}, "b.json": {Timezone: &off}}}
	cases := []struct {
		a    *coreauth.Auth
		want string
	}{{&coreauth.Auth{FileName: "a.json"}, tokyo}, {&coreauth.Auth{FileName: "b.json"}, ""}, {&coreauth.Auth{FileName: "c.json"}, "America/New_York"}, {&coreauth.Auth{FileName: "a.json", Metadata: map[string]any{"timezone_override": "Europe/London"}}, "Europe/London"}}
	var wg sync.WaitGroup
	for _, c := range cases {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				resolved := ConfigForAuth(cfg, c.a)
				if resolved.TimezoneOverride != c.want {
					t.Error("incorrect override")
				}
				if c.a.FileName == "a.json" && resolved.TimezoneOverrideCountry != "" {
					t.Error("inherited conflicting location")
				}
			}
		}()
	}
	wg.Wait()
	if cfg.TimezoneOverride != "America/New_York" || cfg.TimezoneOverrideCountry != "US" {
		t.Fatal("shared config mutated")
	}
}
func TestTimezoneToolOutputsUnchanged(t *testing.T) {
	// Build markers in pieces so fixtures stay literal through proxy environments.
	env := "<" + "environment_context><timezone>UTC</timezone><current_date>2000-01-01</current_date></" + "environment_context>"
	raw, _ := json.Marshal(map[string]any{"input": []any{map[string]any{"type": "function_call_output", "output": env}, map[string]any{"role": "tool", "content": env}, map[string]any{"role": "user", "content": []any{map[string]any{"type": "tool_result", "content": env}}}}})
	out := ApplyTimezoneOverrideAt(&config.Config{TimezoneOverride: "Asia/Tokyo"}, raw, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if string(out) != string(raw) {
		t.Fatal("tool output rewritten")
	}
	msg, _ := json.Marshal(map[string]any{"input": []any{map[string]any{"role": "user", "content": env}}})
	out = ApplyTimezoneOverrideAt(&config.Config{TimezoneOverride: "Asia/Tokyo"}, msg, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if gjson.GetBytes(out, "input.0.content").String() == env {
		t.Fatal("actual environment not rewritten")
	}
}
