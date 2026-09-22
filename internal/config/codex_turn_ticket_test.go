package config

import (
	"encoding/json"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestCodexTurnTicketAdaptiveConfigDecoding pins the wire names of the adaptive routing
// fields so a rename cannot silently drop operator configuration.
func TestCodexTurnTicketAdaptiveConfigDecoding(t *testing.T) {
	const yamlConfig = `codex:
  turn-ticket:
    enabled: true
    injection-enabled: true
    adaptive-injection: false
    routing-cookie-ttl-seconds: 120
    routing-refresh-before-seconds: 20
    routing-probe-interval-seconds: 10
    harvest-attempts: 5
`
	const jsonConfig = `{"codex":{"turn-ticket":{"enabled":true,"injection-enabled":true,` +
		`"adaptive-injection":false,"routing-cookie-ttl-seconds":120,` +
		`"routing-refresh-before-seconds":20,"routing-probe-interval-seconds":10,` +
		`"harvest-attempts":5}}}`

	for _, tt := range []struct {
		name   string
		decode func(*Config) error
	}{
		{
			name: "YAML",
			decode: func(cfg *Config) error {
				return yaml.Unmarshal([]byte(yamlConfig), cfg)
			},
		},
		{
			name: "JSON",
			decode: func(cfg *Config) error {
				return json.Unmarshal([]byte(jsonConfig), cfg)
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var cfg Config
			if errDecode := tt.decode(&cfg); errDecode != nil {
				t.Fatalf("decode config: %v", errDecode)
			}
			ttk := cfg.Codex.TurnTicket
			if !ttk.Enabled {
				t.Fatal("enabled = false, want true")
			}
			if ttk.InjectionEnabled == nil || !*ttk.InjectionEnabled {
				t.Fatalf("injection-enabled = %v, want explicit true", ttk.InjectionEnabled)
			}
			if ttk.AdaptiveInjection == nil || *ttk.AdaptiveInjection {
				t.Fatalf("adaptive-injection = %v, want explicit false", ttk.AdaptiveInjection)
			}
			if ttk.RoutingCookieTTLSeconds != 120 {
				t.Fatalf("routing-cookie-ttl-seconds = %d, want 120", ttk.RoutingCookieTTLSeconds)
			}
			if ttk.RoutingRefreshBeforeSeconds != 20 {
				t.Fatalf("routing-refresh-before-seconds = %d, want 20", ttk.RoutingRefreshBeforeSeconds)
			}
			if ttk.RoutingProbeIntervalSeconds != 10 {
				t.Fatalf("routing-probe-interval-seconds = %d, want 10", ttk.RoutingProbeIntervalSeconds)
			}
			if ttk.HarvestAttempts != 5 {
				t.Fatalf("harvest-attempts = %d, want 5", ttk.HarvestAttempts)
			}
		})
	}
}

// TestCodexTurnTicketAdaptiveConfigOmittedLeavesNilTreatsAsUnset documents that the
// config layer does not bake in the adaptive default; the core resolves it.
func TestCodexTurnTicketAdaptiveConfigOmittedLeavesNil(t *testing.T) {
	var cfg Config
	if errDecode := yaml.Unmarshal([]byte("codex:\n  turn-ticket:\n    enabled: true\n"), &cfg); errDecode != nil {
		t.Fatalf("decode config: %v", errDecode)
	}
	ttk := cfg.Codex.TurnTicket
	if ttk.AdaptiveInjection != nil {
		t.Fatalf("adaptive-injection = %v, want nil when omitted", *ttk.AdaptiveInjection)
	}
	if ttk.RoutingCookieTTLSeconds != 0 || ttk.RoutingRefreshBeforeSeconds != 0 || ttk.RoutingProbeIntervalSeconds != 0 || ttk.HarvestAttempts != 0 {
		t.Fatalf("numeric adaptive fields = %d/%d/%d/%d, want zero-value when omitted",
			ttk.RoutingCookieTTLSeconds, ttk.RoutingRefreshBeforeSeconds, ttk.RoutingProbeIntervalSeconds, ttk.HarvestAttempts)
	}
}
