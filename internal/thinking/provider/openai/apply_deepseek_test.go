package openai

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/thinking"
	"github.com/tidwall/gjson"
)

func TestApplyDeepSeekV4ReasoningEffort(t *testing.T) {
	tests := []struct {
		name       string
		config     thinking.ThinkingConfig
		wantType   string
		wantEffort string
	}{
		{name: "none", config: thinking.ThinkingConfig{Mode: thinking.ModeNone}, wantType: "disabled"},
		{name: "minimal", config: thinking.ThinkingConfig{Mode: thinking.ModeLevel, Level: thinking.LevelMinimal}, wantType: "enabled", wantEffort: "low"},
		{name: "low", config: thinking.ThinkingConfig{Mode: thinking.ModeLevel, Level: thinking.LevelLow}, wantType: "enabled", wantEffort: "low"},
		{name: "medium", config: thinking.ThinkingConfig{Mode: thinking.ModeLevel, Level: thinking.LevelMedium}, wantType: "enabled", wantEffort: "high"},
		{name: "high", config: thinking.ThinkingConfig{Mode: thinking.ModeLevel, Level: thinking.LevelHigh}, wantType: "enabled", wantEffort: "high"},
		{name: "xhigh", config: thinking.ThinkingConfig{Mode: thinking.ModeLevel, Level: thinking.LevelXHigh}, wantType: "enabled", wantEffort: "xhigh"},
		{name: "max", config: thinking.ThinkingConfig{Mode: thinking.ModeLevel, Level: thinking.LevelMax}, wantType: "enabled", wantEffort: "max"},
	}

	applier := NewApplier()
	modelInfo := &registry.ModelInfo{ID: "deepseek-flash", Type: "openai-compatibility"}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := []byte(`{"reasoning_effort":"stale","thinking":{"type":"stale"}}`)
			out, err := applier.Apply(body, test.config, modelInfo)
			if err != nil {
				t.Fatalf("Apply() error = %v", err)
			}
			if got := gjson.GetBytes(out, "thinking.type").String(); got != test.wantType {
				t.Fatalf("thinking.type = %q, want %q; body=%s", got, test.wantType, out)
			}
			effort := gjson.GetBytes(out, "reasoning_effort")
			if test.wantEffort == "" {
				if effort.Exists() {
					t.Fatalf("reasoning_effort exists, want omitted; body=%s", out)
				}
			} else if effort.String() != test.wantEffort {
				t.Fatalf("reasoning_effort = %q, want %q; body=%s", effort.String(), test.wantEffort, out)
			}
		})
	}
}

func TestApplyDeepSeekV4MatchesOfficialAndConfiguredNames(t *testing.T) {
	models := []string{
		"deepseek-flash",
		"deepseek-latest-flash",
		"deepseek-v4.1-flash",
		"deepseek-ai/DeepSeek-V4-Flash-0731",
		"deepseek_v4_flash",
	}
	for _, model := range models {
		if !isDeepSeekV4Model(&registry.ModelInfo{ID: model}) {
			t.Fatalf("isDeepSeekV4Model(%q) = false, want true", model)
		}
	}
	if isDeepSeekV4Model(&registry.ModelInfo{ID: "deepseek-v3.1"}) {
		t.Fatal("DeepSeek V3.1 must not use the V4 effort mapping")
	}
}

func TestApplyNonDeepSeekOpenAIModelUnchanged(t *testing.T) {
	applier := NewApplier()
	modelInfo := &registry.ModelInfo{
		ID:       "generic-openai-model",
		Type:     "openai-compatibility",
		Thinking: &registry.ThinkingSupport{Levels: []string{"low", "medium", "high"}},
	}
	out, err := applier.Apply(
		[]byte(`{"reasoning_effort":"low"}`),
		thinking.ThinkingConfig{Mode: thinking.ModeLevel, Level: thinking.LevelMedium},
		modelInfo,
	)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if got := gjson.GetBytes(out, "reasoning_effort").String(); got != "medium" {
		t.Fatalf("reasoning_effort = %q, want medium; body=%s", got, out)
	}
	if gjson.GetBytes(out, "thinking").Exists() {
		t.Fatalf("generic model gained DeepSeek thinking field: %s", out)
	}
}

func TestDeepSeekV41XHighUsesResolvedVersion(t *testing.T) {
	for _, tc := range []struct{ model, want string }{
		{"deepseek-flash", "xhigh"},
		{"deepseek-v4.1-flash", "xhigh"},
		{"deepseek-ai/DeepSeek-V4.1-Flash", "xhigh"},
		{"deepseek_v4.1_flash", "xhigh"},
		{"deepseek-v4-flash", "high"},
		{"deepseek-ai/DeepSeek-V4-Flash-0731", "high"},
		{"deepseek-latest-flash", "high"},
	} {
		t.Run(tc.model, func(t *testing.T) {
			out, err := NewApplier().Apply([]byte(`{}`), thinking.ThinkingConfig{Mode: thinking.ModeLevel, Level: thinking.LevelXHigh}, &registry.ModelInfo{ID: tc.model})
			if err != nil {
				t.Fatal(err)
			}
			if got := gjson.GetBytes(out, "reasoning_effort").String(); got != tc.want {
				t.Fatalf("effort=%q, want %q", got, tc.want)
			}
		})
	}
}
