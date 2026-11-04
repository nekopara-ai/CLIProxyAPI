// Package openai implements thinking configuration for OpenAI/Codex models.
package openai

import (
	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/thinking"
	"strings"
)

// Applier implements thinking.ProviderApplier for OpenAI models.
type Applier struct{}

var _ thinking.ProviderDocApplier = (*Applier)(nil)

// NewApplier creates a new OpenAI thinking applier.
func NewApplier() *Applier {
	return &Applier{}
}

func init() {
	thinking.RegisterProvider("openai", NewApplier())
}

// Apply applies thinking configuration to OpenAI request body.
func (a *Applier) Apply(body []byte, config thinking.ThinkingConfig, modelInfo *registry.ModelInfo) ([]byte, error) {
	if !isDeepSeekV4Model(modelInfo) {
		if _, ok := resolveOpenAIEffort(config, modelInfo); !ok {
			return body, nil
		}
	}
	if len(body) == 0 || !ojson.ValidBytes(body) {
		body = []byte("{}")
	}
	doc := ojson.NewDoc(body)
	if err := a.ApplyDoc(doc, config, modelInfo); err != nil {
		return nil, err
	}
	return doc.Bytes(), nil
}

// ApplyDoc applies thinking configuration onto doc in place.
func (a *Applier) ApplyDoc(doc *ojson.Doc, config thinking.ThinkingConfig, modelInfo *registry.ModelInfo) error {
	if doc == nil {
		return nil
	}
	if isDeepSeekV4Model(modelInfo) {
		return applyDeepSeekV4Doc(doc, config, isDeepSeekV41Model(modelInfo))
	}
	effort, ok := resolveOpenAIEffort(config, modelInfo)
	if !ok {
		return nil
	}
	_ = doc.Set("reasoning_effort", effort)
	return nil
}

func resolveOpenAIEffort(config thinking.ThinkingConfig, modelInfo *registry.ModelInfo) (string, bool) {
	if thinking.IsUserDefinedModel(modelInfo) {
		switch config.Mode {
		case thinking.ModeLevel:
			if config.Level == "" {
				return "", false
			}
			return string(config.Level), true
		case thinking.ModeNone:
			effort := string(thinking.LevelNone)
			if config.Level != "" {
				effort = string(config.Level)
			}
			return effort, true
		case thinking.ModeAuto:
			return string(thinking.LevelAuto), true
		case thinking.ModeBudget:
			level, ok := thinking.ConvertBudgetToLevel(config.Budget)
			if !ok {
				return "", false
			}
			return level, true
		default:
			return "", false
		}
	}
	if modelInfo.Thinking == nil {
		return "", false
	}
	if config.Mode != thinking.ModeLevel && config.Mode != thinking.ModeNone {
		return "", false
	}
	if config.Mode == thinking.ModeLevel {
		return string(config.Level), true
	}

	effort := ""
	support := modelInfo.Thinking
	if config.Budget == 0 {
		if support.ZeroAllowed || thinking.HasLevel(support.Levels, string(thinking.LevelNone)) {
			effort = string(thinking.LevelNone)
		}
	}
	if effort == "" && config.Level != "" {
		effort = string(config.Level)
	}
	if effort == "" && len(support.Levels) > 0 {
		effort = support.Levels[0]
	}
	if effort == "" {
		return "", false
	}
	return effort, true
}

func isDeepSeekV4Model(modelInfo *registry.ModelInfo) bool {
	if modelInfo == nil {
		return false
	}
	model := strings.ToLower(strings.TrimSpace(modelInfo.ID))
	return model == "deepseek-flash" ||
		strings.Contains(model, "deepseek-latest") ||
		strings.Contains(model, "deepseek-v4") ||
		strings.Contains(model, "deepseek_v4")
}

// isDeepSeekV41Model uses the resolved upstream identity, not a public alias
// which may also select an older V4 deployment. OpenCode serves V4.1 as
// deepseek-flash; explicit V4 names retain their existing effort mapping.
func isDeepSeekV41Model(modelInfo *registry.ModelInfo) bool {
	if modelInfo == nil {
		return false
	}
	model := strings.ToLower(strings.TrimSpace(modelInfo.ID))
	model = model[strings.LastIndex(model, "/")+1:]
	return model == "deepseek-flash" || model == "deepseek-v4.1" ||
		strings.HasPrefix(model, "deepseek-v4.1-") ||
		model == "deepseek_v4.1" || strings.HasPrefix(model, "deepseek_v4.1_")
}

func applyDeepSeekV4Doc(doc *ojson.Doc, config thinking.ThinkingConfig, preserveXHigh bool) error {

	if config.Mode == thinking.ModeNone {
		_ = doc.Delete("reasoning_effort")
		_ = doc.Set("thinking.type", "disabled")
		return nil
	}

	effort := ""
	switch config.Mode {
	case thinking.ModeLevel:
		switch config.Level {
		case thinking.LevelMinimal, thinking.LevelLow:
			effort = string(thinking.LevelLow)
		case thinking.LevelMedium, thinking.LevelHigh:
			effort = string(thinking.LevelHigh)
		case thinking.LevelXHigh:
			effort = string(thinking.LevelHigh)
			if preserveXHigh {
				effort = string(thinking.LevelXHigh)
			}
		case thinking.LevelMax, thinking.ThinkingLevel("ultra"):
			effort = string(thinking.LevelMax)
		}
	case thinking.ModeAuto:
		effort = string(thinking.LevelHigh)
	case thinking.ModeBudget:
		level, ok := thinking.ConvertBudgetToLevel(config.Budget)
		if ok {
			return applyDeepSeekV4Doc(doc, thinking.ThinkingConfig{Mode: thinking.ModeLevel, Level: thinking.ThinkingLevel(level)}, preserveXHigh)
		}
	}
	if effort == "" {
		return nil
	}

	_ = doc.Set("thinking.type", "enabled")
	_ = doc.Set("reasoning_effort", effort)
	return nil
}
