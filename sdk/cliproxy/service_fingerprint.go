package cliproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/fingerprint"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

func (s *Service) currentConfig() *config.Config {
	if s == nil {
		return nil
	}
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.cfg
}
func (s *Service) startFingerprintMonitor(ctx context.Context) {
	if s == nil || s.coreManager == nil {
		return
	}
	s.fingerprintMonitor = fingerprint.New(s.currentConfig, s.coreManager.List, s.probeFingerprint)
	fingerprint.SetCurrent(s.fingerprintMonitor)
	s.coreManager.SetExecutionModelGuard(s.fingerprintMonitor.Allowed)
	s.fingerprintMonitor.Start(ctx)
}
func (s *Service) probeFingerprint(ctx context.Context, a *coreauth.Auth, model, prompt string) (string, error) {
	if a == nil || a.Provider != "codex" {
		return "", errors.New("fingerprint probes require a Codex credential")
	}
	current := s.currentConfig()
	if current == nil {
		return "", errors.New("fingerprint configuration unavailable")
	}
	callerKey, err := current.InternalRequestAPIKey()
	if err != nil {
		return "", err
	}
	ctx = usage.WithInternalAPIKey(ctx, callerKey)
	// Bypass business eligibility only for this selected-auth diagnostic. No selector,
	// proxy substitution, token sharing, or automatic credential enablement is involved.
	provider, ok := s.coreManager.Executor(a.Provider)
	if !ok {
		return "", errors.New("executor unavailable")
	}
	if a.Provider == "codex" {
		cfg := *current
		cfg.DisableImageGeneration = config.DisableImageGenerationAll
		cfg.Payload = config.PayloadConfig{}
		provider = runtimeexecutor.NewCodexExecutor(&cfg)
	}
	payload, _ := json.Marshal(map[string]any{"model": model, "instructions": "", "store": false, "stream": true, "input": []any{map[string]any{"role": "user", "type": "message", "content": []any{map[string]any{"type": "input_text", "text": prompt}}}}, "reasoning": map[string]any{"effort": "low"}, "tools": []any{}, "tool_choice": "none", "parallel_tool_calls": false})
	format := translator.FromString("openai-response")
	// The streaming executor stops on terminal SSE events, not on a transport EOF.
	// Cancellation is tied to completion or policy changes, never a wall-clock deadline.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	response, err := provider.ExecuteStream(ctx, a, executor.Request{Model: model, Payload: payload}, executor.Options{SourceFormat: format, ResponseFormat: format, OriginalRequest: payload, Metadata: map[string]any{"fingerprint_probe": true}})
	if err != nil {
		return "", err
	}
	for chunk := range response.Chunks {
		if chunk.Err != nil {
			return "", chunk.Err
		}
		fingerprint.RecordActivity(ctx, len(chunk.Payload))
		for _, line := range bytes.Split(chunk.Payload, []byte("\n")) {
			if !bytes.HasPrefix(line, []byte("data:")) {
				continue
			}
			event := gjson.ParseBytes(bytes.TrimSpace(line[5:]))
			switch event.Get("type").String() {
			case "response.completed":
				return fingerprintResponseText(event.Get("response"))
			case "response.failed", "response.incomplete", "error":
				return "", errors.New("incomplete probe response")
			case "response.output_item.added", "response.output_item.done":
				kind := event.Get("item.type").String()
				if kind != "" && kind != "message" && kind != "reasoning" {
					return "", errors.New("probe attempted a tool call")
				}
			}
		}
	}
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	return "", errors.New("probe stream ended without completion")
}

func fingerprintResponseText(data gjson.Result) (string, error) {
	if data.Get("status").String() != "completed" || data.Get("error").Exists() && data.Get("error").Type != gjson.Null {
		return "", errors.New("incomplete probe response")
	}
	var text strings.Builder
	for _, item := range data.Get("output").Array() {
		if item.Get("type").String() != "message" && item.Get("type").String() != "reasoning" {
			return "", errors.New("probe attempted a tool call")
		}
		for _, part := range item.Get("content").Array() {
			if part.Get("type").String() == "output_text" {
				if text.Len()+len(part.Get("text").String()) > 1<<20 {
					return "", errors.New("probe answer too large")
				}
				text.WriteString(part.Get("text").String())
			}
		}
	}
	return text.String(), nil
}
