package cliproxy

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

type aliasReloadTestExecutor struct {
	mu         sync.Mutex
	closed     []string
	identifier string
}

func (e *aliasReloadTestExecutor) Identifier() string { return e.identifier }

func (e *aliasReloadTestExecutor) Execute(context.Context, *auth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e *aliasReloadTestExecutor) ExecuteStream(context.Context, *auth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	chunks := make(chan cliproxyexecutor.StreamChunk)
	close(chunks)
	return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
}

func (e *aliasReloadTestExecutor) Refresh(_ context.Context, auth *auth.Auth) (*auth.Auth, error) {
	return auth, nil
}

func (e *aliasReloadTestExecutor) CountTokens(context.Context, *auth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e *aliasReloadTestExecutor) HttpRequest(context.Context, *auth.Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

func (e *aliasReloadTestExecutor) CloseExecutionSession(sessionID string) {
	e.mu.Lock()
	e.closed = append(e.closed, sessionID)
	e.mu.Unlock()
}

func (e *aliasReloadTestExecutor) closedSessionIDs() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.closed...)
}

func TestServiceOAuthModelAliasReloadPreservesCodexExecutor(t *testing.T) {
	const authID = "alias-reload-codex-auth"
	manager := auth.NewManager(nil, nil, nil)
	credential := &auth.Auth{
		ID:       authID,
		Provider: "codex",
		Status:   auth.StatusActive,
		Attributes: map[string]string{
			auth.AttributeAuthKind: auth.AuthKindOAuth,
		},
	}
	if _, errRegister := manager.Register(auth.WithSkipPersist(context.Background()), credential); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
	oldConfig := &config.Config{
		OAuthModelAlias: map[string][]config.OAuthModelAlias{
			"codex": {{Name: "gpt-5.5", Alias: "gpt-5-legacy"}},
		},
	}
	newConfig := oldConfig.CloneForRuntime()
	newConfig.OAuthModelAlias = map[string][]config.OAuthModelAlias{
		"codex": {{Name: "gpt-5.5", Alias: "gpt-5-public"}},
	}
	service := &Service{cfg: oldConfig, coreManager: manager}
	executor := &aliasReloadTestExecutor{identifier: "codex"}
	manager.RegisterExecutor(executor)
	t.Cleanup(func() { GlobalModelRegistry().UnregisterClient(authID) })

	service.applyWatcherOAuthModelAliasUpdate(newConfig)

	currentExecutor, okExecutor := manager.Executor("codex")
	if !okExecutor || currentExecutor != executor {
		t.Fatalf("alias-only update replaced codex executor: got %T/%p, want %T/%p", currentExecutor, currentExecutor, executor, executor)
	}
	if closed := executor.closedSessionIDs(); len(closed) != 0 {
		t.Fatalf("alias-only update closed active sessions: %v", closed)
	}
	models := registry.GetGlobalRegistry().GetModelsForClient(authID)
	foundPublic, foundLegacy := false, false
	for _, model := range models {
		if model == nil {
			continue
		}
		foundPublic = foundPublic || model.ID == "gpt-5-public"
		foundLegacy = foundLegacy || model.ID == "gpt-5-legacy"
	}
	if !foundPublic || foundLegacy {
		t.Fatalf("model registry after alias update has public=%t legacy=%t", foundPublic, foundLegacy)
	}
}

func TestServiceOAuthModelAliasReloadFallsBackToFullRebuildForOtherChanges(t *testing.T) {
	const authID = "alias-reload-negative-auth"
	manager := auth.NewManager(nil, nil, nil)
	credential := &auth.Auth{
		ID:       authID,
		Provider: "codex",
		Status:   auth.StatusActive,
		Attributes: map[string]string{
			auth.AttributeAuthKind: auth.AuthKindOAuth,
		},
	}
	if _, errRegister := manager.Register(auth.WithSkipPersist(context.Background()), credential); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
	oldConfig := &config.Config{
		Port: 8080,
		OAuthModelAlias: map[string][]config.OAuthModelAlias{
			"codex": {{Name: "gpt-5.5", Alias: "gpt-5-legacy"}},
		},
	}
	newConfig := oldConfig.CloneForRuntime()
	newConfig.Port = 8081
	newConfig.OAuthModelAlias = map[string][]config.OAuthModelAlias{
		"codex": {{Name: "gpt-5.5", Alias: "gpt-5-public"}},
	}
	service := &Service{cfg: oldConfig, coreManager: manager}
	executor := &aliasReloadTestExecutor{identifier: "codex"}
	manager.RegisterExecutor(executor)
	t.Cleanup(func() { GlobalModelRegistry().UnregisterClient(authID) })

	service.applyWatcherOAuthModelAliasUpdate(newConfig)

	closed := executor.closedSessionIDs()
	if len(closed) != 1 || closed[0] != auth.CloseAllExecutionSessionsID {
		t.Fatalf("full config change close calls = %v, want [%q]", closed, auth.CloseAllExecutionSessionsID)
	}
	currentExecutor, okExecutor := manager.Executor("codex")
	if !okExecutor || currentExecutor == executor {
		t.Fatal("full config change unexpectedly retained old codex executor")
	}
}
