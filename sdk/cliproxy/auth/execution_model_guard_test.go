package auth

import (
	"context"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/thinking"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestExecutionModelGuardUsesAliasTargetWithoutBlockingSiblingModels(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	a := &Auth{ID: "model-guard-alias", Provider: "codex", Status: StatusActive}
	manager.SetOAuthModelAlias(map[string][]config.OAuthModelAlias{"codex": {
		{Name: "gpt-6-astra", Alias: "astra-public"},
		{Name: "gpt-6-sol", Alias: "sol-public"},
	}})
	manager.SetExecutionModelGuard(func(candidate *Auth, model string) bool {
		return candidate.ID != a.ID || thinking.ParseSuffix(model).ModelName != "gpt-6-astra"
	})
	for _, tc := range []struct {
		requested, upstream string
	}{
		{"astra-public", ""}, {"astra-public(high)", ""},
		{"gpt-6-astra", ""}, {"gpt-6-astra(high)", ""},
		{"sol-public", "gpt-6-sol"}, {"sol-public(high)", "gpt-6-sol(high)"},
		{"gpt-5.6-sol", "gpt-5.6-sol"},
	} {
		got, _ := manager.preparedExecutionModels(a, tc.requested)
		if tc.upstream == "" {
			if len(got) != 0 {
				t.Errorf("blocked route %s resolved to %v", tc.requested, got)
			}
		} else if len(got) != 1 || got[0] != tc.upstream {
			t.Errorf("allowed route %s = %v, want %s", tc.requested, got, tc.upstream)
		}
	}
}

func TestExecutionModelGuardFiltersResolvedModels(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	auth := &Auth{ID: "auth-a", Provider: "codex", Status: StatusActive}
	manager.SetExecutionModelGuard(func(candidate *Auth, model string) bool {
		return candidate != nil && candidate.ID == "auth-a" && model == "gpt-5.6-sol"
	})

	got := manager.filterExecutionModels(auth, "gpt-5.6-sol", []string{"gpt-5.6-sol", "gpt-6-astra"}, true)
	if len(got) != 1 || got[0] != "gpt-5.6-sol" {
		t.Fatalf("guarded models = %v, want only gpt-5.6-sol", got)
	}

	manager.SetExecutionModelGuard(nil)
	got = manager.filterExecutionModels(auth, "gpt-5.6-sol", []string{"gpt-5.6-sol", "gpt-6-astra"}, true)
	if len(got) != 2 {
		t.Fatalf("cleared guard left %d models, want 2", len(got))
	}
}

func TestExecutionModelGuardRecoveryAllowsNewSessionWithoutMovingExistingBinding(t *testing.T) {
	const model = "guard-recovery-model"
	ctx := context.Background()
	affinity := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: &WeightedRoundRobinSelector{}, TTL: 2 * time.Hour})
	defer affinity.Stop()
	manager := NewManager(nil, affinity, nil)
	manager.SetRetryConfig(1, 0, 1)
	ready := false
	manager.SetExecutionModelGuard(func(auth *Auth, _ string) bool {
		return auth.ID != "guard-recovering" || ready
	})
	manager.RegisterExecutor(&customStreamMockExecutor{
		identifier: "codex",
		mockCustomErrorExecutor: mockCustomErrorExecutor{executeFn: func(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
			if auth.ID == "guard-recovering" && !ready {
				t.Fatal("expired routing lease reached the executor")
			}
			return cliproxyexecutor.Response{Payload: []byte(auth.ID)}, nil
		}},
	})
	for _, auth := range []*Auth{
		{ID: "guard-recovering", Provider: "codex", Status: StatusActive, Attributes: map[string]string{"priority": "1"}},
		{ID: "guard-healthy", Provider: "codex", Status: StatusActive, Attributes: map[string]string{"priority": "0"}},
	} {
		registry.GetGlobalRegistry().RegisterClient(auth.ID, "codex", []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })
		if _, err := manager.Register(WithSkipPersist(ctx), auth); err != nil {
			t.Fatal(err)
		}
	}
	execute := func(session, want string) {
		t.Helper()
		response, err := manager.Execute(ctx, []string{"codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{Metadata: map[string]any{cliproxyexecutor.DerivedSessionIDMetadataKey: session}})
		if err != nil || string(response.Payload) != want {
			t.Fatalf("session %s selected %q, error=%v, want %s", session, response.Payload, err, want)
		}
	}
	execute("existing", "guard-healthy")
	ready = true
	execute("existing", "guard-healthy")
	execute("new-after-renewal", "guard-recovering")
	ready = false
	execute("new-after-renewal", "guard-healthy")
}
