package auth

import "testing"

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
