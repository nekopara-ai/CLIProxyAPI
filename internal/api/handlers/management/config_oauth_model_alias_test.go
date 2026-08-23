package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"gopkg.in/yaml.v3"
)

const oauthModelAliasConfigYAML = `# preserve this comment
oauth-model-alias:
  codex:
    - name: gpt-5.6
      alias: luna
`

func writeOAuthModelAliasConfigFile(t *testing.T) (string, []byte) {
	t.Helper()
	path := writeTestConfigFile(t)
	contents := []byte(oauthModelAliasConfigYAML)
	if errWrite := os.WriteFile(path, contents, 0o600); errWrite != nil {
		t.Fatalf("failed to write OAuth model alias config: %v", errWrite)
	}
	return path, contents
}

func newOAuthModelAliasConfig() *config.Config {
	return &config.Config{
		OAuthModelAlias: map[string][]config.OAuthModelAlias{
			"codex": {{Name: "gpt-5.6", Alias: "luna"}},
		},
	}
}

func oauthModelAliasRequest(method, path, body string) (*gin.Context, *httptest.ResponseRecorder) {
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(method, path, strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	return ctx, recorder
}

func requireOAuthModelAliasStatusOK(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var response struct {
		Status string `json:"status"`
	}
	if errDecode := json.Unmarshal(recorder.Body.Bytes(), &response); errDecode != nil {
		t.Fatalf("decode response: %v", errDecode)
	}
	if response.Status != "ok" {
		t.Fatalf("response status = %q, want ok", response.Status)
	}
}

func TestOAuthModelAliasNoOpWriteSkipsPersistAndReload(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		body   string
		invoke func(*Handler, *gin.Context)
	}{
		{
			name:   "PUT",
			method: http.MethodPut,
			path:   "/v0/management/oauth-model-alias",
			body:   `{" CODEx ":[{"name":" gpt-5.6 ","alias":" luna "}]}`,
			invoke: func(h *Handler, c *gin.Context) { h.PutOAuthModelAlias(c) },
		},
		{
			name:   "PATCH",
			method: http.MethodPatch,
			path:   "/v0/management/oauth-model-alias",
			body:   `{"channel":" CODEX ","aliases":[{"name":" gpt-5.6 ","alias":" luna "}]}`,
			invoke: func(h *Handler, c *gin.Context) { h.PatchOAuthModelAlias(c) },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path, before := writeOAuthModelAliasConfigFile(t)
			original := newOAuthModelAliasConfig()
			h := &Handler{cfg: original, configFilePath: path}
			reloads := make(chan *config.Config, 1)
			h.SetConfigReloadHook(func(_ context.Context, cfg *config.Config) {
				reloads <- cfg
			})

			ctx, recorder := oauthModelAliasRequest(tc.method, tc.path, tc.body)
			tc.invoke(h, ctx)

			requireOAuthModelAliasStatusOK(t, recorder)
			after, errRead := os.ReadFile(path)
			if errRead != nil {
				t.Fatalf("read config: %v", errRead)
			}
			if string(after) != string(before) {
				t.Fatalf("no-op write changed config file:\n%s", after)
			}

			h.mu.Lock()
			gotConfig := h.cfg
			generation := h.reloadGeneration
			h.mu.Unlock()
			if gotConfig != original {
				t.Fatal("no-op write replaced handler config")
			}
			if generation != 0 {
				t.Fatalf("reload generation = %d, want 0", generation)
			}
			select {
			case <-reloads:
				t.Fatal("no-op write triggered config reload")
			default:
			}
		})
	}
}

func TestOAuthModelAliasChangedWritePersistsIndependentCandidate(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		path      string
		body      string
		wantAlias string
		wantCount int
		invoke    func(*Handler, *gin.Context)
	}{
		{
			name:      "PUT",
			method:    http.MethodPut,
			path:      "/v0/management/oauth-model-alias",
			body:      `{"codex":[{"name":"gpt-5.6","alias":"luna"},{"name":"gpt-5.6-codex","alias":"sol"}]}`,
			wantAlias: "sol",
			wantCount: 2,
			invoke:    func(h *Handler, c *gin.Context) { h.PutOAuthModelAlias(c) },
		},
		{
			name:      "PATCH",
			method:    http.MethodPatch,
			path:      "/v0/management/oauth-model-alias",
			body:      `{"provider":"codex","aliases":[{"name":"gpt-5.6-codex","alias":"sol"}]}`,
			wantAlias: "sol",
			wantCount: 1,
			invoke:    func(h *Handler, c *gin.Context) { h.PatchOAuthModelAlias(c) },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path, before := writeOAuthModelAliasConfigFile(t)
			original := newOAuthModelAliasConfig()
			h := &Handler{cfg: original, configFilePath: path}
			reloads := make(chan *config.Config, 1)
			h.SetConfigReloadHook(func(_ context.Context, cfg *config.Config) {
				reloads <- cfg
			})

			ctx, recorder := oauthModelAliasRequest(tc.method, tc.path, tc.body)
			tc.invoke(h, ctx)

			requireOAuthModelAliasStatusOK(t, recorder)
			h.mu.Lock()
			gotConfig := h.cfg
			generation := h.reloadGeneration
			h.mu.Unlock()
			if gotConfig == original {
				t.Fatal("changed write did not replace handler config with an independent candidate")
			}
			if generation != 1 {
				t.Fatalf("reload generation = %d, want 1", generation)
			}
			if got := original.OAuthModelAlias["codex"]; len(got) != 1 || got[0].Alias != "luna" {
				t.Fatalf("shared original config was mutated: %#v", got)
			}
			gotAliases := gotConfig.OAuthModelAlias["codex"]
			if len(gotAliases) != tc.wantCount || gotAliases[len(gotAliases)-1].Alias != tc.wantAlias {
				t.Fatalf("handler aliases = %#v, want count %d ending in %q", gotAliases, tc.wantCount, tc.wantAlias)
			}

			after, errRead := os.ReadFile(path)
			if errRead != nil {
				t.Fatalf("read config: %v", errRead)
			}
			if string(after) == string(before) {
				t.Fatal("changed write did not update config file")
			}
			var saved struct {
				OAuthModelAlias map[string][]config.OAuthModelAlias `yaml:"oauth-model-alias"`
			}
			if errUnmarshal := yaml.Unmarshal(after, &saved); errUnmarshal != nil {
				t.Fatalf("decode saved config: %v", errUnmarshal)
			}
			savedAliases := saved.OAuthModelAlias["codex"]
			if len(savedAliases) != tc.wantCount || savedAliases[len(savedAliases)-1].Alias != tc.wantAlias {
				t.Fatalf("saved aliases = %#v, want count %d ending in %q", savedAliases, tc.wantCount, tc.wantAlias)
			}

			select {
			case reloaded := <-reloads:
				reloadedAliases := reloaded.OAuthModelAlias["codex"]
				if len(reloadedAliases) != tc.wantCount || reloadedAliases[len(reloadedAliases)-1].Alias != tc.wantAlias {
					t.Fatalf("reloaded aliases = %#v, want count %d ending in %q", reloadedAliases, tc.wantCount, tc.wantAlias)
				}
			case <-time.After(time.Second):
				t.Fatal("changed write did not trigger config reload")
			}
		})
	}
}

func TestDeleteOAuthModelAliasPersistsIndependentCandidate(t *testing.T) {
	path, before := writeOAuthModelAliasConfigFile(t)
	original := newOAuthModelAliasConfig()
	h := &Handler{cfg: original, configFilePath: path}
	reloads := make(chan *config.Config, 1)
	h.SetConfigReloadHook(func(_ context.Context, cfg *config.Config) {
		reloads <- cfg
	})

	ctx, recorder := oauthModelAliasRequest(http.MethodDelete, "/v0/management/oauth-model-alias?channel=codex", "")
	h.DeleteOAuthModelAlias(ctx)

	requireOAuthModelAliasStatusOK(t, recorder)
	h.mu.Lock()
	gotConfig := h.cfg
	generation := h.reloadGeneration
	h.mu.Unlock()
	if gotConfig == original {
		t.Fatal("delete did not replace handler config with an independent candidate")
	}
	if generation != 1 {
		t.Fatalf("reload generation = %d, want 1", generation)
	}
	if len(original.OAuthModelAlias["codex"]) != 1 {
		t.Fatal("delete mutated shared original config")
	}
	if gotConfig.OAuthModelAlias != nil {
		t.Fatalf("handler aliases = %#v, want nil", gotConfig.OAuthModelAlias)
	}

	after, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatalf("read config: %v", errRead)
	}
	if string(after) == string(before) {
		t.Fatal("delete did not update config file")
	}
	var saved struct {
		OAuthModelAlias map[string][]config.OAuthModelAlias `yaml:"oauth-model-alias"`
	}
	if errUnmarshal := yaml.Unmarshal(after, &saved); errUnmarshal != nil {
		t.Fatalf("decode saved config: %v", errUnmarshal)
	}
	if len(saved.OAuthModelAlias) != 0 {
		t.Fatalf("saved aliases = %#v, want empty", saved.OAuthModelAlias)
	}

	select {
	case reloaded := <-reloads:
		if reloaded.OAuthModelAlias != nil {
			t.Fatalf("reloaded aliases = %#v, want nil", reloaded.OAuthModelAlias)
		}
	case <-time.After(time.Second):
		t.Fatal("delete did not trigger config reload")
	}
}
