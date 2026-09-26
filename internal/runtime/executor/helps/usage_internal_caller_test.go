package helps

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
)

func TestInternalUsageCallerDoesNotReplaceCredentialOrBusinessKey(t *testing.T) {
	ctx := usage.WithInternalAPIKey(context.Background(), "synthetic-system")
	auth := &coreauth.Auth{ID: "selected-account", Provider: "codex", Metadata: map[string]any{"email": "selected@example.invalid"}}
	r := NewUsageReporter(ctx, "codex", "gpt-6-sol", auth)
	if r.apiKey != "synthetic-system" || r.authID != auth.ID || r.source != "selected@example.invalid" {
		t.Fatal("caller attribution changed the selected account identity")
	}
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Set("userApiKey", "business-caller")
	business := context.WithValue(ctx, "gin", c)
	if APIKeyFromContext(business) != "business-caller" {
		t.Fatal("internal metadata overrode authenticated business caller")
	}
	c.Set("userApiKey", "")
	if APIKeyFromContext(business) != "" {
		t.Fatal("explicit empty business caller inherited internal identity")
	}
	if APIKeyFromContext(nil) != "" {
		t.Fatal("nil context acquired a key")
	}
}
