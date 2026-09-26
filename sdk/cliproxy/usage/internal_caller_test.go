package usage

import (
	"context"
	"testing"
)

func TestInternalAPIKeyContext(t *testing.T) {
	if InternalAPIKeyFromContext(nil) != "" || InternalAPIKeyFromContext(context.Background()) != "" {
		t.Fatal("missing internal identity must stay empty")
	}
	ctx := WithInternalAPIKey(nil, " synthetic-system ")
	if InternalAPIKeyFromContext(ctx) != "synthetic-system" {
		t.Fatal("typed identity lost")
	}
	if InternalAPIKeyFromContext(WithInternalAPIKey(ctx, "")) != "" {
		t.Fatal("empty identity did not clear the inherited internal key")
	}
	if InternalAPIKeyFromContext(context.WithValue(context.Background(), "internal_api_key", "untrusted")) != "" {
		t.Fatal("untyped metadata must not impersonate an internal key")
	}
}
