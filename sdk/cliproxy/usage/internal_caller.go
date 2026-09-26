package usage

import (
	"context"
	"strings"
)

type internalAPIKeyContextKey struct{}

// WithInternalAPIKey attributes a background execution to an operator-selected client key.
// This is accounting metadata, not upstream authentication or a routing override.
func WithInternalAPIKey(ctx context.Context, key string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, internalAPIKeyContextKey{}, strings.TrimSpace(key))
}

// InternalAPIKeyFromContext returns only a typed, internally supplied key.
func InternalAPIKeyFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	key, _ := ctx.Value(internalAPIKeyContextKey{}).(string)
	return key
}
