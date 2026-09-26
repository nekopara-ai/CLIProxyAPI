package diff

import (
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestInternalRequestKeyChangeLogDoesNotDiscloseReference(t *testing.T) {
	old := &config.Config{}
	next := &config.Config{InternalRequestAPIKeySHA256: strings.Repeat("a", 64)}
	detail := strings.Join(BuildConfigChangeDetails(old, next), "\n")
	if !strings.Contains(detail, "internal request API key reference updated") || strings.Contains(detail, next.InternalRequestAPIKeySHA256) {
		t.Fatal("missing or unredacted key reference change")
	}
}
