package management

import "testing"

func TestLatestReleaseURLUsesNekoparaFork(t *testing.T) {
	const want = "https://api.github.com/repos/nekopara-ai/CLIProxyAPI/releases/latest"
	if latestReleaseURL != want {
		t.Fatalf("latestReleaseURL = %q, want %q", latestReleaseURL, want)
	}
}
