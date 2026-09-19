package cliproxy

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
)

// TestRunInstallsTurnTicketWiringInHomeMode is the Home-mode regression. Home serves the
// same Codex traffic as the standard runtime, so the turn-ticket subsystem must be wired
// by the real Run lifecycle, not only by the non-Home branch.
//
// Home mode does not need a reachable Home control plane for this assertion: the wiring is
// installed while Run is starting the server, and the subscriber retries in the background.
func TestRunInstallsTurnTicketWiringInHomeMode(t *testing.T) {
	defer helps.ConfigureCodexTurnTickets(nil, nil)
	listener, errListen := net.Listen("tcp4", "127.0.0.1:0")
	if errListen != nil {
		t.Fatalf("reserve loopback port: %v", errListen)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if errClose := listener.Close(); errClose != nil {
		t.Fatalf("release reserved port: %v", errClose)
	}

	tempDir := t.TempDir()
	cfg := &config.Config{
		Host:    "127.0.0.1",
		Port:    port,
		AuthDir: filepath.Join(tempDir, "auths"),
	}
	cfg.Home.Enabled = true
	cfg.Codex.TurnTicket.Models = []string{"gpt-5.5"}

	service, errBuild := NewBuilder().
		WithConfig(cfg).
		WithConfigPath(filepath.Join(tempDir, "config.yaml")).
		Build()
	if errBuild != nil {
		t.Fatalf("Build() error = %v", errBuild)
	}

	runCtx, cancelRun := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		_ = service.Run(runCtx)
	}()
	defer func() {
		cancelRun()
		select {
		case <-runDone:
		case <-time.After(30 * time.Second):
			t.Errorf("Run did not return after cancellation")
		}
	}()

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if helps.CurrentCodexTurnTickets() != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("Home mode never installed the process-wide turn-ticket wiring")
}
