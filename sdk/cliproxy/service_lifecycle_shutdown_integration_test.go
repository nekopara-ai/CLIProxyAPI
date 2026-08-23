//go:build integration

package cliproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/api"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func TestRunCreatesShutdownDeadlineWhenRunExits(t *testing.T) {
	listener, errListen := net.Listen("tcp4", "127.0.0.1:0")
	if errListen != nil {
		t.Fatalf("reserve loopback port: %v", errListen)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if errClose := listener.Close(); errClose != nil {
		t.Fatalf("release reserved loopback port: %v", errClose)
	}

	handlerStarted := make(chan struct{})
	releaseHandler := make(chan struct{})
	var handlerStartedOnce sync.Once
	var releaseHandlerOnce sync.Once
	release := func() {
		releaseHandlerOnce.Do(func() { close(releaseHandler) })
	}

	tempDir := t.TempDir()
	cfg := &config.Config{
		Host:           "127.0.0.1",
		Port:           port,
		AuthDir:        filepath.Join(tempDir, "auths"),
		CommercialMode: true,
	}
	service, errBuild := NewBuilder().
		WithConfig(cfg).
		WithConfigPath(filepath.Join(tempDir, "config.yaml")).
		WithWatcherFactory(func(string, string, func(*config.Config)) (*WatcherWrapper, error) {
			return &WatcherWrapper{}, nil
		}).
		WithServerOptions(api.WithEngineConfigurator(func(engine *gin.Engine) {
			engine.GET("/__integration/ready", func(c *gin.Context) {
				c.Status(http.StatusNoContent)
			})
			engine.GET("/__integration/block", func(c *gin.Context) {
				handlerStartedOnce.Do(func() { close(handlerStarted) })
				<-releaseHandler
				c.Status(http.StatusNoContent)
			})
		})).
		Build()
	if errBuild != nil {
		t.Fatalf("build service: %v", errBuild)
	}

	runCtx, cancelRun := context.WithCancel(t.Context())
	runFinished := make(chan struct{})
	var runErr error
	go func() {
		runErr = service.Run(runCtx)
		close(runFinished)
	}()
	t.Cleanup(func() {
		release()
		cancelRun()
		select {
		case <-runFinished:
		case <-time.After(5 * time.Second):
			t.Errorf("service Run did not finish during cleanup")
		}
	})

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	readinessClient := &http.Client{Timeout: 500 * time.Millisecond}
	t.Cleanup(readinessClient.CloseIdleConnections)
	readinessDeadline := time.Now().Add(5 * time.Second)
	for {
		resp, errGet := readinessClient.Get(baseURL + "/__integration/ready")
		if errGet == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusNoContent {
				break
			}
		}
		select {
		case <-runFinished:
			t.Fatalf("service Run exited before readiness: %v", runErr)
		default:
		}
		if time.Now().After(readinessDeadline) {
			t.Fatalf("service did not become ready before deadline; last error: %v", errGet)
		}
		time.Sleep(25 * time.Millisecond)
	}

	// The original implementation created its 30-second shutdown context when
	// Run started. Staying alive beyond that deadline reproduces the stale-context
	// condition without changing the production timeout or using a fake clock.
	time.Sleep(31*time.Second + 250*time.Millisecond)
	select {
	case <-runFinished:
		t.Fatalf("service Run exited before shutdown test: %v", runErr)
	default:
	}

	requestClient := &http.Client{Timeout: 10 * time.Second}
	t.Cleanup(requestClient.CloseIdleConnections)
	requestFinished := make(chan struct{})
	var requestErr error
	go func() {
		defer close(requestFinished)
		resp, errGet := requestClient.Get(baseURL + "/__integration/block")
		if errGet != nil {
			requestErr = errGet
			return
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != http.StatusNoContent {
			requestErr = fmt.Errorf("blocking request status = %d, want %d", resp.StatusCode, http.StatusNoContent)
		}
	}()

	select {
	case <-handlerStarted:
	case <-requestFinished:
		t.Fatalf("blocking request finished before entering handler: %v", requestErr)
	case <-time.After(3 * time.Second):
		t.Fatal("blocking handler did not start")
	}

	cancelRun()
	select {
	case <-runFinished:
		t.Fatalf("service Run returned before active handler drained: %v", runErr)
	case <-time.After(time.Second):
	}

	release()
	select {
	case <-requestFinished:
		if requestErr != nil {
			t.Fatalf("blocking request failed while draining: %v", requestErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("blocking request did not finish after release")
	}

	select {
	case <-runFinished:
		if !errors.Is(runErr, context.Canceled) {
			t.Fatalf("service Run error = %v, want context canceled", runErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("service Run did not finish after active handler drained")
	}
}
