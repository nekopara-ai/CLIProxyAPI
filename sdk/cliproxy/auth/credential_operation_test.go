package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func waitOperation(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("operation did not reach expected lifecycle state")
	}
}

func disableCredential(t *testing.T, m *Manager, a *Auth) *Auth {
	t.Helper()
	off := a.Clone()
	off.Disabled, off.Status = true, StatusDisabled
	saved, err := m.Update(context.Background(), off)
	if err != nil {
		t.Fatal(err)
	}
	return saved
}

func TestCredentialOperationsDisableCancelsAllAndFencesStaleSelections(t *testing.T) {
	m := NewManager(nil, nil, nil)
	a, _ := m.Register(context.Background(), &Auth{ID: "a", Provider: "test"})
	b, _ := m.Register(context.Background(), &Auth{ID: "b", Provider: "test"})
	var contexts []context.Context
	for i := 0; i < 20; i++ {
		ctx, finish, err := m.BeginCredentialOperation(context.Background(), a)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(finish)
		contexts = append(contexts, ctx)
	}
	ctxB, finishB, _ := m.BeginCredentialOperation(context.Background(), b)
	defer finishB()
	off := disableCredential(t, m, a)
	for _, ctx := range contexts {
		if ctx.Err() == nil {
			t.Fatal("one of concurrent operations was not canceled")
		}
	}
	if ctxB.Err() != nil {
		t.Fatal("sibling credential was canceled")
	}
	if _, _, err := m.BeginCredentialOperation(context.Background(), off); err == nil {
		t.Fatal("OFF accepted new operation")
	}
	on := off.Clone()
	on.Disabled, on.Status = false, StatusActive
	on, _ = m.Update(context.Background(), on)
	if _, _, err := m.BeginCredentialOperation(context.Background(), a); err == nil {
		t.Fatal("old selection revived after ON")
	}
	_, finish, err := m.BeginCredentialOperation(context.Background(), on)
	if err != nil {
		t.Fatal(err)
	}
	finish()
	finish()
	m.Remove(context.Background(), on.ID)
	if _, _, err := m.BeginCredentialOperation(context.Background(), on); err == nil {
		t.Fatal("removed selection accepted")
	}
	fresh, _ := m.Register(context.Background(), &Auth{ID: "a", Provider: "test"})
	_, finishFresh, err := m.BeginCredentialOperation(context.Background(), fresh)
	if err != nil {
		t.Fatal(err)
	}
	finishFresh()
}

type lifecycleExecutor struct {
	mockOAuthErrorExecutor
	entered  chan struct{}
	canceled chan struct{}
	release  chan struct{}
	chunks   chan cliproxyexecutor.StreamChunk
	prepare  bool
}

func (e *lifecycleExecutor) block(ctx context.Context) {
	close(e.entered)
	<-ctx.Done()
	close(e.canceled)
	if e.release != nil {
		<-e.release
	}
}
func (e *lifecycleExecutor) Execute(ctx context.Context, _ *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.block(ctx)
	return cliproxyexecutor.Response{}, nil // Late success must be ignored.
}
func (e *lifecycleExecutor) CountTokens(ctx context.Context, a *Auth, r cliproxyexecutor.Request, o cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return e.Execute(ctx, a, r, o)
}
func (e *lifecycleExecutor) Refresh(ctx context.Context, a *Auth) (*Auth, error) {
	e.block(ctx)
	a.Metadata["access_token"] = "late-token"
	return a, nil
}
func (e *lifecycleExecutor) ShouldPrepareRequestAuth(*Auth) bool { return e.prepare }
func (e *lifecycleExecutor) PrepareRequestAuth(ctx context.Context, a *Auth) (*Auth, error) {
	return e.Refresh(ctx, a)
}
func (e *lifecycleExecutor) ExecuteStream(ctx context.Context, _ *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	e.chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("data: hello\n\n")}
	close(e.entered)
	go func() { <-ctx.Done(); close(e.canceled) }()
	return &cliproxyexecutor.StreamResult{Chunks: e.chunks}, nil
}

func TestManualDisableCancelsNativeWorkAndRejectsLateSuccess(t *testing.T) {
	for _, kind := range []string{"execute", "count", "refresh", "prepare"} {
		t.Run(kind, func(t *testing.T) {
			m := NewManager(nil, nil, nil)
			e := &lifecycleExecutor{mockOAuthErrorExecutor: mockOAuthErrorExecutor{id: "test"}, entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{}), prepare: kind == "prepare"}
			m.RegisterExecutor(e)
			a, err := m.Register(context.Background(), &Auth{ID: "a", Provider: "test", Metadata: map[string]any{"access_token": "old-token"}})
			if err != nil {
				t.Fatal(err)
			}
			registry.GetGlobalRegistry().RegisterClient(a.ID, a.Provider, []*registry.ModelInfo{{ID: "model"}})
			t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })
			done := make(chan struct{})
			var workErr error
			go func() {
				defer close(done)
				switch kind {
				case "refresh":
					_, workErr = m.refreshAuthForRequest(context.Background(), a.ID, "")
				case "prepare":
					_, workErr = m.PrepareRequestAuth(context.Background(), e, a)
				case "count":
					_, workErr = m.ExecuteCount(context.Background(), []string{"test"}, cliproxyexecutor.Request{Model: "model"}, cliproxyexecutor.Options{})
				case "execute":
					_, workErr = m.Execute(context.Background(), []string{"test"}, cliproxyexecutor.Request{Model: "model"}, cliproxyexecutor.Options{})
				}
			}()
			waitOperation(t, e.entered)
			off := disableCredential(t, m, a)
			waitOperation(t, e.canceled)
			on := off.Clone()
			on.Disabled, on.Status = false, StatusActive
			if _, err := m.Update(context.Background(), on); err != nil {
				t.Fatal(err)
			}
			close(e.release)
			waitOperation(t, done)
			if !errors.Is(workErr, context.Canceled) {
				t.Fatalf("late work returned %v", workErr)
			}
			current, _ := m.GetByID(a.ID)
			if current.Metadata["access_token"] != "old-token" || !current.NextRefreshAfter.IsZero() || current.Success != 0 || current.Failed != 0 {
				t.Fatal("late work rewrote credentials or schedule")
			}
		})
	}
}

func TestManualDisableClosesLiveStreamWithoutWaitingForAnotherChunk(t *testing.T) {
	m := NewManager(nil, nil, nil)
	e := &lifecycleExecutor{entered: make(chan struct{}), canceled: make(chan struct{}), chunks: make(chan cliproxyexecutor.StreamChunk, 1)}
	a, _ := m.Register(context.Background(), &Auth{ID: "a", Provider: "test"})
	stream, err := m.executeStreamWithModelPool(context.Background(), e, a, "test", cliproxyexecutor.Request{}, cliproxyexecutor.Options{}, "model", "", []string{"model"}, false, OAuthModelAliasResult{}, nil, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if chunk := <-stream.Chunks; len(chunk.Payload) == 0 {
		t.Fatal("missing first chunk")
	}
	disableCredential(t, m, a)
	waitOperation(t, e.canceled)
	select {
	case _, ok := <-stream.Chunks:
		if ok {
			t.Fatal("disabled stream still forwarding")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("hung upstream kept output open")
	}
	close(e.chunks)
	current, _ := m.GetByID(a.ID)
	if current.Success != 0 || current.Failed != 0 {
		t.Fatal("canceled stream recorded a result")
	}
}

var _ ProviderExecutor = (*lifecycleExecutor)(nil)
var _ RequestAuthPreparer = (*lifecycleExecutor)(nil)

func TestManualDisableInvalidatesQueuedRefreshAfterReenable(t *testing.T) {
	m := NewManager(nil, nil, nil)
	e := &mockOAuthErrorExecutor{id: "test"}
	m.RegisterExecutor(e)
	a, _ := m.Register(context.Background(), &Auth{ID: "queued", Provider: "test"})
	l := newAuthAutoRefreshLoop(m, time.Second, 1)
	job := m.markRefreshPending(l, a.ID, a.RegistrationEpoch, time.Now())
	if job == nil {
		t.Fatal("refresh was not queued")
	}
	l.jobs <- job
	off := disableCredential(t, m, a)
	on := off.Clone()
	on.Disabled, on.Status = false, StatusActive
	if _, err := m.Update(context.Background(), on); err != nil {
		t.Fatal(err)
	}
	l.runJob(context.Background(), <-l.jobs)
	if e.refreshCalls.Load() != 0 {
		t.Fatal("canceled queued refresh revived after ON")
	}
}
