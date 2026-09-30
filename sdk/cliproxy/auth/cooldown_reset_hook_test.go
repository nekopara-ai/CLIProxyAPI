package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCooldownResetHookOnlyManualActions(t *testing.T) {
	m := NewManager(nil, nil, nil)
	a, err := m.Register(context.Background(), &Auth{ID: "reset-test", Provider: "codex", Status: StatusActive})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	m.SetCooldownResetHook(func(a *Auth) error {
		calls++
		if _, ok := m.GetByID(a.ID); !ok {
			t.Fatal("callback ran under manager lock or before installation")
		}
		a.Disabled = !a.Disabled
		return nil
	})
	// Ordinary edits and refreshes must not clear quota waits.
	a.ProxyURL = "socks5://synthetic:1080"
	a, err = m.Update(context.Background(), a)
	if err != nil || calls != 0 {
		t.Fatalf("ordinary update reset: calls=%d err=%v", calls, err)
	}
	for _, disabled := range []bool{true, false} {
		a.Disabled = disabled
		if disabled {
			a.Status = StatusDisabled
		} else {
			a.Status = StatusActive
		}
		a.Unavailable = true
		a.NextRetryAfter = time.Now().Add(time.Hour)
		a.ModelStates = map[string]*ModelState{"gpt-6-sol": {Unavailable: true, NextRetryAfter: time.Now().Add(time.Hour)}}
		a, err = m.Update(context.Background(), a)
		if err != nil || a.Unavailable || !a.NextRetryAfter.IsZero() || a.ModelStates["gpt-6-sol"].Unavailable {
			t.Fatalf("transition didn't clear business state: %+v %v", a, err)
		}
	}
	if calls != 2 {
		t.Fatalf("toggle calls=%d", calls)
	}
	a.RequestCooldownReset()
	a, err = m.Update(context.Background(), a)
	if err != nil || calls != 3 {
		t.Fatalf("already-enabled command did not force reset: calls=%d err=%v", calls, err)
	}
	if a.manualCooldownReset {
		t.Fatal("manual intent leaked into watcher snapshots")
	}
	if _, err = m.Update(context.Background(), a.Clone()); err != nil || calls != 3 {
		t.Fatal("watcher replay repeated forced check")
	}
	if _, _, err = m.ResetQuota(context.Background(), a.ID); err != nil || calls != 4 {
		t.Fatalf("quota reset didn't notify: %d %v", calls, err)
	}
	m.SetCooldownResetHook(nil)
	if _, _, err = m.ResetQuota(context.Background(), a.ID); err != nil || calls != 4 {
		t.Fatal("listener not removed")
	}
}

func TestCooldownResetHookReportsPersistenceFailure(t *testing.T) {
	m := NewManager(nil, nil, nil)
	a, err := m.Register(context.Background(), &Auth{ID: "reset-error", Provider: "codex"})
	if err != nil {
		t.Fatal(err)
	}
	want := errors.New("synthetic reset storage failure")
	m.SetCooldownResetHook(func(*Auth) error { return want })
	a.Disabled = true
	if _, err = m.Update(context.Background(), a); !errors.Is(err, want) {
		t.Fatalf("toggle concealed reset failure: %v", err)
	}
	if _, _, err = m.ResetQuota(context.Background(), a.ID); !errors.Is(err, want) {
		t.Fatalf("quota reset concealed reset failure: %v", err)
	}
}
