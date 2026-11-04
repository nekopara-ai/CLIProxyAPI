package auth

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Embed the executor stub for the unused request methods.
type disabledRefreshOutcomeExecutor struct {
	mockOAuthErrorExecutor
	extendExpiry bool
}

func (e *disabledRefreshOutcomeExecutor) Refresh(_ context.Context, a *Auth) (*Auth, error) {
	e.refreshCalls.Add(1)
	if e.extendExpiry {
		// A provider can renew validity without rotating the credential strings.
		a.Metadata["expires_at"] = time.Now().Add(24 * time.Hour).Format(time.RFC3339)
	}
	return a, nil
}

func TestDisabledRefreshOutcomeJobCycle(t *testing.T) {
	for _, disabledFlag := range []bool{true, false} {
		for _, renew := range []bool{false, true} {
			name := "status-disabled"
			if disabledFlag {
				name = "disabled-flag"
			}
			if renew {
				name += "/renewed"
			} else {
				name += "/no-op"
			}
			t.Run(name, func(t *testing.T) {
				ctx := context.Background()
				m := NewManager(nil, &RoundRobinSelector{}, nil)
				e := &disabledRefreshOutcomeExecutor{mockOAuthErrorExecutor: mockOAuthErrorExecutor{id: "disabled-outcome"}, extendExpiry: renew}
				m.RegisterExecutor(e)
				setRefreshLeadFactory(t, e.id, func() *time.Duration { d := time.Minute; return &d })
				oldRefresh := time.Now().Add(-48 * time.Hour)
				a := &Auth{ID: name, Provider: e.id, Disabled: disabledFlag, Status: StatusDisabled,
					LastRefreshedAt: oldRefresh, RefreshFailures: 3,
					Metadata: map[string]any{"access_token": "unchanged", "expires_at": time.Now().Add(-time.Hour).Format(time.RFC3339)}}
				if disabledFlag {
					a.Status = StatusActive
				}
				registered, err := m.Register(ctx, a)
				if err != nil {
					t.Fatal(err)
				}
				now := time.Now()
				// This fork treats manual disable as a stop for token refresh too.
				if _, ok := nextRefreshCheckAt(now, registered, time.Minute); ok {
					t.Fatal("disabled auth entered proactive refresh schedule")
				}
				if job := m.markRefreshPending(nil, a.ID, registered.RegistrationEpoch, now); job != nil {
					t.Fatal("disabled auth queued a refresh job")
				}
				if _, err := m.refreshAuthForRequestAtEpoch(ctx, a.ID, "", registered.RegistrationEpoch); err == nil {
					t.Fatal("disabled request refresh was accepted")
				}
				current, _ := m.GetByID(a.ID)
				if e.refreshCalls.Load() != 0 || !current.LastRefreshedAt.Equal(oldRefresh) || current.RefreshFailures != 3 {
					t.Fatal("disabled credential was refreshed or its outcome changed")
				}
				if current.Disabled != registered.Disabled || current.Status != registered.Status {
					t.Fatal("manual disabled state changed")
				}
			})
		}
	}
}

func TestDisabledRefreshOutcomeFileSnapshotPreserved(t *testing.T) {
	ctx := context.Background()
	m := NewManager(nil, &RoundRobinSelector{}, nil)
	now := time.Now()
	a := &Auth{ID: "disabled-snapshot", Provider: "codex", Disabled: true, Status: StatusDisabled,
		LastRefreshedAt: now.Add(-time.Hour), NextRefreshAfter: now.Add(time.Hour), RefreshFailures: 4,
		Metadata: map[string]any{"access_token": "unchanged"}}
	existing, err := m.Register(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "auth.json")
	data := []byte(`{"access_token":"unchanged"}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	snapshot := existing.Clone()
	snapshot.LastRefreshedAt = time.Time{}
	snapshot.NextRefreshAfter = time.Time{}
	snapshot.RefreshFailures = 0
	snapshot.BindFileSnapshot(path, data)
	updated, err := m.Update(ctx, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !updated.LastRefreshedAt.Equal(existing.LastRefreshedAt) || !updated.NextRefreshAfter.Equal(existing.NextRefreshAfter) || updated.RefreshFailures != existing.RefreshFailures {
		t.Fatalf("file snapshot replaced runtime refresh state: %+v", updated)
	}
}
