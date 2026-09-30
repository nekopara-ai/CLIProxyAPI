package fingerprint

import (
	"context"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func assertStopped(t *testing.T, s Snapshot) {
	t.Helper()
	if !s.Suspended || s.Running || s.Progress != nil || !s.NextRunAt.IsZero() || len(s.CurrentResults) != 0 {
		t.Fatalf("credential still scheduled: %+v", s)
	}
	for model, ms := range s.ModelStates {
		if ms != nil && (!ms.NextRunAt.IsZero() || ms.Wait != nil) {
			t.Fatalf("model %s still scheduled: %+v", model, ms)
		}
	}
}

func TestManualDisableCancelsActiveProbeAndResumesOnlyFreshWork(t *testing.T) {
	h := setup(t)
	h.cfg.Fingerprint.Models = []string{"gpt-6-sol"}
	manager := coreauth.NewManager(nil, nil, nil)
	var err error
	h.a, err = manager.Register(context.Background(), h.a)
	if err != nil {
		t.Fatal(err)
	}
	h.m.auths = manager.List
	manager.SetCooldownResetHook(h.m.ResetCooldown)
	oldProbe := h.m.probe
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	h.m.probe = func(ctx context.Context, _ *coreauth.Auth, _, _ string) (string, error) {
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-release // Simulate a provider returning a late 429 after cancellation.
		return "", quotaFailure{delay: 96 * time.Hour, credential: true}
	}
	h.m.tick(context.Background())
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("probe did not start")
	}
	off := h.a.Clone()
	off.Disabled, off.Status = true, coreauth.StatusDisabled
	off, err = manager.Update(context.Background(), off)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("probe was not canceled")
	}
	assertStopped(t, h.m.Snapshot(off))
	close(release)
	h.m.wg.Wait()
	s := h.m.Snapshot(off)
	assertStopped(t, s)
	if len(s.History) != 0 || s.RequestsToday != 1 {
		t.Fatalf("late probe committed: %+v", s)
	}
	for i := 0; i < 3; i++ {
		h.cycle()
	}
	assertStopped(t, h.m.Snapshot(off))
	on := off.Clone()
	on.Disabled, on.Status = false, coreauth.StatusActive
	h.a, err = manager.Update(context.Background(), on)
	if err != nil {
		t.Fatal(err)
	}
	h.m.probe = oldProbe
	h.cycle()
	if h.calls != 3 || h.m.Snapshot(h.a).ModelStates["gpt-6-sol"].Result.Status != "match" {
		t.Fatal("manual ON did not run a fresh complete check")
	}
}

func TestManualDisableClearsFuturePlansDurablyEvenWithMasterOff(t *testing.T) {
	for _, statusOnly := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled-flag", true: "disabled-status"}[statusOnly], func(t *testing.T) {
			h := setup(t)
			h.cycle()
			n := h.calls
			h.a.Generation = 5
			h.a.Disabled = !statusOnly
			h.a.Status = coreauth.StatusDisabled
			h.cfg.Fingerprint.Enabled = ptr(false)
			// Reconcile a legacy future plan without a management callback.
			h.cycle()
			assertStopped(t, h.m.Snapshot(h.a))
			if err := h.m.ResetCooldown(h.a); err != nil {
				t.Fatal(err)
			}
			assertStopped(t, h.m.Snapshot(h.a))
			restarted := New(h.m.cfg, h.m.auths, h.m.probe)
			assertStopped(t, restarted.Snapshot(h.a))
			if h.calls != n {
				t.Fatal("disabled credential consumed probe quota")
			}
			staleOn := h.a.Clone()
			staleOn.Generation, staleOn.Disabled, staleOn.Status = 4, false, coreauth.StatusActive
			if err := h.m.ResetCooldown(staleOn); err != nil {
				t.Fatal(err)
			}
			assertStopped(t, h.m.Snapshot(h.a))
		})
	}
}
