package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestUnauthorizedClassificationPreservesFiniteCooldowns(t *testing.T) {
	now := time.Now()
	for _, offset := range []time.Duration{-time.Minute, time.Minute} {
		auth := &Auth{
			Unavailable: true, Status: StatusError,
			LastError:      &Error{Code: "unauthorized", HTTPStatus: http.StatusUnauthorized},
			NextRetryAfter: now.Add(offset),
		}
		if hasUnauthorizedAuthFailure(auth) {
			t.Fatal("finite request cooldown classified as permanent refresh failure")
		}
		blocked, _, next := isAuthBlockedForModel(auth, "", now)
		if blocked != (offset > 0) || (blocked && !next.Equal(auth.NextRetryAfter)) {
			t.Fatalf("blocked=%v next=%v, want deadline %v", blocked, next, auth.NextRetryAfter)
		}
	}
}

func TestRejectedRefreshRemainsTerminalDuringCooldown(t *testing.T) {
	ctx := context.Background()
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(unauthorizedRefreshTestExecutor{
		schedulerProviderTestExecutor: schedulerProviderTestExecutor{provider: "codex"},
	})
	auth := &Auth{
		ID: "refresh-during-cooldown", Provider: "codex",
		Unavailable: true, Status: StatusError,
		NextRetryAfter: time.Now().Add(time.Hour),
	}
	if _, err := manager.Register(ctx, auth); err != nil {
		t.Fatal(err)
	}
	manager.refreshAuth(ctx, auth.ID)
	auth, _ = manager.GetByID(auth.ID)
	auth = auth.Clone()
	body, err := json.Marshal(CooldownStateRecord{LastFailureScope: auth.lastFailureScope, LastError: cloneError(auth.LastError)})
	if err != nil {
		t.Fatal(err)
	}
	var restored CooldownStateRecord
	if err := json.Unmarshal(body, &restored); err != nil {
		t.Fatal(err)
	}
	auth.LastError = restored.LastError
	auth.lastFailureScope = restored.LastFailureScope
	if !hasUnauthorizedAuthFailure(auth) {
		t.Fatal("rejected refresh lost permanent classification after clone/serialization")
	}
	if blocked, _, next := isAuthBlockedForModel(auth, "any-model", time.Now()); !blocked || !next.IsZero() {
		t.Fatal("rejected refresh incorrectly inherited a finite request cooldown")
	}
	auth.NextRefreshAfter = time.Now().Add(time.Minute)
	if hasUnauthorizedAuthFailure(auth) {
		t.Fatal("scheduled refresh with a still-valid token became terminal")
	}
}
