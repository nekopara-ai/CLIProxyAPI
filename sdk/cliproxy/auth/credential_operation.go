package auth

import (
	"context"
	"errors"
	"io"
	"sync"
)

type credentialOperation struct{ marker byte }

type credentialVersion struct{ epoch, generation uint64 }

type credentialOperationKey struct{}

var errCredentialStopped = errors.New("credential scheduling stopped")

func (m *Manager) credentialStoppedLocked(a, current *Auth) bool {
	stop := m.credentialStopGeneration[a.ID]
	return current.Disabled || current.Status == StatusDisabled ||
		a.RegistrationEpoch < current.RegistrationEpoch ||
		a.RegistrationEpoch == stop.epoch && a.Generation < stop.generation
}

// BeginCredentialOperation binds provider work to the credential's enabled
// lifecycle. Disable cancels existing work and rejects stale selections.
func (m *Manager) BeginCredentialOperation(ctx context.Context, a *Auth) (context.Context, func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if m == nil || a == nil {
		return ctx, func() {}, nil
	}
	m.mu.Lock()
	current := m.auths[a.ID]
	if current == nil {
		m.mu.Unlock()
		if a.RegistrationEpoch != 0 {
			return ctx, func() {}, &Error{Code: "auth_not_found", Message: "credential no longer registered"}
		}
		// Home ephemeral credentials have their own selection lifecycle.
		return ctx, func() {}, nil
	}
	if m.credentialStoppedLocked(a, current) {
		m.mu.Unlock()
		return ctx, func() {}, &Error{Code: "auth_disabled", Message: "credential scheduling is disabled"}
	}
	operation := &credentialOperation{}
	workCtx, cancelCause := context.WithCancelCause(ctx)
	cancel := func() { cancelCause(errCredentialStopped) }
	workCtx = context.WithValue(workCtx, credentialOperationKey{}, &Auth{ID: a.ID, Generation: a.Generation, RegistrationEpoch: a.RegistrationEpoch})
	if workCtx.Err() != nil {
		m.mu.Unlock()
		cancel()
		return workCtx, func() {}, workCtx.Err()
	}
	if m.credentialOperations == nil {
		m.credentialOperations = make(map[string]map[*credentialOperation]context.CancelFunc)
	}
	if m.credentialOperations[a.ID] == nil {
		m.credentialOperations[a.ID] = make(map[*credentialOperation]context.CancelFunc)
	}
	m.credentialOperations[a.ID][operation] = cancel
	m.mu.Unlock()
	var once sync.Once
	finish := func() {
		once.Do(func() {
			cancelCause(context.Canceled)
			m.mu.Lock()
			delete(m.credentialOperations[a.ID], operation)
			if len(m.credentialOperations[a.ID]) == 0 {
				delete(m.credentialOperations, a.ID)
			}
			m.mu.Unlock()
		})
	}
	return workCtx, finish, nil
}

func (m *Manager) stopCredentialOperationsLocked(a *Auth) {
	if m.credentialStopGeneration == nil {
		m.credentialStopGeneration = make(map[string]credentialVersion)
	}
	m.credentialStopGeneration[a.ID] = credentialVersion{a.RegistrationEpoch, a.Generation}
	for _, cancel := range m.credentialOperations[a.ID] {
		cancel()
	}
}

type credentialResponseBody struct {
	io.ReadCloser
	finish func()
}

func (b *credentialResponseBody) Close() error {
	err := b.ReadCloser.Close()
	b.finish()
	return err
}
