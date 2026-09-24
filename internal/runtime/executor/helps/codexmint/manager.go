package codexmint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Gateway                                                      string
	TicketLength                                                 int
	TicketTTL, PairTTL, Margin, RefreshBefore                    time.Duration
	AttemptTimeout, TotalTimeout, FailureCooldown, RejectBackoff time.Duration
	MaxAttempts, Capacity                                        int
}

func (c Config) Normalized() Config {
	c.Gateway = NormalizeGateway(c.Gateway)
	if c.TicketTTL <= 0 {
		c.TicketTTL = 240 * time.Second
	}
	if c.PairTTL <= 0 {
		c.PairTTL = 3900 * time.Second
	}
	if c.AttemptTimeout <= 0 {
		c.AttemptTimeout = 25 * time.Second
	}
	if c.TotalTimeout <= 0 {
		c.TotalTimeout = 75 * time.Second
	}
	if c.FailureCooldown <= 0 {
		c.FailureCooldown = 30 * time.Second
	}
	if c.RejectBackoff <= 0 {
		c.RejectBackoff = 600 * time.Second
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 24
	}
	c.MaxAttempts = min(c.MaxAttempts, 128)
	if c.Capacity <= 0 {
		c.Capacity = 256
	}
	if c.Margin < 0 {
		c.Margin = 0
	}
	if c.RefreshBefore < c.Margin {
		c.RefreshBefore = c.Margin
	}
	c.RefreshBefore = min(c.RefreshBefore, c.TicketTTL/2, c.PairTTL/2)
	return c
}

type Ticket struct {
	State, Model        string
	IssuedAt, ExpiresAt time.Time
}

func (t Ticket) valid(now time.Time, c Config, margin time.Duration) bool {
	return t.State != "" && len(t.State) <= ScanLimit && strings.IndexFunc(t.State, func(r rune) bool { return r < 0x21 || r > 0x7e }) < 0 && (c.TicketLength == 0 || len(t.State) == c.TicketLength) &&
		earlier(t.ExpiresAt, t.IssuedAt.Add(c.TicketTTL)).After(now.Add(margin))
}

type Bundle struct {
	Ticket Ticket
	Pair   Pair
}
type Attempt struct {
	Header                   http.Header
	State, Model, ResponseID string
	Source                   string
	Status                   int
	Terminal                 bool
	Failure                  string
}
type Request struct {
	Model string
	Pair  *Pair
}
type Probe func(context.Context, Request) (Attempt, error)

// A scope is an opaque digest of credential, workspace, upstream, transport,
// egress and identity/policy. Different models in one scope share only the pair.
func Scope(parts ...string) string {
	sum := sha256.New()
	for _, part := range parts {
		sum.Write([]byte(strconv.Itoa(len(part))))
		sum.Write([]byte(":"))
		sum.Write([]byte(part))
	}
	return hex.EncodeToString(sum.Sum(nil))
}

type entry struct {
	pair    Pair
	tickets map[string]Ticket
	blocked map[string]time.Time
	flight  chan struct{}
	epoch   uint64
	touched uint64
	next    time.Time
	last    Snapshot
}

type Snapshot struct {
	Ready           bool      `json:"ready"`
	Gateway         string    `json:"gateway,omitempty"`
	Model           string    `json:"model,omitempty"`
	TicketLength    int       `json:"ticket_length,omitempty"`
	TicketExpiresAt time.Time `json:"ticket_expires_at,omitempty"`
	PairExpiresAt   time.Time `json:"pair_expires_at,omitempty"`
	ObservedAt      time.Time `json:"observed_at,omitempty"`
	NextAttemptAt   time.Time `json:"next_attempt_at,omitempty"`
	Attempts        int       `json:"attempts"`
	Status          int       `json:"status,omitempty"`
	Reason          string    `json:"reason,omitempty"`
	InFlight        bool      `json:"in_flight"`
}

type Manager struct {
	mu       sync.Mutex
	scopes   map[string]*entry
	sequence uint64
	now      func() time.Time
}

func New(now func() time.Time) *Manager {
	if now == nil {
		now = time.Now
	}
	return &Manager{scopes: make(map[string]*entry), now: now}
}

func (m *Manager) getEntry(scope string, c Config) *entry {
	e := m.scopes[scope]
	if e == nil {
		if len(m.scopes) >= c.Capacity {
			oldest := ""
			var seq uint64
			for key, v := range m.scopes {
				if v.flight == nil && (oldest == "" || v.touched < seq) {
					oldest = key
					seq = v.touched
				}
			}
			if oldest == "" {
				return nil
			}
			delete(m.scopes, oldest)
		}
		e = &entry{tickets: make(map[string]Ticket), blocked: make(map[string]time.Time)}
		m.scopes[scope] = e
	}
	m.sequence++
	e.touched = m.sequence
	return e
}
func (m *Manager) Get(scope, model string, c Config) (Bundle, bool) {
	c = c.Normalized()
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.scopes[scope]
	if e == nil {
		return Bundle{}, false
	}
	t, ok := e.tickets[model]
	now := m.now()
	if !ok || t.Model != model || !t.valid(now, c, c.Margin) || !e.pair.valid(now, c, c.Margin) {
		return Bundle{}, false
	}
	t.ExpiresAt = earlier(t.ExpiresAt, t.IssuedAt.Add(c.TicketTTL))
	p := e.pair
	p.ExpiresAt = earlier(p.ExpiresAt, p.CapturedAt.Add(c.PairTTL))
	m.sequence++
	e.touched = m.sequence
	return Bundle{Ticket: t, Pair: p}, true
}
func (m *Manager) Snapshot(scope, model string, c Config) Snapshot {
	c = c.Normalized()
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.scopes[scope]
	if e == nil {
		return Snapshot{Model: model, Reason: "unclassified"}
	}
	s := e.last
	s.InFlight = e.flight != nil
	s.NextAttemptAt = e.next
	s.Model = model
	t := e.tickets[model]
	s.TicketLength = len(t.State)
	s.TicketExpiresAt = t.ExpiresAt
	s.PairExpiresAt = e.pair.ExpiresAt
	s.Gateway = e.pair.Gateway
	s.Ready = t.Model == model && t.valid(m.now(), c, c.Margin) && e.pair.valid(m.now(), c, c.Margin)
	return s
}

// Reject invalidates only the material actually submitted by an injected request.
// An old response cannot evict a newer ticket or a rotated pair.
func (m *Manager) Reject(scope, model, state, cookie string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.scopes[scope]
	if e == nil || state == "" || e.tickets[model].State != state || e.pair.Cookie() != cookie {
		return false
	}
	delete(e.tickets, model)
	e.pair = Pair{}
	e.epoch++
	e.next = time.Time{}
	e.last.Reason = "injected_route_rejected"
	return true
}

// Refresh performs a bounded, single-flight acquisition for all requested models.
// Probe owns its connection; this engine never replays a business request and never
// sends a cached turn-state when asking upstream to mint a new ticket.
func (m *Manager) Refresh(ctx context.Context, scope string, models []string, endpoint string, c Config, probe Probe) error {
	if ctx == nil {
		ctx = context.Background()
	}
	c = c.Normalized()
	if scope == "" || probe == nil || len(models) == 0 {
		return errors.New("invalid_mint_request")
	}
	unique := make([]string, 0, len(models))
	seen := map[string]bool{}
	for _, model := range models {
		if model != "" && !seen[model] {
			seen[model] = true
			unique = append(unique, model)
		}
	}
	if len(unique) == 0 {
		return errors.New("invalid_mint_request")
	}
	models = unique
	for {
		m.mu.Lock()
		e := m.getEntry(scope, c)
		if e == nil {
			m.mu.Unlock()
			return errors.New("mint_capacity")
		}
		if ch := e.flight; ch != nil {
			m.mu.Unlock()
			select {
			case <-ch:
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if m.now().Before(e.next) {
			m.mu.Unlock()
			return errors.New("mint_backoff")
		}
		if allFresh(e, models, c, m.now()) {
			m.mu.Unlock()
			return nil
		}
		ch := make(chan struct{})
		e.flight = ch
		epoch := e.epoch
		m.mu.Unlock()
		return m.refresh(ctx, e, epoch, models, endpoint, c, probe)
	}
}
func allFresh(e *entry, models []string, c Config, now time.Time) bool {
	if !e.pair.valid(now, c, c.RefreshBefore) {
		return false
	}
	for _, model := range models {
		if !e.tickets[model].valid(now, c, c.RefreshBefore) {
			return false
		}
	}
	return true
}
func (m *Manager) refresh(parent context.Context, e *entry, epoch uint64, models []string, endpoint string, c Config, probe Probe) (err error) {
	ctx, cancel := context.WithTimeout(parent, c.TotalTimeout)
	defer cancel()
	attempts := 0
	reason := "mint_exhausted"
	status := 0
	next := time.Time{}
	defer func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if e.epoch == epoch {
			if err != nil && !errors.Is(err, context.Canceled) && next.IsZero() {
				next = m.now().Add(c.FailureCooldown)
			}
			e.next = next
			e.last = Snapshot{Attempts: attempts, ObservedAt: m.now(), Reason: reason, Status: status}
		}
		ch := e.flight
		e.flight = nil
		close(ch)
	}()
	cursor := 0
	for attempts < c.MaxAttempts {
		if err = ctx.Err(); err != nil {
			reason = "mint_canceled"
			return err
		}
		m.mu.Lock()
		if e.epoch != epoch {
			m.mu.Unlock()
			reason = "stale_observation"
			return errors.New(reason)
		}
		now := m.now()
		if allFresh(e, models, c, now) {
			m.mu.Unlock()
			reason = "ready"
			return nil
		}
		model := ""
		// Round-robin prevents an unavailable model from spending the entire budget.
		for offset := 0; offset < len(models); offset++ {
			idx := (cursor + offset) % len(models)
			candidate := models[idx]
			if now.Before(e.blocked[candidate]) {
				continue
			}
			if !e.tickets[candidate].valid(now, c, c.RefreshBefore) || !e.pair.valid(now, c, c.RefreshBefore) {
				model = candidate
				cursor = (idx + 1) % len(models)
				break
			}
		}
		if model == "" {
			m.mu.Unlock()
			reason = "models_backoff"
			return errors.New(reason)
		}
		var sent *Pair
		if e.pair.valid(now, c, c.RefreshBefore) {
			p := e.pair
			sent = &p
		}
		m.mu.Unlock()
		attemptCtx, stop := context.WithTimeout(ctx, c.AttemptTimeout)
		result, probeErr := probe(attemptCtx, Request{Model: model, Pair: sent})
		stop()
		attempts++
		status = result.Status
		if ctx.Err() != nil {
			reason = "mint_canceled"
			return ctx.Err()
		}
		m.mu.Lock()
		if e.epoch != epoch {
			m.mu.Unlock()
			reason = "stale_observation"
			return errors.New(reason)
		}
		now = m.now()
		if status == 401 || status == 403 || status == 429 {
			delay := c.RejectBackoff
			if value := result.Header.Get("Retry-After"); value != "" {
				if seconds, parseErr := strconv.ParseInt(value, 10, 32); parseErr == nil && seconds > 0 {
					delay = max(delay, time.Duration(seconds)*time.Second)
				} else if at, parseErr := http.ParseTime(value); parseErr == nil {
					delay = max(delay, at.Sub(now))
				}
			}
			next = now.Add(delay)
			m.mu.Unlock()
			reason = "upstream_rejected"
			return errors.New(reason)
		}
		if status == 400 || status == 404 || status == 422 || result.Terminal {
			e.blocked[model] = now.Add(c.RejectBackoff)
			m.mu.Unlock()
			reason = "model_rejected"
			continue
		}
		if probeErr != nil || result.Failure != "" || (status != 200 && status != 101) {
			m.mu.Unlock()
			reason = "probe_failed"
			continue
		}
		if result.ResponseID == "" || strings.TrimSpace(result.Model) == "" {
			m.mu.Unlock()
			reason = "missing_created"
			continue
		}
		pair, changed := ReadPair(result.Header, endpoint, now, c)
		if changed {
			pair.Source = result.Source
			e.pair = pair
		} else if sent != nil && sent.valid(now, c, c.Margin) {
			e.pair = *sent
		} else {
			e.pair = Pair{}
		}
		if !e.pair.valid(now, c, c.Margin) {
			m.mu.Unlock()
			reason = "gateway_or_pair_mismatch"
			continue
		}
		if result.Model != model {
			m.mu.Unlock()
			reason = "model_mismatch"
			continue
		}
		if result.State == "" || (c.TicketLength > 0 && len(result.State) != c.TicketLength) {
			m.mu.Unlock()
			reason = "ticket_length_mismatch"
			continue
		}
		issued := issuedAt(result.State, now)
		ticket := Ticket{State: result.State, Model: model, IssuedAt: issued, ExpiresAt: issued.Add(c.TicketTTL)}
		if !ticket.valid(now, c, c.Margin) {
			m.mu.Unlock()
			reason = "expired_ticket"
			continue
		}
		// Pair-only renewal must never overwrite a still-fresh model ticket.
		if !e.tickets[model].valid(now, c, c.RefreshBefore) {
			e.tickets[model] = ticket
		}
		ready := allFresh(e, models, c, now)
		m.mu.Unlock()
		if ready {
			reason = "ready"
			return nil
		}
	}
	return errors.New(reason)
}

// Inject replaces only turn-state and the two routing cookies, preserving all
// unrelated cookies and headers. Its caller has already selected the credential.
func Inject(h http.Header, b Bundle) {
	if h == nil {
		return
	}
	var keep []*http.Cookie
	for key, values := range h {
		if strings.EqualFold(key, "Cookie") {
			for _, value := range values {
				r := &http.Request{Header: http.Header{"Cookie": {value}}}
				for _, cookie := range r.Cookies() {
					if cookie.Name != "__cflb" && cookie.Name != "__oailb" {
						keep = append(keep, cookie)
					}
				}
			}
			delete(h, key)
		} else if strings.EqualFold(key, StateHeader) {
			delete(h, key)
		}
	}
	h.Set(StateHeader, b.Ticket.State)
	r := &http.Request{Header: h}
	for _, cookie := range keep {
		r.AddCookie(cookie)
	}
	r.AddCookie(&http.Cookie{Name: "__cflb", Value: b.Pair.CFLB})
	r.AddCookie(&http.Cookie{Name: "__oailb", Value: b.Pair.OAILB})
}

// Forget invalidates a scope and fences in-flight results from republishing it.
func (m *Manager) Forget(scope string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e := m.scopes[scope]; e != nil {
		e.epoch++
		delete(m.scopes, scope)
	}
}
