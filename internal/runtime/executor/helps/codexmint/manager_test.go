package codexmint

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const endpoint = "https://chatgpt.com/backend-api/codex/responses"

func testConfig() Config {
	return Config{Gateway: "unified-88", TicketLength: 780, TicketTTL: 240 * time.Second, PairTTL: 3900 * time.Second, Margin: 5 * time.Second, RefreshBefore: 30 * time.Second, MaxAttempts: 4, FailureCooldown: 30 * time.Second}.Normalized()
}
func testManager() (*Manager, *atomic.Int64) {
	clock := &atomic.Int64{}
	clock.Store(1800000000)
	return New(func() time.Time { return time.Unix(clock.Load(), 0) }), clock
}
func pairHeaders(now time.Time, gateway string, life time.Duration) http.Header {
	claims, _ := json.Marshal(map[string]any{"exp": now.Add(life).Unix(), "node": "chat.gateway." + gateway + ".api.openai.com"})
	jwt := "e30." + base64.RawURLEncoding.EncodeToString(claims) + ".signature"
	return http.Header{"Set-Cookie": {"__cflb=route; Path=/; Secure", "__oailb=" + jwt + "; Path=/; Secure"}}
}
func success(now time.Time, model, gateway string) Attempt {
	return Attempt{Status: 200, Model: model, ResponseID: "resp_1", State: strings.Repeat("x", 780), Header: pairHeaders(now, gateway, time.Hour)}
}
func mint(t *testing.T, m *Manager, c Config, scope string, models []string, probe Probe) {
	t.Helper()
	if err := m.Refresh(context.Background(), scope, models, endpoint, c, probe); err != nil {
		t.Fatal(err)
	}
}

func TestGatewayMismatchDespiteSameModel(t *testing.T) {
	m, _ := testManager()
	c := testConfig()
	calls := 0
	err := m.Refresh(context.Background(), "scope", []string{"A"}, endpoint, c, func(_ context.Context, r Request) (Attempt, error) {
		calls++
		if r.Pair != nil {
			t.Fatal("off-target pair replayed")
		}
		return success(m.now(), r.Model, "unified-12"), nil
	})
	if err == nil || calls != c.MaxAttempts {
		t.Fatalf("error=%v calls=%d", err, calls)
	}
	if _, ok := m.Get("scope", "A", c); ok {
		t.Fatal("wrong gateway accepted")
	}
}

func TestGatewayRejectListRetriesOnlyDeniedAndKeepsOtherRoutes(t *testing.T) {
	c := testConfig()
	c.Gateway = "any"
	c.RejectGateways = []string{"149"}
	for _, allowed := range []string{"unified-83", "unified-88", "unified-167"} {
		t.Run(allowed, func(t *testing.T) {
			m, _ := testManager()
			calls := 0
			mint(t, m, c, allowed, []string{"A"}, func(_ context.Context, r Request) (Attempt, error) {
				calls++
				if r.Pair != nil {
					t.Fatal("rejected pair replayed")
				}
				gateway := "unified-149"
				if calls == 2 {
					gateway = allowed
				}
				return success(m.now(), r.Model, gateway), nil
			})
			if calls != 2 {
				t.Fatalf("wanted one retry, got %d", calls)
			}
			bundle, ok := m.Get(allowed, "A", c)
			if !ok || bundle.Pair.Gateway != allowed {
				t.Fatalf("allowed gateway lost: ok=%t gateway=%s", ok, bundle.Pair.Gateway)
			}
		})
	}
	m, clock := testManager()
	c.MaxAttempts = 3
	calls := 0
	probe := func(_ context.Context, r Request) (Attempt, error) {
		calls++
		if r.Pair != nil {
			t.Fatal("denied pair reused")
		}
		return success(m.now(), r.Model, "unified-149"), nil
	}
	if err := m.Refresh(context.Background(), "denied", []string{"A"}, endpoint, c, probe); err == nil || calls != c.MaxAttempts {
		t.Fatalf("unbounded or accepted: err=%v calls=%d", err, calls)
	}
	if _, ok := m.Get("denied", "A", c); ok || m.Snapshot("denied", "A", c).Reason != "gateway_rejected" {
		t.Fatal("denied pair became ready or was not diagnosed")
	}
	if err := m.Refresh(context.Background(), "denied", []string{"A"}, endpoint, c, probe); err == nil || calls != c.MaxAttempts {
		t.Fatal("cooldown was bypassed")
	}
	clock.Add(31)
	if err := m.Refresh(context.Background(), "denied", []string{"A"}, endpoint, c, probe); err == nil || calls != c.MaxAttempts*2 {
		t.Fatal("cooldown did not allow bounded retry")
	}
}

func TestGatewayRejectListChangeDiscardsOldRouteAndItsTicket(t *testing.T) {
	m, _ := testManager()
	c := testConfig()
	c.Gateway = "any"
	mint(t, m, c, "scope", []string{"A"}, func(_ context.Context, r Request) (Attempt, error) {
		return success(m.now(), r.Model, "unified-149"), nil
	})
	c.RejectGateways = []string{"unified-149"}
	if _, ok := m.Get("scope", "A", c); ok || m.Snapshot("scope", "A", c).Ready {
		t.Fatal("old route reused after policy change")
	}
	mint(t, m, c, "scope", []string{"A"}, func(_ context.Context, r Request) (Attempt, error) {
		if r.Pair != nil {
			t.Fatal("cached rejected route sent in new probe")
		}
		a := success(m.now(), r.Model, "unified-83")
		a.State = strings.Repeat("n", 780)
		return a, nil
	})
	bundle, ok := m.Get("scope", "A", c)
	if !ok || bundle.Ticket.State != strings.Repeat("n", 780) || bundle.Pair.Gateway != "unified-83" {
		t.Fatal("old ticket lent to replacement route")
	}
}

func TestGatewayReject149FromEitherCookieHint(t *testing.T) {
	m, _ := testManager()
	c := testConfig()
	c.Gateway = "any"
	c.RejectGateways = []string{"unified-149"}
	for _, tt := range []struct {
		name, cflb, oailb string
	}{
		{"oailb", "route", "unified-0149"},
		{"conflicting cflb", "unified-149", "unified-83"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{"Set-Cookie": {"__cflb=" + tt.cflb + "; Path=/; Secure", "__oailb=" + tt.oailb + "; Path=/; Secure"}}
			p, changed := ReadPair(h, endpoint, m.now(), c.Normalized())
			if !changed || p.CFLB != "" || p.OAILB != "" || p.Gateway != "unified-149" {
				t.Fatalf("rejected route escaped: changed=%t gateway=%s", changed, p.Gateway)
			}
		})
	}
}
func TestModelMismatchRetainsOnlyTargetPair(t *testing.T) {
	m, _ := testManager()
	c := testConfig()
	calls := 0
	mint(t, m, c, "scope", []string{"A"}, func(_ context.Context, r Request) (Attempt, error) {
		calls++
		a := success(m.now(), "B", "unified-88")
		if calls == 2 {
			if r.Pair == nil {
				t.Fatal("target pair lost")
			}
			a.Model = "A"
			a.Header = nil
		}
		return a, nil
	})
	if calls != 2 {
		t.Fatal(calls)
	}
	if _, ok := m.Get("scope", "B", c); ok {
		t.Fatal("wrong-model ticket cached")
	}
}
func TestTicketAndPairHaveIndependentLifetimes(t *testing.T) {
	m, clock := testManager()
	c := testConfig()
	calls := 0
	p := func(_ context.Context, r Request) (Attempt, error) {
		calls++
		a := success(m.now(), r.Model, "unified-88")
		a.State = strings.Repeat(string(rune('w'+calls)), 780)
		if calls == 2 {
			if r.Pair == nil {
				t.Fatal("ticket renewal did not reuse pair")
			}
			a.Header = nil
		}
		return a, nil
	}
	mint(t, m, c, "scope", []string{"A"}, p)
	first, _ := m.Get("scope", "A", c)
	mint(t, m, c, "scope", []string{"A"}, p)
	if calls != 1 {
		t.Fatal("warm cache probed")
	}
	clock.Add(220)
	mint(t, m, c, "scope", []string{"A"}, p)
	second, _ := m.Get("scope", "A", c)
	if second.Pair != first.Pair || second.Ticket.State == first.Ticket.State {
		t.Fatal("ticket-only renewal replaced pair")
	}
	m.mu.Lock()
	e := m.scopes["scope"]
	e.pair.ExpiresAt = m.now().Add(time.Second)
	m.mu.Unlock()
	mint(t, m, c, "scope", []string{"A"}, func(_ context.Context, r Request) (Attempt, error) {
		calls++
		if r.Pair != nil {
			t.Fatal("near-expired pair replayed")
		}
		a := success(m.now(), r.Model, "unified-88")
		a.State = strings.Repeat("q", 780)
		return a, nil
	})
	third, _ := m.Get("scope", "A", c)
	if third.Ticket != second.Ticket {
		t.Fatal("pair repair replaced fresh ticket")
	}
}
func TestRotationPartialAndDeletionDoNotUseOldPair(t *testing.T) {
	for _, cookies := range [][]string{{"__cflb=new"}, {"__oailb=; Max-Age=0"}} {
		t.Run(cookies[0], func(t *testing.T) {
			m, clock := testManager()
			c := testConfig()
			c.MaxAttempts = 1
			mint(t, m, c, "scope", []string{"A"}, func(_ context.Context, r Request) (Attempt, error) {
				return success(m.now(), r.Model, "unified-88"), nil
			})
			clock.Add(220)
			err := m.Refresh(context.Background(), "scope", []string{"A"}, endpoint, c, func(_ context.Context, r Request) (Attempt, error) {
				a := success(m.now(), r.Model, "unified-88")
				a.Header = http.Header{"Set-Cookie": cookies}
				return a, nil
			})
			if err == nil {
				t.Fatal("partial rotation accepted")
			}
			if _, ok := m.Get("scope", "A", c); ok {
				t.Fatal("old pair survived rotation")
			}
		})
	}
}
func TestPartialSuccessRoundRobinAndSharedBudget(t *testing.T) {
	m, _ := testManager()
	c := testConfig()
	c.MaxAttempts = 3
	var requested []string
	err := m.Refresh(context.Background(), "scope", []string{"bad", "good"}, endpoint, c, func(_ context.Context, r Request) (Attempt, error) {
		requested = append(requested, r.Model)
		a := success(m.now(), r.Model, "unified-88")
		if r.Model == "bad" {
			a.Model = "wrong"
		}
		return a, nil
	})
	if err == nil || len(requested) != 3 || requested[1] != "good" {
		t.Fatalf("%v %v", err, requested)
	}
	if _, ok := m.Get("scope", "good", c); !ok {
		t.Fatal("good model starved")
	}
	if _, ok := m.Get("scope", "bad", c); ok {
		t.Fatal("bad model published")
	}
}
func TestCredentialRejectionStopsAllModelsAndHonorsBackoff(t *testing.T) {
	for _, status := range []int{401, 403, 429} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			m, clock := testManager()
			c := testConfig()
			calls := 0
			probe := func(_ context.Context, r Request) (Attempt, error) {
				calls++
				return Attempt{Status: status, Header: http.Header{"Retry-After": {"900"}}}, nil
			}
			_ = m.Refresh(context.Background(), "scope", []string{"A", "B"}, endpoint, c, probe)
			clock.Add(601)
			_ = m.Refresh(context.Background(), "scope", []string{"A", "B"}, endpoint, c, probe)
			if calls != 1 {
				t.Fatal("rejection retried", calls)
			}
		})
	}
}
func TestFatalModelDoesNotStarveAnother(t *testing.T) {
	m, _ := testManager()
	c := testConfig()
	calls := map[string]int{}
	_ = m.Refresh(context.Background(), "scope", []string{"bad", "good"}, endpoint, c, func(_ context.Context, r Request) (Attempt, error) {
		calls[r.Model]++
		if r.Model == "bad" {
			return Attempt{Status: 404}, nil
		}
		return success(m.now(), r.Model, "unified-88"), nil
	})
	if calls["bad"] != 1 || calls["good"] != 1 {
		t.Fatal(calls)
	}
	if _, ok := m.Get("scope", "good", c); !ok {
		t.Fatal("good model lost")
	}
}
func TestSingleFlightAndCanceledWaiter(t *testing.T) {
	m, _ := testManager()
	c := testConfig()
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	var calls atomic.Int32
	probe := func(ctx context.Context, r Request) (Attempt, error) {
		calls.Add(1)
		close(entered)
		select {
		case <-release:
			return success(m.now(), r.Model, "unified-88"), nil
		case <-ctx.Done():
			return Attempt{}, ctx.Err()
		}
	}
	go func() { done <- m.Refresh(context.Background(), "scope", []string{"A"}, endpoint, c, probe) }()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.Refresh(ctx, "scope", []string{"A"}, endpoint, c, probe); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for i := 0; i < 8; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if err := m.Refresh(context.Background(), "scope", []string{"A"}, endpoint, c, probe); err != nil {
				t.Error(err)
			}
		}()
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	wait.Wait()
	if calls.Load() != 1 {
		t.Fatal(calls.Load())
	}
}
func TestCancellationClosesActiveAttempt(t *testing.T) {
	m, _ := testManager()
	c := testConfig()
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- m.Refresh(ctx, "scope", []string{"A"}, endpoint, c, func(ctx context.Context, _ Request) (Attempt, error) {
			close(entered)
			<-ctx.Done()
			return Attempt{}, ctx.Err()
		})
	}()
	<-entered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if m.Snapshot("scope", "A", c).InFlight {
		t.Fatal("flight leaked")
	}
}
func TestLateInjectedResponseCannotEvictRenewedMaterial(t *testing.T) {
	m, clock := testManager()
	c := testConfig()
	mint(t, m, c, "scope", []string{"A"}, func(_ context.Context, r Request) (Attempt, error) {
		return success(m.now(), r.Model, "unified-88"), nil
	})
	old, _ := m.Get("scope", "A", c)
	clock.Add(220)
	mint(t, m, c, "scope", []string{"A"}, func(_ context.Context, r Request) (Attempt, error) {
		a := success(m.now(), r.Model, "unified-88")
		a.State = strings.Repeat("n", 780)
		return a, nil
	})
	if m.Reject("scope", "A", old.Ticket.State, old.Pair.Cookie()) {
		t.Fatal("late response evicted new ticket")
	}
	current, _ := m.Get("scope", "A", c)
	if !m.Reject("scope", "A", current.Ticket.State, current.Pair.Cookie()) {
		t.Fatal("current rejection ignored")
	}
	if _, ok := m.Get("scope", "A", c); ok {
		t.Fatal("rejected material usable")
	}
}
func TestLeaseNeverExtendedOnReadOrConfigChange(t *testing.T) {
	m, clock := testManager()
	c := testConfig()
	mint(t, m, c, "scope", []string{"A"}, func(_ context.Context, r Request) (Attempt, error) {
		return success(m.now(), r.Model, "unified-88"), nil
	})
	before, _ := m.Get("scope", "A", c)
	long := c
	long.TicketTTL = time.Hour
	after, _ := m.Get("scope", "A", long)
	if after.Ticket.ExpiresAt != before.Ticket.ExpiresAt {
		t.Fatal("lease extended")
	}
	short := c
	short.TicketTTL = 20 * time.Second
	clock.Add(16)
	if _, ok := m.Get("scope", "A", short); ok {
		t.Fatal("shorter TTL bypassed")
	}
	changed := c
	changed.TicketLength = 10
	if _, ok := m.Get("scope", "A", changed); ok {
		t.Fatal("new length bypassed")
	}
}
func TestScopeIsolationAndBoundedCache(t *testing.T) {
	if Scope("a", "bc") == Scope("ab", "c") {
		t.Fatal("ambiguous identity hash")
	}
	m, _ := testManager()
	c := testConfig()
	c.Capacity = 2
	for _, scope := range []string{"account1/sse", "account1/websocket", "account2/sse"} {
		mint(t, m, c, scope, []string{"A"}, func(_ context.Context, r Request) (Attempt, error) {
			return success(m.now(), r.Model, "unified-88"), nil
		})
	}
	if _, ok := m.Get("account1/sse", "A", c); ok {
		t.Fatal("capacity not bounded")
	}
	if _, ok := m.Get("account2/sse", "B", c); ok {
		t.Fatal("cross-model hit")
	}
}
func TestInjectionPreservesUnrelatedHeadersAndCookies(t *testing.T) {
	h := http.Header{"x-codex-turn-state": {"old"}, "Cookie": {"session=keep; __cflb=old; __oailb=old"}, "Authorization": {"Bearer own"}, "X-Test": {"keep"}}
	Inject(h, Bundle{Ticket: Ticket{State: "new"}, Pair: Pair{CFLB: "route", OAILB: "opaque"}})
	if h.Get(StateHeader) != "new" || h.Get("Authorization") != "Bearer own" || h.Get("X-Test") != "keep" {
		t.Fatal("headers changed")
	}
	if got := h.Get("Cookie"); !strings.Contains(got, "session=keep") || strings.Contains(got, "old") || strings.Count(got, "__cflb=") != 1 {
		t.Fatal(got)
	}
}
