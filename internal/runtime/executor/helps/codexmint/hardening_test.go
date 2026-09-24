package codexmint

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestGatewayMetadataPreservesAtomicCookieArrays(t *testing.T) {
	wire, _ := json.Marshal(map[string]any{"type": "codex.response.metadata", "headers": map[string]any{
		"x-codex-turn-state": []string{"ticket"}, "set-cookie": []string{"__cflb=a", "__oailb=b"},
	}})
	event, err := ParseEvent(wire, "")
	if err != nil || event.State != "ticket" || len(event.Headers.Values("Set-Cookie")) != 2 {
		t.Fatal("typed metadata arrays lost", event, err)
	}
	for _, raw := range []string{
		`{"type":"codex.response.metadata","headers":{"x-codex-turn-state":["a","b"]}}`,
		`{"type":"codex.response.metadata","headers":{"set-cookie":{"invalid":"object"}}}`,
		`{"type":"codex.response.metadata","headers":{"set-cookie":["a=1\r\nInjected: yes"]}}`,
		`{"type":"codex.response.metadata","headers":{"Set-Cookie":"a=1","set-cookie":"b=2"}}`,
	} {
		if _, err := ParseEvent([]byte(raw), ""); err == nil {
			t.Fatal("ambiguous metadata accepted", raw)
		}
	}
}

func TestGatewayPairRepairRetainsTicketEvenWithoutNewTicket(t *testing.T) {
	m, _ := testManager()
	cfg := testConfig()
	mint(t, m, cfg, "scope", []string{"A"}, func(_ context.Context, r Request) (Attempt, error) {
		return success(m.now(), r.Model, "unified-88"), nil
	})
	before, _ := m.Get("scope", "A", cfg)
	if !m.RejectParts("scope", "A", before.Ticket.State, before.Pair.Cookie(), true, false) {
		t.Fatal("route-only invalidation failed")
	}
	if _, ready := m.Get("scope", "A", cfg); ready {
		t.Fatal("missing route passed")
	}
	calls := 0
	mint(t, m, cfg, "scope", []string{"A"}, func(_ context.Context, r Request) (Attempt, error) {
		calls++
		if r.Pair != nil {
			t.Fatal("invalidated route reused")
		}
		a := success(m.now(), "different-model", "unified-88")
		a.State = ""
		return a, nil
	})
	after, ok := m.Get("scope", "A", cfg)
	if !ok || calls != 1 || after.Ticket != before.Ticket {
		t.Fatal("independent route repair lost a valid ticket")
	}
}

func TestGatewayCredentialParkBlocksInjectionAndFencesObservation(t *testing.T) {
	m, clock := testManager()
	cfg := testConfig()
	mint(t, m, cfg, "scope", []string{"A"}, func(_ context.Context, r Request) (Attempt, error) {
		return success(m.now(), r.Model, "unified-88"), nil
	})
	m.Park("scope", m.now().Add(time.Minute))
	if _, ok := m.Get("scope", "A", cfg); ok || m.Snapshot("scope", "A", cfg).Ready {
		t.Fatal("parked scope still injects")
	}
	clock.Add(61)
	if _, ok := m.Get("scope", "A", cfg); !ok {
		t.Fatal("lease was extended or destroyed instead of temporarily parked")
	}
	err := m.Refresh(context.Background(), "other", []string{"A"}, endpoint, cfg, func(_ context.Context, r Request) (Attempt, error) {
		m.Park("other", m.now().Add(time.Minute))
		return success(m.now(), r.Model, "unified-88"), nil
	})
	if err == nil {
		t.Fatal("parked in-flight observation published")
	}
	if _, ok := m.Get("other", "A", cfg); ok {
		t.Fatal("park did not fence publication")
	}
}

func TestGatewayRejectedProbeBlocksEarlierPartialSuccess(t *testing.T) {
	m, _ := testManager()
	cfg := testConfig()
	err := m.Refresh(context.Background(), "scope", []string{"A", "B"}, endpoint, cfg, func(_ context.Context, r Request) (Attempt, error) {
		if r.Model == "A" {
			return success(m.now(), r.Model, "unified-88"), nil
		}
		return Attempt{Status: 429, Header: http.Header{"Retry-After": {"1200"}}}, nil
	})
	if err == nil {
		t.Fatal("rejection ignored")
	}
	if _, ok := m.Get("scope", "A", cfg); ok {
		t.Fatal("credential rejection allowed a partial cached success")
	}
	if s := m.Snapshot("scope", "A", cfg); s.Ready || !s.NextAttemptAt.Equal(m.now().Add(1200*time.Second)) {
		t.Fatal(s)
	}
	badUTF8 := []byte(`{"type":"response.created","response":{"id":"id","model":"A` + strings.Repeat("\xff", 1) + `"}}`)
	if _, err := ParseEvent(badUTF8, ""); err == nil {
		t.Fatal("invalid UTF-8 model declaration accepted")
	}
}
