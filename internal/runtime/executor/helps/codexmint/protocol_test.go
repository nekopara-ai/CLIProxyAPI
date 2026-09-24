package codexmint

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type oneByteReader struct{ io.Reader }

func (r oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.Reader.Read(p)
}

type failAfter struct {
	prefix   *strings.Reader
	readPast bool
}

func (r *failAfter) Read(p []byte) (int, error) {
	if r.prefix.Len() == 0 {
		r.readPast = true
		return 0, errors.New("must not wait for completion")
	}
	return r.prefix.Read(p)
}
func TestStrictCreatedParsingAndEarlyStop(t *testing.T) {
	json := `{"type":"response.created","response":{"id":"resp_a","model":"A"}}`
	for _, sep := range []string{"\n", "\r\n", "\r"} {
		for _, bom := range []string{"", "\xef\xbb\xbf"} {
			wire := bom + "event: response.created" + sep + "data: " + json + sep + sep
			r := &failAfter{prefix: strings.NewReader(wire)}
			event, err := ReadCreated(oneByteReader{r})
			if err != nil || event.Model != "A" || event.ID != "resp_a" || r.readPast {
				t.Fatalf("%q %v %+v", sep, err, event)
			}
		}
	}
}
func TestRejectIncompleteAndSpoofedEvents(t *testing.T) {
	for _, wire := range []string{
		`data: {"model":"A"}` + "\n\n",
		`data: {"type":"response.completed","response":{"id":"id","model":"A"}}` + "\n\n",
		`data: {"type":"response.created","response":{"model":"A"}}` + "\n\n",
		`data: {"type":"response.created","response":{"id":"id","model":"A"}}` + "\n",
		"event: notice\ndata: " + `{"type":"response.created","response":{"id":"id","model":"A"}}` + "\n\n",
		":" + strings.Repeat("a", ScanLimit) + "\n\n",
		"\xef\xbb\xbf\n",
	} {
		if event, err := ReadCreated(strings.NewReader(wire)); err == nil || event.ID != "" {
			t.Fatalf("accepted %q %+v", wire, event)
		}
	}
}
func TestMultilineSSEAndTypedErrorEvents(t *testing.T) {
	wire := "data: {\n" + `data: "type":"response.created",` + "\n" + `data: "response":{"id":"id","model":"A"}}` + "\n\n"
	if e, err := ReadCreated(strings.NewReader(wire)); err != nil || e.Model != "A" {
		t.Fatal(e, err)
	}
	e, err := ReadCreated(strings.NewReader(`data: {"type":"error","error":{"code":"permission_denied","message":"secret-token"}}` + "\n\n"))
	if err != nil || e.Status != 403 || !e.Terminal || strings.Contains(e.Failure, "secret") {
		t.Fatal(e, err)
	}
}
func TestWebsocketMetadataIsTypedAndCaseInsensitive(t *testing.T) {
	for _, header := range []string{"x-codex-turn-state", "X-Codex-Turn-State"} {
		e, err := ParseEvent([]byte(`{"type":"codex.response.metadata","headers":{"`+header+`":"ticket"}}`), "")
		if err != nil || e.State != "ticket" {
			t.Fatal(e, err)
		}
	}
	e, _ := ParseEvent([]byte(`{"type":"other","text":"codex.response.metadata","headers":{"x-codex-turn-state":"fake"}}`), "")
	if e.State != "" {
		t.Fatal("untyped metadata accepted")
	}
}
func TestGatewayLabelsAndCookieExpiry(t *testing.T) {
	m, _ := testManager()
	c := testConfig()
	for _, name := range []string{"88", "unified_88", "unified.88", "unified-88"} {
		if NormalizeGateway(name) != "unified-88" {
			t.Fatal(name)
		}
	}
	for _, name := range []string{"any", "*", ""} {
		if NormalizeGateway(name) != "" {
			t.Fatal(name)
		}
	}
	h := pairHeaders(m.now(), "unified-88", 50*time.Second)
	p, changed := ReadPair(h, endpoint, m.now(), c)
	if !changed || p.Gateway != "unified-88" || !p.ExpiresAt.Equal(m.now().Add(50*time.Second)) {
		t.Fatal(p, changed)
	}
	expired := pairHeaders(m.now(), "unified-88", -time.Second)
	if p, _ := ReadPair(expired, endpoint, m.now(), c); p.CFLB != "" {
		t.Fatal("expired JWT accepted")
	}
	for _, suffix := range []string{"; Domain=evil.example", "; Path=/other", "; Max-Age=0", "; Expires=Thu, 01 Jan 1970 00:00:00 GMT"} {
		bad := h.Clone()
		bad["Set-Cookie"][1] += suffix
		if p, changed := ReadPair(bad, endpoint, m.now(), c); !changed || p.CFLB != "" {
			t.Fatalf("accepted %q", suffix)
		}
	}
	duplicate := h.Clone()
	duplicate.Add("Set-Cookie", "__cflb=duplicate")
	if p, _ := ReadPair(duplicate, endpoint, m.now(), c); p.CFLB != "" {
		t.Fatal("duplicate pair accepted")
	}
	if _, changed := ReadPair(http.Header{"Set-Cookie": {"unrelated=value"}}, endpoint, m.now(), c); changed {
		t.Fatal("unrelated cookie invalidated pair")
	}
}
