// Package codexmint acquires opaque routing material. It does not identify model
// weights, measure response quality, or implement a forwarding transport.
package codexmint

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const StateHeader = "X-Codex-Turn-State"
const ScanLimit = 16 * 1024

var unifiedPattern = regexp.MustCompile(`(?i)unified[-_.]?(\d+)`)

var gatewayPattern = regexp.MustCompile(`(?i)unified[-_.]?(\d+)|gateway[-_.][a-z0-9-]+`)

func NormalizeGateway(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || s == "*" || s == "any" {
		return ""
	}
	if _, err := strconv.ParseUint(s, 10, 64); err == nil {
		return "unified-" + s
	}
	m := gatewayPattern.FindStringSubmatch(s)
	if len(m) > 1 && m[0] == s && m[1] != "" {
		return "unified-" + m[1]
	}
	return s
}

func jwtPayload(s string) []byte {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return nil
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil || len(b) > ScanLimit {
		return nil
	}
	return b
}

func Gateway(cflb, oailb string) string {
	for _, s := range []string{string(jwtPayload(oailb)), oailb, cflb} {
		m := gatewayPattern.FindStringSubmatch(s)
		if len(m) > 0 {
			if len(m[0]) > 96 {
				return ""
			}
			if u := unifiedPattern.FindStringSubmatch(m[0]); len(u) > 1 {
				return "unified-" + u[1]
			}
			return strings.ToLower(m[0])
		}
	}
	return ""
}

type Pair struct {
	CFLB, OAILB, Gateway  string
	Source                string
	CapturedAt, ExpiresAt time.Time
}

func (p Pair) Cookie() string { return "__cflb=" + p.CFLB + "; __oailb=" + p.OAILB }
func (p Pair) valid(now time.Time, c Config, margin time.Duration) bool {
	return p.CFLB != "" && p.OAILB != "" && (c.Gateway == "" || p.Gateway == c.Gateway) &&
		earlier(p.ExpiresAt, p.CapturedAt.Add(c.PairTTL)).After(now.Add(margin))
}
func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// ReadPair treats any partial rotation, deletion or malformed routing cookie as
// a lost route. JWT claims are unverified hints, never authorization evidence.
// Server expiration hints can shorten, but never extend, the local lease.
func ReadPair(h http.Header, endpoint string, now time.Time, c Config) (Pair, bool) {
	p := Pair{CapturedAt: now, ExpiresAt: now.Add(c.PairTTL)}
	u, err := url.Parse(endpoint)
	if err != nil {
		return Pair{}, false
	}
	raw := map[string]string{}
	changed := false
	for name, values := range h {
		if !strings.EqualFold(name, "Set-Cookie") {
			continue
		}
		for _, line := range values {
			key, _, ok := strings.Cut(line, "=")
			key = strings.TrimSpace(key)
			if !ok || (key != "__cflb" && key != "__oailb") {
				continue
			}
			changed = true
			// Ambiguous duplicate updates cannot produce a trusted pair.
			if _, exists := raw[key]; exists {
				return Pair{}, true
			}
			raw[key] = line
		}
	}
	if !changed {
		return Pair{}, false
	}
	if len(raw) != 2 {
		return Pair{}, true
	}
	for _, name := range []string{"__cflb", "__oailb"} {
		cookies := (&http.Response{Header: http.Header{"Set-Cookie": {raw[name]}}}).Cookies()
		if len(cookies) != 1 {
			return Pair{}, true
		}
		k := cookies[0]
		if k.Name != name || k.Value == "" || len(k.Value) > 4096 || k.MaxAge < 0 || k.Valid() != nil {
			return Pair{}, true
		}
		domain := strings.TrimPrefix(strings.ToLower(k.Domain), ".")
		if domain != "" && domain != strings.ToLower(u.Hostname()) {
			return Pair{}, true
		}
		path := u.EscapedPath()
		if path == "" {
			path = "/"
		}
		if k.Path != "" && !(path == k.Path || (strings.HasPrefix(path, k.Path) && (strings.HasSuffix(k.Path, "/") || strings.HasPrefix(strings.TrimPrefix(path, k.Path), "/")))) {
			return Pair{}, true
		}
		if k.Secure && u.Scheme != "https" && u.Scheme != "wss" {
			return Pair{}, true
		}
		if k.MaxAge > 0 {
			p.ExpiresAt = earlier(p.ExpiresAt, now.Add(time.Duration(min(k.MaxAge, int(c.PairTTL/time.Second)))*time.Second))
		}
		if !k.Expires.IsZero() {
			p.ExpiresAt = earlier(p.ExpiresAt, k.Expires)
		}
		if name == "__cflb" {
			p.CFLB = k.Value
		} else {
			p.OAILB = k.Value
		}
	}
	var claims struct {
		Exp json.Number `json:"exp"`
	}
	if payload := jwtPayload(p.OAILB); len(payload) > 0 {
		if json.Unmarshal(payload, &claims) == nil && claims.Exp != "" {
			exp, e := claims.Exp.Int64()
			if e != nil || exp <= 0 {
				return Pair{}, true
			}
			p.ExpiresAt = earlier(p.ExpiresAt, time.Unix(exp, 0))
		}
	}
	p.Gateway = Gateway(p.CFLB, p.OAILB)
	if !p.valid(now, c, 0) {
		return Pair{Gateway: p.Gateway}, true
	}
	return p, true
}

type Event struct {
	Headers                   http.Header
	Model, ID, State, Failure string
	Status                    int
	Terminal                  bool
}

// ParseEvent accepts only complete JSON events. Arbitrary model strings inside
// text, metadata, output items or completed events are not identity declarations.
func ParseEvent(data []byte, eventName string) (Event, error) {
	var wire struct {
		Type    string                     `json:"type"`
		Status  int                        `json:"status"`
		Headers map[string]json.RawMessage `json:"headers"`
		Error   struct {
			Code, Type string
			Status     int
		} `json:"error"`
		Response struct {
			ID    string `json:"id"`
			Model string `json:"model"`
			Error struct {
				Code, Type string
				Status     int
			} `json:"error"`
		} `json:"response"`
	}
	if len(data) > ScanLimit || !utf8.Valid(data) || !json.Valid(data) || json.Unmarshal(data, &wire) != nil {
		return Event{}, errors.New("malformed_event")
	}
	if eventName != "" && eventName != wire.Type {
		return Event{}, errors.New("event_type_mismatch")
	}
	switch wire.Type {
	case "response.created":
		if strings.TrimSpace(wire.Response.ID) == "" || strings.TrimSpace(wire.Response.Model) == "" {
			return Event{}, errors.New("invalid_created")
		}
		return Event{ID: wire.Response.ID, Model: wire.Response.Model}, nil
	case "codex.response.metadata":
		headers := make(http.Header)
		for key, raw := range wire.Headers {
			key = http.CanonicalHeaderKey(key)
			if key != StateHeader && key != "Set-Cookie" && key != "Retry-After" {
				continue
			}
			if _, duplicate := headers[key]; duplicate {
				return Event{}, errors.New("ambiguous_metadata")
			}
			var value string
			var values []string
			if json.Unmarshal(raw, &value) == nil {
				values = []string{value}
			} else if json.Unmarshal(raw, &values) != nil || len(values) == 0 {
				return Event{}, errors.New("invalid_metadata")
			}
			if key != "Set-Cookie" && len(values) != 1 {
				return Event{}, errors.New("ambiguous_metadata")
			}
			for _, value := range values {
				if strings.ContainsAny(value, "\r\n\x00") {
					return Event{}, errors.New("invalid_metadata")
				}
			}
			headers[key] = values
		}
		return Event{State: headers.Get(StateHeader), Headers: headers}, nil
	case "error", "response.error", "response.failed", "response.incomplete":
		code := wire.Error.Code
		if code == "" {
			code = wire.Error.Type
		}
		if code == "" {
			code = wire.Response.Error.Code
		}
		if code == "" {
			code = wire.Response.Error.Type
		}
		e := Event{Failure: "upstream_event_error", Status: wire.Status}
		if e.Status == 0 {
			e.Status = wire.Error.Status
		}
		if e.Status == 0 {
			e.Status = wire.Response.Error.Status
		}
		switch code {
		case "authentication_error", "invalid_api_key":
			e.Status = 401
			e.Terminal = true
		case "permission_denied":
			e.Status = 403
			e.Terminal = true
		case "rate_limit_exceeded", "rate_limit_error":
			e.Status = 429
		case "insufficient_quota":
			e.Status = 429
			e.Terminal = true
		case "invalid_request_error", "invalid_request", "invalid_argument", "model_not_found", "unsupported_model", "invalid_model":
			e.Status = 400
			e.Terminal = true
		}
		if e.Status < 400 || e.Status > 599 {
			e.Status = 502
		}
		return e, nil
	}
	return Event{}, nil
}

// ReadCreated stops at the first complete created/error event, without waiting
// for generation or EOF. The byte budget covers comments and unknown events too.
func ReadCreated(r io.Reader) (Event, error) {
	br := bufio.NewReader(io.LimitReader(r, ScanLimit+1))
	var line, data []byte
	name := ""
	consumed := 0
	skipLF := false
	firstLine := true
	dispatch := func() (Event, error) {
		if firstLine {
			line = bytes.TrimPrefix(line, []byte{0xef, 0xbb, 0xbf})
			firstLine = false
		}
		if len(line) == 0 {
			if len(data) == 0 {
				name = ""
				return Event{}, nil
			}
			payload := bytes.TrimSuffix(data, []byte("\n"))
			eventName := name
			data = nil
			name = ""
			if bytes.Equal(payload, []byte("[DONE]")) {
				return Event{}, errors.New("missing_created")
			}
			return ParseEvent(payload, eventName)
		}
		if line[0] != ':' {
			field, value, _ := bytes.Cut(line, []byte(":"))
			value = bytes.TrimPrefix(value, []byte(" "))
			switch string(field) {
			case "event":
				name = string(value)
			case "data":
				data = append(append(data, value...), '\n')
			}
		}
		line = nil
		return Event{}, nil
	}
	for {
		b, err := br.ReadByte()
		if err != nil {
			return Event{}, errors.New("incomplete_created")
		}
		consumed++
		if consumed > ScanLimit {
			return Event{}, errors.New("scan_limit")
		}
		if skipLF && b == '\n' {
			skipLF = false
			continue
		}
		skipLF = false
		if b == '\r' || b == '\n' {
			skipLF = b == '\r'
			e, err := dispatch()
			if err != nil || e.ID != "" || e.Failure != "" {
				return e, err
			}
		} else {
			line = append(line, b)
		}
	}
}

func issuedAt(state string, observed time.Time) time.Time {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(state, "="))
	if err == nil && len(b) >= 9 && b[0] == 0x80 {
		sec := binary.BigEndian.Uint64(b[1:9])
		if sec > 0 && sec <= uint64(observed.Unix()) {
			return time.Unix(int64(sec), 0)
		}
	}
	return observed
}
