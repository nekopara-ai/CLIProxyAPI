package helps

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// TestUtlsReleaseConnectionDrainsGoaway checks that releasing one stream after GOAWAY does not
// forcibly close another stream that is still using the same connection.
func TestUtlsReleaseConnectionDrainsGoaway(t *testing.T) {
	finish := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(finish) })
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-finish
		_, _ = io.WriteString(w, "OK")
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	c, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	cc, err := (&http2.Transport{}).NewClientConn(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	request, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	r1, err := cc.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := cc.RoundTrip(request.Clone(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	defer r1.Body.Close()
	defer r2.Body.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() { _ = srv.Config.Shutdown(ctx) }()
	for !cc.State().Closing && ctx.Err() == nil {
		runtime.Gosched()
	}
	if !cc.State().Closing {
		t.Fatal("server did not send GOAWAY")
	}
	addr := srv.Listener.Addr().String()
	pooled := &utlsConnection{client: cc, addr: addr, inFlight: 2}
	rt := &utlsRoundTripper{connections: map[string]*utlsConnection{addr: pooled}}
	rt.releaseConnection(pooled)
	if cc.State().Closed {
		t.Errorf("connection closed with %d other stream still in flight", pooled.inFlight)
	}
	once.Do(func() { close(finish) })
	_, _ = io.ReadAll(r1.Body)
	body, err := io.ReadAll(r2.Body)
	if err != nil {
		t.Errorf("other stream aborted: %v", err)
	}
	if string(body) != "OK" {
		t.Errorf("other stream body = %q, want OK", body)
	}
	rt.releaseConnection(pooled)
	if !cc.State().Closed {
		t.Error("drained connection was not closed")
	}
	if _, exists := rt.connections[addr]; exists {
		t.Error("drained connection remains in the pool")
	}
}
