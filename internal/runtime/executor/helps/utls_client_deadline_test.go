package helps

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

type deadlineTrackingConn struct {
	net.Conn
	deadlines []time.Time
}

func (c *deadlineTrackingConn) SetDeadline(deadline time.Time) error {
	c.deadlines = append(c.deadlines, deadline)
	return c.Conn.SetDeadline(deadline)
}

func TestNewUtlsRoundTripperSetsConnectionStageTimeouts(t *testing.T) {
	roundTripper := newUtlsRoundTripper("")
	if got := roundTripper.dialTimeout; got != utlsDialTimeout {
		t.Fatalf("dial timeout = %v, want %v", got, utlsDialTimeout)
	}
	if got := roundTripper.tlsHandshakeTimeout; got != utlsTLSHandshakeTimeout {
		t.Fatalf("TLS handshake timeout = %v, want %v", got, utlsTLSHandshakeTimeout)
	}

	client := NewUtlsHTTPClient(t.Context(), nil, nil, 0)
	if got := client.Timeout; got != 0 {
		t.Fatalf("HTTP client timeout = %v, want no whole-request timeout", got)
	}
}

func TestUtlsRoundTripperDialStageDeadline(t *testing.T) {
	deadlineSeen := make(chan time.Time, 1)
	roundTripper := &utlsRoundTripper{
		dialer: contextDialerFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
			deadline, ok := ctx.Deadline()
			if !ok {
				return nil, errors.New("dial context has no deadline")
			}
			deadlineSeen <- deadline
			<-ctx.Done()
			return nil, ctx.Err()
		}),
		dialTimeout:         50 * time.Millisecond,
		tlsHandshakeTimeout: time.Second,
	}

	started := time.Now()
	_, errConnect := roundTripper.createConnection(t.Context(), "chatgpt.com", "chatgpt.com:443")
	if !errors.Is(errConnect, context.DeadlineExceeded) {
		t.Fatalf("createConnection error = %v, want dial deadline exceeded", errConnect)
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("dial stopped after %v, want less than 1s", elapsed)
	}
	select {
	case deadline := <-deadlineSeen:
		if deadline.IsZero() {
			t.Fatal("dial deadline is zero")
		}
	default:
		t.Fatal("dialer did not observe the stage deadline")
	}
}

func TestUtlsRoundTripperDialFailureClosesReturnedRawConnection(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		if errClose := serverConn.Close(); errClose != nil && !errors.Is(errClose, net.ErrClosed) && !errors.Is(errClose, io.ErrClosedPipe) {
			t.Errorf("close server connection: %v", errClose)
		}
	})

	dialErr := errors.New("injected TCP dial failure")
	trackedConn := &trackedNetConn{Conn: clientConn}
	roundTripper := &utlsRoundTripper{
		dialer: contextDialerFunc(func(context.Context, string, string) (net.Conn, error) {
			return trackedConn, dialErr
		}),
		dialTimeout:         time.Second,
		tlsHandshakeTimeout: time.Second,
	}

	_, errConnect := roundTripper.createConnection(t.Context(), "chatgpt.com", "chatgpt.com:443")
	if !errors.Is(errConnect, dialErr) {
		t.Fatalf("createConnection error = %v, want injected dial error", errConnect)
	}
	if got := trackedConn.closeCount.Load(); got != 1 {
		t.Fatalf("raw connection close count = %d, want 1", got)
	}
}

func TestUtlsRoundTripperSOCKSNegotiationTimeoutClosesProxyConnection(t *testing.T) {
	listener, errListen := net.Listen("tcp", "127.0.0.1:0")
	if errListen != nil {
		t.Fatal(errListen)
	}
	t.Cleanup(func() {
		if errClose := listener.Close(); errClose != nil && !errors.Is(errClose, net.ErrClosed) {
			t.Errorf("close SOCKS listener: %v", errClose)
		}
	})

	proxyConnectionClosed := make(chan error, 1)
	go func() {
		conn, errAccept := listener.Accept()
		if errAccept != nil {
			proxyConnectionClosed <- errAccept
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buffer := make([]byte, 32)
		for {
			if _, errRead := conn.Read(buffer); errRead != nil {
				proxyConnectionClosed <- errRead
				return
			}
		}
	}()

	socksDialer, errSOCKS := proxy.SOCKS5("tcp", listener.Addr().String(), nil, proxy.Direct)
	if errSOCKS != nil {
		t.Fatal(errSOCKS)
	}
	roundTripper := &utlsRoundTripper{
		dialer:              socksDialer,
		dialTimeout:         50 * time.Millisecond,
		tlsHandshakeTimeout: time.Second,
	}

	_, errConnect := roundTripper.createConnection(t.Context(), "chatgpt.com", "chatgpt.com:443")
	if !errors.Is(errConnect, context.DeadlineExceeded) {
		t.Fatalf("createConnection error = %v, want SOCKS negotiation deadline exceeded", errConnect)
	}
	select {
	case errRead := <-proxyConnectionClosed:
		if !errors.Is(errRead, io.EOF) && !errors.Is(errRead, net.ErrClosed) {
			t.Fatalf("SOCKS proxy read error = %v, want client connection close", errRead)
		}
	case <-time.After(time.Second):
		t.Fatal("SOCKS proxy connection remained open after stage timeout")
	}
}

func TestUtlsRoundTripperTLSHandshakeStageTimeoutClosesRawConnection(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		if errClose := serverConn.Close(); errClose != nil && !errors.Is(errClose, net.ErrClosed) && !errors.Is(errClose, io.ErrClosedPipe) {
			t.Errorf("close server connection: %v", errClose)
		}
	})

	trackedConn := &trackedNetConn{Conn: clientConn}
	roundTripper := &utlsRoundTripper{
		dialer: contextDialerFunc(func(context.Context, string, string) (net.Conn, error) {
			return trackedConn, nil
		}),
		dialTimeout:         time.Second,
		tlsHandshakeTimeout: 50 * time.Millisecond,
	}

	started := time.Now()
	_, errConnect := roundTripper.createConnection(t.Context(), "chatgpt.com", "chatgpt.com:443")
	if !errors.Is(errConnect, context.DeadlineExceeded) {
		t.Fatalf("createConnection error = %v, want TLS handshake deadline exceeded", errConnect)
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("TLS handshake stopped after %v, want less than 1s", elapsed)
	}
	if got := trackedConn.closeCount.Load(); got != 1 {
		t.Fatalf("raw connection close count = %d, want 1", got)
	}
}

func TestRunUtlsConnectionStageClearsDeadlineAfterSuccess(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		if errClose := clientConn.Close(); errClose != nil && !errors.Is(errClose, net.ErrClosed) && !errors.Is(errClose, io.ErrClosedPipe) {
			t.Errorf("close client connection: %v", errClose)
		}
		if errClose := serverConn.Close(); errClose != nil && !errors.Is(errClose, net.ErrClosed) && !errors.Is(errClose, io.ErrClosedPipe) {
			t.Errorf("close server connection: %v", errClose)
		}
	})

	trackedConn := &deadlineTrackingConn{Conn: clientConn}
	errStage := runUtlsConnectionStage(t.Context(), trackedConn, time.Second, func(ctx context.Context) error {
		if _, ok := ctx.Deadline(); !ok {
			return errors.New("stage context has no deadline")
		}
		return nil
	})
	if errStage != nil {
		t.Fatal(errStage)
	}
	if got := len(trackedConn.deadlines); got != 2 {
		t.Fatalf("SetDeadline call count = %d, want 2", got)
	}
	if trackedConn.deadlines[0].IsZero() {
		t.Fatal("stage deadline is zero")
	}
	if !trackedConn.deadlines[1].IsZero() {
		t.Fatalf("cleared deadline = %v, want zero", trackedConn.deadlines[1])
	}
}
