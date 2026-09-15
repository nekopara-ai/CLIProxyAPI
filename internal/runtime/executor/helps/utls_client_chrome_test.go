package helps

import (
	gotls "crypto/tls"
	"crypto/x509"
	errorsstd "errors"
	"io"
	"net"
	"reflect"
	"testing"
	"time"

	tls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

func chromeSpecExtensionCounts(spec *tls.ClientHelloSpec) map[reflect.Type]int {
	counts := make(map[reflect.Type]int, len(spec.Extensions))
	for _, extension := range spec.Extensions {
		counts[reflect.TypeOf(extension)]++
	}
	return counts
}

// TestChromeTLSClientHelloSpecOnlyAddsPreSharedKey pins the intentional
// difference from uTLS's Chrome parrot. Anything else -- a dropped extension, a
// reordered pre_shared_key, an extra one -- changes the fingerprint the browser
// profile presents and must fail here first.
func TestChromeTLSClientHelloSpecOnlyAddsPreSharedKey(t *testing.T) {
	stockSpec, errStock := tls.UTLSIdToSpec(tls.HelloChrome_Auto)
	if errStock != nil {
		t.Fatalf("resolve stock Chrome spec: %v", errStock)
	}
	chromeSpec, errChrome := chromeTLSClientHelloSpec()
	if errChrome != nil {
		t.Fatalf("chromeTLSClientHelloSpec: %v", errChrome)
	}

	stockCounts := chromeSpecExtensionCounts(&stockSpec)
	chromeCounts := chromeSpecExtensionCounts(chromeSpec)
	pskType := reflect.TypeOf(&tls.UtlsPreSharedKeyExtension{})
	for extensionType, count := range chromeCounts {
		want := stockCounts[extensionType]
		if extensionType == pskType {
			want++
		}
		if count != want {
			t.Fatalf("extension %v appears %d times, want %d", extensionType, count, want)
		}
	}

	if len(chromeSpec.Extensions) != len(stockSpec.Extensions)+1 {
		t.Fatalf("extension count = %d, want %d", len(chromeSpec.Extensions), len(stockSpec.Extensions)+1)
	}
	last := chromeSpec.Extensions[len(chromeSpec.Extensions)-1]
	if _, ok := last.(*tls.UtlsPreSharedKeyExtension); !ok {
		t.Fatalf("last extension is %T, want pre_shared_key last so the ClientHello stays valid", last)
	}
}

// TestChromeTLSSessionResumptionCompletesHandshake proves the browser profile
// can actually resume a session now that the spec carries pre_shared_key. A
// client that performs a full handshake for every request is easy to separate
// from a real one.
func TestChromeTLSSessionResumptionCompletesHandshake(t *testing.T) {
	certificate := newResumptionTestCertificate(t)
	roots := x509.NewCertPool()
	roots.AddCert(certificate.Leaf)

	listener, errListen := net.Listen("tcp", "127.0.0.1:0")
	if errListen != nil {
		t.Fatalf("listen: %v", errListen)
	}
	t.Cleanup(func() {
		if errClose := listener.Close(); errClose != nil && !errorsstd.Is(errClose, net.ErrClosed) {
			t.Errorf("close listener: %v", errClose)
		}
	})

	serverConfig := &gotls.Config{
		Certificates: []gotls.Certificate{certificate},
		MinVersion:   gotls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	go func() {
		for {
			raw, errAccept := listener.Accept()
			if errAccept != nil {
				return
			}
			go func(conn net.Conn) {
				server := gotls.Server(conn, serverConfig)
				if errHandshake := server.Handshake(); errHandshake != nil {
					_ = conn.Close()
					return
				}
				// The greeting flushes the post-handshake NewSessionTicket the
				// client needs in order to resume.
				_, _ = server.Write([]byte("ok\n"))
				_, _ = server.Read(make([]byte, 8))
				_ = server.Close()
			}(raw)
		}
	}()

	sessionCache := tls.NewLRUClientSessionCache(utlsSessionCacheCapacity)
	dial := func(round int) bool {
		raw, errDial := net.Dial("tcp", listener.Addr().String())
		if errDial != nil {
			t.Fatalf("round %d dial: %v", round, errDial)
		}
		defer func() {
			if errClose := raw.Close(); errClose != nil && !errorsstd.Is(errClose, net.ErrClosed) {
				t.Errorf("round %d close: %v", round, errClose)
			}
		}()

		// The loopback server presents the shared test certificate, so the
		// ClientHello is aimed at the name that certificate covers. The Chrome
		// profile itself does not depend on which host is dialled.
		config := newChromeTLSConfig("api.anthropic.com", sessionCache)
		config.RootCAs = roots
		spec, errSpec := chromeTLSClientHelloSpec()
		if errSpec != nil {
			t.Fatalf("round %d spec: %v", round, errSpec)
		}
		conn := tls.UClient(raw, config, tls.HelloCustom)
		if errPreset := conn.ApplyPreset(spec); errPreset != nil {
			t.Fatalf("round %d apply preset: %v", round, errPreset)
		}
		if errHandshake := conn.Handshake(); errHandshake != nil {
			t.Fatalf("round %d handshake: %v", round, errHandshake)
		}
		if _, errRead := conn.Read(make([]byte, 8)); errRead != nil && !errorsstd.Is(errRead, io.EOF) {
			t.Fatalf("round %d read: %v", round, errRead)
		}
		_, _ = conn.Write([]byte("bye\n"))
		return conn.ConnectionState().DidResume
	}

	if resumed := dial(1); resumed {
		t.Fatal("first handshake reported resumption without a cached session")
	}
	if resumed := dial(2); !resumed {
		t.Fatal("second handshake did not resume, so the session cache is not effective")
	}
}

func newTestHTTP2ClientConn(t *testing.T) *http2.ClientConn {
	t.Helper()
	client, server := net.Pipe()
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		// Drain the client preface and the frames the transport writes, so
		// nothing blocks on the unbuffered pipe.
		_, _ = io.Copy(io.Discard, server)
	}()
	conn, errConn := (&http2.Transport{}).NewClientConn(client)
	if errConn != nil {
		t.Fatalf("new client conn: %v", errConn)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		_ = server.Close()
		<-drained
	})
	return conn
}

// TestUtlsConnectionPoolTracksInFlightAndIdleConnections covers the pooling
// bookkeeping the browser profile now relies on: multiplexed requests share one
// connection, a duplicate dial is closed once it drains, and an idle connection
// expires instead of being reused forever.
func TestUtlsConnectionPoolTracksInFlightAndIdleConnections(t *testing.T) {
	roundTripper := &utlsRoundTripper{connections: make(map[string]*utlsConnection)}
	addr := "chatgpt.com:443"
	pooled := &utlsConnection{client: newTestHTTP2ClientConn(t), addr: addr, inFlight: 1}
	roundTripper.connections[addr] = pooled

	if !pooled.canServeRequest() {
		t.Fatal("a connection with work in flight must accept multiplexed requests")
	}
	roundTripper.releaseConnection(pooled)
	if pooled.inFlight != 0 {
		t.Fatalf("in flight = %d, want 0 after release", pooled.inFlight)
	}
	if !pooled.canServeRequest() {
		t.Fatal("a freshly released connection must stay reusable")
	}

	pooled.idleSince = time.Now().Add(-2 * utlsIdleConnectionTTL)
	if pooled.canServeRequest() {
		t.Fatal("an idle connection past the TTL must not be reused")
	}

	duplicate := &utlsConnection{client: newTestHTTP2ClientConn(t), addr: addr, inFlight: 1, unpooled: true}
	roundTripper.releaseConnection(duplicate)
	if roundTripper.connections[addr] != pooled {
		t.Fatal("releasing a duplicate must not evict the pooled connection")
	}

	roundTripper.CloseIdleConnections()
	if len(roundTripper.connections) != 0 {
		t.Fatalf("pooled connections = %d, want 0 after CloseIdleConnections", len(roundTripper.connections))
	}
}
