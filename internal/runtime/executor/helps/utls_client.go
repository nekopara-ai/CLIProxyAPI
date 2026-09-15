package helps

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	tls "github.com/refraction-networking/utls"
	internalcache "github.com/router-for-me/CLIProxyAPI/v7/internal/cache"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/httpwire"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

// utlsRoundTripper implements http.RoundTripper using a Chrome fingerprint for
// providers that require a browser-like TLS and HTTP/2 transport.
//
// It keeps the TLS session cache and the HTTP/2 connection between requests.
// A client that renegotiates from scratch for every request never resumes a
// session and never reuses a connection, which no browser does and which the
// upstream can observe directly.
type utlsRoundTripper struct {
	dialer              proxy.Dialer
	dialTimeout         time.Duration
	tlsHandshakeTimeout time.Duration
	sessions            tls.ClientSessionCache
	mu                  sync.Mutex
	connections         map[string]*utlsConnection
}

// utlsConnection is one pooled Chrome-profile HTTP/2 connection. Pooled
// connections may serve several requests at once, exactly like a browser
// multiplexing streams, so a connection is closed only once the last in-flight
// request has released it.
type utlsConnection struct {
	client    *http2.ClientConn
	addr      string
	inFlight  int
	idleSince time.Time
	unpooled  bool
}

const (
	utlsDialTimeout         = 30 * time.Second
	utlsTLSHandshakeTimeout = 10 * time.Second
	// utlsIdleConnectionTTL bounds how long an unused connection is kept, so a
	// connection silently dropped by an upstream is not reused forever.
	utlsIdleConnectionTTL = 90 * time.Second
	// utlsSessionCacheCapacity bounds the per-transport TLS session cache. The
	// cache is scoped to a single proxy, which is also the unit the round
	// tripper cache is keyed by.
	utlsSessionCacheCapacity = 32
)

// releaseConnectionBody returns the pooled connection to the round tripper once
// the caller is done with the response body, so the next request reuses the
// handshake instead of starting a new one.
type releaseConnectionBody struct {
	io.ReadCloser
	release func()
	once    sync.Once
	err     error
}

type onceCloseConn struct {
	net.Conn
	once sync.Once
	err  error
}

func (c *onceCloseConn) Close() error {
	if c == nil {
		return nil
	}
	c.once.Do(func() {
		if c.Conn != nil {
			c.err = c.Conn.Close()
		}
	})
	return c.err
}

func (b *releaseConnectionBody) Close() error {
	if b == nil {
		return nil
	}
	b.once.Do(func() {
		if b.release != nil {
			b.release()
		}
		if b.ReadCloser != nil {
			b.err = b.ReadCloser.Close()
		}
	})
	return b.err
}

func newUtlsRoundTripper(proxyURL string) *utlsRoundTripper {
	var dialer proxy.Dialer = proxy.Direct
	if proxyURL != "" {
		proxyDialer, mode, errBuild := proxyutil.BuildDialer(proxyURL)
		if errBuild != nil {
			log.Errorf("utls: failed to configure proxy dialer for %q: %v", proxyutil.Redact(proxyURL), errBuild)
		} else if mode != proxyutil.ModeInherit && proxyDialer != nil {
			dialer = proxyDialer
		}
	}
	return &utlsRoundTripper{
		dialer:              dialer,
		dialTimeout:         utlsDialTimeout,
		tlsHandshakeTimeout: utlsTLSHandshakeTimeout,
		sessions:            tls.NewLRUClientSessionCache(utlsSessionCacheCapacity),
		connections:         make(map[string]*utlsConnection),
	}
}

func withUtlsStageTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}

func utlsStageContextError(ctx context.Context) error {
	if errContext := ctx.Err(); errContext != nil {
		return errContext
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func closeUtlsConnection(conn net.Conn, stage string, stageErr error) error {
	if conn == nil {
		return fmt.Errorf("utls: %s: %w", stage, stageErr)
	}
	if errClose := conn.Close(); errClose != nil {
		return fmt.Errorf("utls: %s: %w; close connection: %v", stage, stageErr, errClose)
	}
	return fmt.Errorf("utls: %s: %w", stage, stageErr)
}

func (t *utlsRoundTripper) dialConnection(ctx context.Context, addr string) (net.Conn, error) {
	contextDialer, ok := t.dialer.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("utls: dialer does not support context cancellation")
	}

	dialCtx, cancelDial := withUtlsStageTimeout(ctx, t.dialTimeout)
	defer cancelDial()

	conn, errDial := contextDialer.DialContext(dialCtx, "tcp", addr)
	if conn != nil {
		conn = &onceCloseConn{Conn: conn}
	}
	if errDial != nil {
		if errContext := utlsStageContextError(dialCtx); errContext != nil {
			errDial = errContext
		}
		return nil, closeUtlsConnection(conn, "dial upstream", errDial)
	}
	if errContext := utlsStageContextError(dialCtx); errContext != nil {
		return nil, closeUtlsConnection(conn, "dial upstream", errContext)
	}
	return conn, nil
}

func runUtlsConnectionStage(ctx context.Context, conn net.Conn, timeout time.Duration, stage func(context.Context) error) error {
	stageCtx, cancelStage := withUtlsStageTimeout(ctx, timeout)
	defer cancelStage()

	if deadline, ok := stageCtx.Deadline(); ok {
		if errDeadline := conn.SetDeadline(deadline); errDeadline != nil {
			return fmt.Errorf("set connection deadline: %w", errDeadline)
		}
	}

	cancelDone := make(chan struct{})
	stopCancel := context.AfterFunc(stageCtx, func() {
		_ = conn.SetDeadline(time.Now())
		close(cancelDone)
	})
	errStage := stage(stageCtx)
	if !stopCancel() {
		<-cancelDone
	}

	if errContext := utlsStageContextError(stageCtx); errContext != nil {
		return errContext
	}
	if errStage != nil {
		return errStage
	}
	if errDeadline := conn.SetDeadline(time.Time{}); errDeadline != nil {
		return fmt.Errorf("clear connection deadline: %w", errDeadline)
	}
	return nil
}

func (t *utlsRoundTripper) createConnection(ctx context.Context, host, addr string) (*http2.ClientConn, error) {
	conn, errDial := t.dialConnection(ctx, addr)
	if errDial != nil {
		return nil, errDial
	}

	spec, errSpec := chromeTLSClientHelloSpec()
	if errSpec != nil {
		return nil, closeUtlsConnection(conn, "build Chrome ClientHello", errSpec)
	}
	tlsConn := tls.UClient(conn, newChromeTLSConfig(host, t.sessions), tls.HelloCustom)
	if errPreset := tlsConn.ApplyPreset(spec); errPreset != nil {
		return nil, closeUtlsConnection(conn, "apply Chrome ClientHello", errPreset)
	}

	errHandshake := runUtlsConnectionStage(ctx, conn, t.tlsHandshakeTimeout, tlsConn.HandshakeContext)
	if errHandshake != nil {
		return nil, closeUtlsConnection(conn, "TLS handshake", errHandshake)
	}

	tr := &http2.Transport{}
	h2Conn, errClientConn := tr.NewClientConn(tlsConn)
	if errClientConn != nil {
		if errClose := tlsConn.Close(); errClose != nil {
			return nil, fmt.Errorf("utls: initialize HTTP/2 connection: %w; close TLS connection: %v", errClientConn, errClose)
		}
		return nil, fmt.Errorf("utls: initialize HTTP/2 connection: %w", errClientConn)
	}

	return h2Conn, nil
}

// canServeRequest reports whether a pooled connection may take another request.
// A connection with work in flight is always eligible, because HTTP/2 streams
// are multiplexed; an idle connection must still be able to open a stream and
// must not have outlived the idle TTL.
func (c *utlsConnection) canServeRequest() bool {
	if c == nil || c.unpooled || c.client == nil {
		return false
	}
	if !c.client.CanTakeNewRequest() {
		return false
	}
	if c.inFlight == 0 && time.Since(c.idleSince) > utlsIdleConnectionTTL {
		return false
	}
	return true
}

func (c *utlsConnection) close() {
	if c == nil || c.client == nil {
		return
	}
	if errClose := c.client.Close(); errClose != nil {
		log.Debugf("utls: close pooled connection: %v", errClose)
	}
}

// acquireConnection returns a live connection for addr, reusing a pooled one
// when possible and dialling a new one otherwise.
func (t *utlsRoundTripper) acquireConnection(ctx context.Context, host, addr string) (*utlsConnection, error) {
	t.mu.Lock()
	if pooled := t.connections[addr]; pooled.canServeRequest() {
		pooled.inFlight++
		t.mu.Unlock()
		return pooled, nil
	}
	t.mu.Unlock()

	client, err := t.createConnection(ctx, host, addr)
	if err != nil {
		return nil, err
	}
	created := &utlsConnection{client: client, addr: addr, inFlight: 1}

	t.mu.Lock()
	defer t.mu.Unlock()
	if existing := t.connections[addr]; existing == nil || (existing.canServeRequest() == false && existing.inFlight == 0) {
		existing.close()
		t.connections[addr] = created
		return created, nil
	}
	// Another request already published a usable connection. Keep it for the
	// next request and close this one as soon as its stream finishes.
	created.unpooled = true
	return created, nil
}

// releaseConnection returns a connection to the pool, or closes it when it is
// no longer usable.
func (t *utlsRoundTripper) releaseConnection(conn *utlsConnection) {
	if conn == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if conn.inFlight > 0 {
		conn.inFlight--
	}
	conn.idleSince = time.Now()
	if conn.unpooled || t.connections[conn.addr] != conn {
		conn.close()
		return
	}
	if !conn.client.CanTakeNewRequest() {
		delete(t.connections, conn.addr)
		conn.close()
	}
}

// CloseIdleConnections closes every pooled connection that has no work in
// flight. It satisfies the cache eviction hook used for round trippers.
func (t *utlsRoundTripper) CloseIdleConnections() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for addr, conn := range t.connections {
		if conn.inFlight > 0 {
			continue
		}
		delete(t.connections, addr)
		conn.close()
	}
}

func (t *utlsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	hostname := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(hostname, port)

	conn, err := t.acquireConnection(req.Context(), hostname, addr)
	if err != nil {
		return nil, err
	}

	resp, err := conn.client.RoundTrip(req)
	if err != nil {
		t.releaseConnection(conn)
		return nil, err
	}
	if resp == nil {
		t.releaseConnection(conn)
		return nil, fmt.Errorf("utls: upstream returned an empty response")
	}
	if resp.Body == nil {
		resp.Body = http.NoBody
	}
	resp.Body = &releaseConnectionBody{
		ReadCloser: resp.Body,
		release:    func() { t.releaseConnection(conn) },
	}
	return resp, nil
}

// claudeCodeSessionCacheCapacity bounds the per-transport TLS session cache for
// the Anthropic inference plane.
const claudeCodeSessionCacheCapacity = 32

// newClaudeCodeTLSConfig builds the uTLS config for one inference-plane dial.
//
// OmitEmptyPsk keeps the pre_shared_key extension silent until a session is
// cached, so an unresumed ClientHello stays byte-identical to the captured
// native handshake. PreferSkipResumptionOnNilExtension turns uTLS's HelloCustom
// "resume without the matching extension" panic into a skipped resumption.
func newClaudeCodeTLSConfig(host string, sessionCache tls.ClientSessionCache) *tls.Config {
	return &tls.Config{
		ServerName:                         host,
		ClientSessionCache:                 sessionCache,
		OmitEmptyPsk:                       true,
		PreferSkipResumptionOnNilExtension: true,
	}
}

// claudeCodeTLSClientHelloSpec reproduces the deterministic Node/OpenSSL
// ClientHello emitted by Claude Code 2.1.220 on macOS arm64. Keep this spec in
// sync with a fresh native capture whenever the advertised Claude Code version
// changes.
func claudeCodeTLSClientHelloSpec() *tls.ClientHelloSpec {
	return &tls.ClientHelloSpec{
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []uint8{0},
		Extensions: []tls.TLSExtension{
			&tls.SNIExtension{},
			&tls.ExtendedMasterSecretExtension{},
			&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
			&tls.SupportedCurvesExtension{Curves: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{0}},
			&tls.SessionTicketExtension{},
			&tls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
			&tls.StatusRequestExtension{},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
				tls.PKCS1WithSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.PSSWithSHA384,
				tls.PKCS1WithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA512,
				tls.PKCS1WithSHA1,
			}},
			&tls.SCTExtension{},
			&tls.KeyShareExtension{KeyShares: []tls.KeyShare{{Group: tls.X25519}}},
			&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
			&tls.SupportedVersionsExtension{Versions: []uint16{tls.VersionTLS13, tls.VersionTLS12}},
			&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
			// pre_shared_key MUST be the final extension (RFC 8446 4.2.11), after
			// padding. It contributes zero bytes until a cached session exists.
			&tls.UtlsPreSharedKeyExtension{},
		},
	}
}

// newChromeTLSConfig builds the uTLS config for one browser-profile dial.
//
// OmitEmptyPsk keeps the pre_shared_key extension silent until a session is
// cached, so a first ClientHello stays byte-identical to a fresh Chrome
// handshake. PreferSkipResumptionOnNilExtension turns uTLS's "resume without
// the matching extension" panic into a skipped resumption.
func newChromeTLSConfig(host string, sessionCache tls.ClientSessionCache) *tls.Config {
	return &tls.Config{
		ServerName:                         host,
		ClientSessionCache:                 sessionCache,
		OmitEmptyPsk:                       true,
		PreferSkipResumptionOnNilExtension: true,
	}
}

// chromeTLSClientHelloSpec returns the ClientHello the Chrome profile sends.
//
// It is uTLS's stock Chrome parrot with one correction: the parrot carries no
// pre_shared_key extension, so a cached TLS session could never be resumed and
// every request would pay for a full handshake. The extension is appended last,
// which is where RFC 8446 requires it and where Chrome sends it, and it
// contributes zero bytes until a session exists.
func chromeTLSClientHelloSpec() (*tls.ClientHelloSpec, error) {
	spec, errSpec := tls.UTLSIdToSpec(tls.HelloChrome_Auto)
	if errSpec != nil {
		return nil, fmt.Errorf("utls: resolve Chrome ClientHello: %w", errSpec)
	}
	spec.Extensions = append(spec.Extensions, &tls.UtlsPreSharedKeyExtension{})
	return &spec, nil
}

const claudeCodeRoundTripperCacheCapacity = 64

var claudeCodeRoundTripperCache = internalcache.NewBoundedLRU[string, http.RoundTripper](
	claudeCodeRoundTripperCacheCapacity,
	func(_ string, roundTripper http.RoundTripper) {
		if transport, ok := roundTripper.(interface{ CloseIdleConnections() }); ok {
			transport.CloseIdleConnections()
		}
	},
)

const chromeRoundTripperCacheCapacity = 64

var chromeRoundTripperCache = internalcache.NewBoundedLRU[string, http.RoundTripper](
	chromeRoundTripperCacheCapacity,
	func(_ string, roundTripper http.RoundTripper) {
		if transport, ok := roundTripper.(interface{ CloseIdleConnections() }); ok {
			transport.CloseIdleConnections()
		}
	},
)

// cachedChromeRoundTripper keeps one browser-profile transport per proxy. Both
// the TLS session cache and the pooled HTTP/2 connection live on that
// transport, so without the cache every request would still start from an
// empty handshake.
func cachedChromeRoundTripper(proxyURL string) http.RoundTripper {
	return chromeRoundTripperCache.GetOrAdd(proxyURL, func() http.RoundTripper {
		return newUtlsRoundTripper(proxyURL)
	})
}

var claudeCodeMessagesHeaderOrder = []string{
	"Accept",
	"Authorization",
	"Content-Type",
	"User-Agent",
	"X-Claude-Code-Session-Id",
	"X-Stainless-Arch",
	"X-Stainless-Lang",
	"X-Stainless-OS",
	"X-Stainless-Package-Version",
	"X-Stainless-Retry-Count",
	"X-Stainless-Runtime",
	"X-Stainless-Runtime-Version",
	"X-Stainless-Timeout",
	"anthropic-beta",
	"anthropic-dangerous-direct-browser-access",
	"anthropic-version",
	"x-app",
	"x-client-request-id",
	"Connection",
	"Host",
	"Accept-Encoding",
	"Content-Length",
}

var claudeCodeCountTokensHeaderOrder = []string{
	"Accept",
	"Authorization",
	"Content-Type",
	"User-Agent",
	"X-Claude-Code-Session-Id",
	"X-Stainless-Arch",
	"X-Stainless-Lang",
	"X-Stainless-OS",
	"X-Stainless-Package-Version",
	"X-Stainless-Retry-Count",
	"X-Stainless-Runtime",
	"X-Stainless-Runtime-Version",
	"anthropic-beta",
	"anthropic-dangerous-direct-browser-access",
	"anthropic-version",
	"x-app",
	"x-client-request-id",
	"Connection",
	"Host",
	"Accept-Encoding",
	"Content-Length",
}

func claudeCodeRequestHeaderOrder(_, requestTarget string) []string {
	if strings.HasPrefix(requestTarget, "/v1/messages/count_tokens") {
		return claudeCodeCountTokensHeaderOrder
	}
	return claudeCodeMessagesHeaderOrder
}

func cachedClaudeCodeRoundTripper(proxyURL string) http.RoundTripper {
	return claudeCodeRoundTripperCache.GetOrAdd(proxyURL, func() http.RoundTripper {
		return newClaudeCodeRoundTripper(proxyURL)
	})
}

func newClaudeCodeRoundTripper(proxyURL string) http.RoundTripper {
	// The cache is scoped to this round tripper, which is already keyed by proxy,
	// so resumption never crosses proxy boundaries.
	sessionCache := tls.NewLRUClientSessionCache(claudeCodeSessionCacheCapacity)
	var dialer proxy.Dialer = proxy.Direct
	if proxyURL != "" {
		proxyDialer, mode, errBuild := proxyutil.BuildDialer(proxyURL)
		if errBuild != nil {
			log.Errorf("claude tls: failed to configure proxy dialer for %q: %v", proxyutil.Redact(proxyURL), errBuild)
		} else if mode != proxyutil.ModeInherit && proxyDialer != nil {
			dialer = proxyDialer
		}
	}

	transport := &http.Transport{
		ForceAttemptHTTP2: false,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var (
				conn net.Conn
				err  error
			)
			if contextDialer, ok := dialer.(proxy.ContextDialer); ok {
				conn, err = contextDialer.DialContext(ctx, network, addr)
			} else {
				conn, err = dialer.Dial(network, addr)
			}
			if err != nil {
				return nil, fmt.Errorf("claude tls: dial upstream: %w", err)
			}

			host, _, errSplit := net.SplitHostPort(addr)
			if errSplit != nil {
				if errClose := conn.Close(); errClose != nil {
					log.Debugf("claude tls: close failed connection: %v", errClose)
				}
				return nil, fmt.Errorf("claude tls: split upstream address: %w", errSplit)
			}
			tlsConn := tls.UClient(conn, newClaudeCodeTLSConfig(host, sessionCache), tls.HelloCustom)
			if errPreset := tlsConn.ApplyPreset(claudeCodeTLSClientHelloSpec()); errPreset != nil {
				if errClose := tlsConn.Close(); errClose != nil {
					log.Debugf("claude tls: close connection after preset failure: %v", errClose)
				}
				return nil, fmt.Errorf("claude tls: apply Claude Code ClientHello: %w", errPreset)
			}
			if errHandshake := tlsConn.HandshakeContext(ctx); errHandshake != nil {
				if errClose := tlsConn.Close(); errClose != nil {
					log.Debugf("claude tls: close connection after handshake failure: %v", errClose)
				}
				return nil, fmt.Errorf("claude tls: handshake upstream: %w", errHandshake)
			}
			return httpwire.NewOrderedRequestConn(tlsConn, claudeCodeRequestHeaderOrder), nil
		},
	}
	return transport
}

// fallbackRoundTripper uses provider-specific TLS fingerprints for protected
// HTTPS hosts and falls back to the standard transport for all other requests.
type fallbackRoundTripper struct {
	anthropic http.RoundTripper
	chrome    http.RoundTripper
	fallback  http.RoundTripper
}

func (f *fallbackRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if IsAnthropicUpstreamURL(req.URL) {
		return f.anthropic.RoundTrip(req)
	}
	if req.URL.Scheme == "https" && strings.EqualFold(req.URL.Hostname(), "chatgpt.com") {
		return f.chrome.RoundTrip(req)
	}
	return f.fallback.RoundTrip(req)
}

// NewUtlsHTTPClient creates an HTTP client using provider-specific TLS
// fingerprints for protected hosts. It uses Claude Code's Node/OpenSSL profile
// for Anthropic and a Chrome profile for ChatGPT, with a standard-transport
// fallback for other hosts.
func NewUtlsHTTPClient(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth, timeout time.Duration) *http.Client {
	var proxyURL string
	if auth != nil {
		proxyURL = strings.TrimSpace(auth.ProxyURL)
	}
	if proxyURL == "" && cfg != nil {
		proxyURL = strings.TrimSpace(cfg.ProxyURL)
	}

	var ctxRoundTripper http.RoundTripper
	if ctx != nil {
		ctxRoundTripper, _ = ctx.Value("cliproxy.roundtripper").(http.RoundTripper)
	}

	var chromeRT http.RoundTripper = cachedChromeRoundTripper(proxyURL)
	var anthropicRT http.RoundTripper = cachedClaudeCodeRoundTripper(proxyURL)
	var standardTransport http.RoundTripper = http.DefaultTransport
	if proxyURL != "" {
		if transport := buildProxyTransport(proxyURL); transport != nil {
			standardTransport = transport
		}
	} else if ctxRoundTripper != nil {
		chromeRT = ctxRoundTripper
		anthropicRT = ctxRoundTripper
		standardTransport = ctxRoundTripper
	}

	client := &http.Client{
		Transport: &fallbackRoundTripper{
			anthropic: anthropicRT,
			chrome:    chromeRT,
			fallback:  standardTransport,
		},
	}
	if timeout > 0 {
		client.Timeout = timeout
	}
	return client
}
