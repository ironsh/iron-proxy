package proxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/allowlist"
)

// startEchoTLSServer starts a TLS server on 127.0.0.1:0 that responds to any
// request with "echo <path>\n". Returns the host:port address and a cert pool
// trusting the server's self-signed leaf, whose SANs cover localhost,
// blocked.example, and allowed.example.
func startEchoTLSServer(t *testing.T) (addr string, pool *x509.CertPool) {
	t.Helper()
	cert, pool := newLocalhostTLSCert(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "echo %s\n", r.URL.Path)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String(), pool
}

func newLocalhostTLSCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "blocked.example", "allowed.example"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: key, Leaf: parsed}, pool
}

// buildSNIProxy creates a Proxy in sni-only mode with an allowlist permitting
// the given hostnames. Returns the proxy and an accessor for captured audit
// records. Callers are responsible for starting listeners and setting
// p.sniUpstreamPort if they want upstream dials to reach a test server.
func buildSNIProxy(t *testing.T, allowed []string, withTunnel bool) (*Proxy, func() []transform.PipelineResult) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	al, err := allowlist.New(allowed, nil)
	require.NoError(t, err)
	pipeline := transform.NewPipeline([]transform.Transformer{al}, transform.BodyLimits{}, logger)

	var mu sync.Mutex
	var results []transform.PipelineResult
	pipeline.SetAuditFunc(func(r *transform.PipelineResult) {
		mu.Lock()
		defer mu.Unlock()
		results = append(results, *r)
	})

	opts := Options{
		HTTPAddr:  "127.0.0.1:0",
		HTTPSAddr: "127.0.0.1:0",
		TLSMode:   "sni-only",
		Pipeline:  transform.NewPipelineHolder(pipeline),
		Logger:    logger,
	}
	if withTunnel {
		opts.TunnelAddr = "127.0.0.1:0"
	}
	p := New(opts)

	return p, func() []transform.PipelineResult {
		mu.Lock()
		defer mu.Unlock()
		out := make([]transform.PipelineResult, len(results))
		copy(out, results)
		return out
	}
}

// startAcceptLoop listens on 127.0.0.1:0 and spawns handle(conn) for each
// accepted connection. Returns the listener's address; the listener is closed
// via t.Cleanup.
func startAcceptLoop(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(conn)
		}
	}()
	return ln.Addr().String()
}

// startTunnelListener wires up a tunnel accept loop for the given proxy on
// 127.0.0.1:0 and returns the listener's address.
func startTunnelListener(t *testing.T, p *Proxy) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	p.tunnelListener = ln
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleTunnel(conn)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		close(p.tunnelDone)
	})
	return ln.Addr().String()
}

// startSNIPassthroughProxy builds a sni-only proxy wired to dial upstream and
// starts a local accept loop that drives serveSNIPassthrough. Returns the
// proxy's listener address and an audit-records accessor.
func startSNIPassthroughProxy(t *testing.T, allowed []string, upstream string) (string, func() []transform.PipelineResult) {
	t.Helper()
	_, upstreamPort, err := net.SplitHostPort(upstream)
	require.NoError(t, err)

	p, getResults := buildSNIProxy(t, allowed, false)
	p.sniUpstreamPort = upstreamPort

	addr := startAcceptLoop(t, func(c net.Conn) { _ = p.serveSNIPassthrough(c) })
	return addr, getResults
}

// connectAndHandshake opens a TCP connection to tunnelAddr, issues CONNECT to
// connectTarget, and completes a TLS handshake with ServerName=sni verified
// against pool. Returns the established TLS connection.
func connectAndHandshake(t *testing.T, tunnelAddr, connectTarget, sni string, pool *x509.CertPool) *tls.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", tunnelAddr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", connectTarget, connectTarget)
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode)

	tlsConn := tls.Client(conn, &tls.Config{ServerName: sni, RootCAs: pool})
	require.NoError(t, tlsConn.Handshake())
	return tlsConn
}

func TestSNIPassthrough_HappyPath(t *testing.T) {
	upstream, pool := startEchoTLSServer(t)
	proxyAddr, getResults := startSNIPassthroughProxy(t, []string{"localhost"}, upstream)

	conn, err := tls.Dial("tcp", proxyAddr, &tls.Config{ServerName: "localhost", RootCAs: pool})
	require.NoError(t, err)

	_, err = conn.Write([]byte("GET /hello HTTP/1.1\r\nHost: localhost\r\n\r\n"))
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, "echo /hello\n", string(body))

	// Close the client conn so the proxy's bidi copy drains and emits audit.
	_ = conn.Close()

	require.Eventually(t, func() bool { return len(getResults()) > 0 }, 2*time.Second, 10*time.Millisecond)

	results := getResults()
	require.Len(t, results, 1)
	require.Equal(t, transform.ModeSNIOnly, results[0].Mode)
	require.Equal(t, "localhost", results[0].SNI)
	require.Equal(t, "localhost", results[0].Host)
	require.Equal(t, "", results[0].Method)
	require.Equal(t, "", results[0].Path)
	require.Equal(t, transform.ActionContinue, results[0].Action)
}

func TestSNIPassthrough_AllowlistDeny(t *testing.T) {
	upstream, _ := startEchoTLSServer(t)
	proxyAddr, getResults := startSNIPassthroughProxy(t, []string{"allowed.example"}, upstream)

	conn, err := net.Dial("tcp", proxyAddr)
	require.NoError(t, err)
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{ServerName: "blocked.example", InsecureSkipVerify: true})
	require.Error(t, tlsConn.Handshake(), "handshake should fail because proxy closes conn")

	require.Eventually(t, func() bool { return len(getResults()) > 0 }, 2*time.Second, 10*time.Millisecond)

	results := getResults()
	require.Len(t, results, 1)
	require.Equal(t, transform.ModeSNIOnly, results[0].Mode)
	require.Equal(t, "blocked.example", results[0].SNI)
	require.Equal(t, transform.ActionReject, results[0].Action)
}

func TestSNIPassthrough_NoSNI(t *testing.T) {
	upstream, _ := startEchoTLSServer(t)
	proxyAddr, getResults := startSNIPassthroughProxy(t, []string{"localhost"}, upstream)

	conn, err := net.Dial("tcp", proxyAddr)
	require.NoError(t, err)
	defer conn.Close()

	// Client with no ServerName sends a ClientHello without an SNI extension.
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	_ = tlsConn.Handshake() // will fail; proxy rejects empty SNI

	require.Eventually(t, func() bool { return len(getResults()) > 0 }, 2*time.Second, 10*time.Millisecond)

	results := getResults()
	require.Len(t, results, 1)
	require.Equal(t, "", results[0].SNI)
	require.Equal(t, transform.ActionReject, results[0].Action)
}

func TestSNIPassthrough_MalformedClientHello(t *testing.T) {
	upstream, _ := startEchoTLSServer(t)
	proxyAddr, getResults := startSNIPassthroughProxy(t, []string{"localhost"}, upstream)

	conn, err := net.Dial("tcp", proxyAddr)
	require.NoError(t, err)
	_, _ = conn.Write([]byte("definitely not a tls client hello"))

	time.Sleep(200 * time.Millisecond)
	_ = conn.Close()

	// Malformed input is rejected before the pipeline runs, so no audit
	// record is emitted.
	require.Empty(t, getResults())
}

func TestSNIPassthrough_ShutdownClosesInFlight(t *testing.T) {
	upstream, pool := startEchoTLSServer(t)
	_, upstreamPort, err := net.SplitHostPort(upstream)
	require.NoError(t, err)

	p, _ := buildSNIProxy(t, []string{"localhost"}, false)
	p.sniUpstreamPort = upstreamPort

	done := make(chan struct{})
	addr := startAcceptLoop(t, func(c net.Conn) {
		_ = p.serveSNIPassthrough(c)
		close(done)
	})

	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: "localhost", RootCAs: pool})
	require.NoError(t, err)
	defer conn.Close()

	// Handshake is complete and connection is idle — proxyBidi goroutines
	// are blocked on reads in both directions. Shutdown should unblock them
	// by closing both conns.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, p.Shutdown(shutdownCtx))

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serveSNIPassthrough did not return after Shutdown")
	}
}

func TestSNIPassthrough_CONNECTTunnel(t *testing.T) {
	upstream, pool := startEchoTLSServer(t)
	_, upstreamPort, err := net.SplitHostPort(upstream)
	require.NoError(t, err)

	p, _ := buildSNIProxy(t, []string{"localhost"}, true)
	p.sniUpstreamPort = upstreamPort
	tunnelAddr := startTunnelListener(t, p)

	tlsConn := connectAndHandshake(t, tunnelAddr, "localhost:"+upstreamPort, "localhost", pool)

	_, err = tlsConn.Write([]byte("GET /tunneled HTTP/1.1\r\nHost: localhost\r\n\r\n"))
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "echo /tunneled\n", string(body))
}

// TestSNIPassthrough_IgnoresCONNECTPort verifies that a client-supplied
// CONNECT port does not influence the upstream port the proxy dials. This
// prevents a malicious client from pivoting an allowlisted hostname onto a
// different port (e.g. SMTP).
func TestSNIPassthrough_IgnoresCONNECTPort(t *testing.T) {
	upstream, pool := startEchoTLSServer(t)
	_, upstreamPort, err := net.SplitHostPort(upstream)
	require.NoError(t, err)

	// Start a second listener that we expect NEVER to be dialed.
	decoyLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer decoyLn.Close()
	_, decoyPort, err := net.SplitHostPort(decoyLn.Addr().String())
	require.NoError(t, err)

	decoyHit := make(chan struct{}, 1)
	go func() {
		conn, err := decoyLn.Accept()
		if err == nil {
			select {
			case decoyHit <- struct{}{}:
			default:
			}
			_ = conn.Close()
		}
	}()

	p, _ := buildSNIProxy(t, []string{"localhost"}, true)
	p.sniUpstreamPort = upstreamPort // proxy should dial here, not decoyPort
	tunnelAddr := startTunnelListener(t, p)

	// Client CONNECTs to localhost:decoyPort but the proxy should ignore
	// that port and dial upstream on sniUpstreamPort.
	_ = connectAndHandshake(t, tunnelAddr, "localhost:"+decoyPort, "localhost", pool)

	select {
	case <-decoyHit:
		t.Fatal("proxy dialed the CONNECT port instead of the fixed sni upstream port")
	case <-time.After(300 * time.Millisecond):
		// no connection to decoy, as expected.
	}
}
