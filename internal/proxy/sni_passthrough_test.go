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

// newLocalhostTLSCert returns a self-signed cert valid for "localhost" and
// 127.0.0.1, plus a pool trusting it.
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

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf:        parsed,
	}, pool
}

// startEchoTLSServer starts a TLS server on 127.0.0.1:0 that responds to any
// HTTP/1.1 request with "echo <path>\n". Returns the "host:port" address.
func startEchoTLSServer(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "echo %s\n", r.URL.Path)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

// startSNIPassthroughProxy builds a Proxy in sni-only mode, listens on a
// random port, and for each connection invokes serveSNIPassthrough with the
// upstream dial rerouted to the test echo server (via sniUpstreamPort).
// Returns the proxy listener addr and a snapshot accessor for audit records.
func startSNIPassthroughProxy(t *testing.T, allowed []string, upstream string) (listenAddr string, getResults func() []transform.PipelineResult) {
	t.Helper()

	_, upstreamPort, err := net.SplitHostPort(upstream)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	al, err := allowlist.New(allowed, nil, &staticResolver{hosts: map[string][]string{
		"localhost":       {"127.0.0.1"},
		"blocked.example": {"127.0.0.1"},
		"allowed.example": {"127.0.0.1"},
	}})
	require.NoError(t, err)

	pipeline := transform.NewPipeline([]transform.Transformer{al}, transform.BodyLimits{}, logger)

	var mu sync.Mutex
	var results []transform.PipelineResult
	pipeline.SetAuditFunc(func(r *transform.PipelineResult) {
		mu.Lock()
		defer mu.Unlock()
		results = append(results, *r)
	})

	holder := transform.NewPipelineHolder(pipeline)

	p := New(Options{
		HTTPAddr:  "127.0.0.1:0",
		HTTPSAddr: "127.0.0.1:0",
		TLSMode:   "sni-only",
		Pipeline:  holder,
		Logger:    logger,
	})
	p.sniUpstreamPort = upstreamPort

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_ = p.serveSNIPassthrough(c)
			}(conn)
		}
	}()

	return ln.Addr().String(), func() []transform.PipelineResult {
		mu.Lock()
		defer mu.Unlock()
		out := make([]transform.PipelineResult, len(results))
		copy(out, results)
		return out
	}
}

func TestSNIPassthrough_HappyPath(t *testing.T) {
	cert, pool := newLocalhostTLSCert(t)
	upstream := startEchoTLSServer(t, cert)

	proxyAddr, getResults := startSNIPassthroughProxy(t, []string{"localhost"}, upstream)

	conn, err := tls.Dial("tcp", proxyAddr, &tls.Config{
		ServerName: "localhost",
		RootCAs:    pool,
	})
	require.NoError(t, err)

	_, err = conn.Write([]byte("GET /hello HTTP/1.1\r\nHost: localhost\r\n\r\n"))
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, "echo /hello\n", string(body))

	// Close the client conn so the proxy's bidi copy drains and emits audit.
	_ = conn.Close()

	require.Eventually(t, func() bool {
		return len(getResults()) > 0
	}, 2*time.Second, 10*time.Millisecond)

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
	cert, _ := newLocalhostTLSCert(t)
	upstream := startEchoTLSServer(t, cert)

	proxyAddr, getResults := startSNIPassthroughProxy(t, []string{"allowed.example"}, upstream)

	conn, err := net.Dial("tcp", proxyAddr)
	require.NoError(t, err)
	defer conn.Close()

	// Start a tls handshake to the proxy with an SNI not on the allowlist.
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "blocked.example",
		InsecureSkipVerify: true,
	})
	handshakeErr := tlsConn.Handshake()
	require.Error(t, handshakeErr, "handshake should fail because proxy closes conn")

	require.Eventually(t, func() bool {
		return len(getResults()) > 0
	}, 2*time.Second, 10*time.Millisecond)

	results := getResults()
	require.Len(t, results, 1)
	require.Equal(t, transform.ModeSNIOnly, results[0].Mode)
	require.Equal(t, "blocked.example", results[0].SNI)
	require.Equal(t, transform.ActionReject, results[0].Action)
}

func TestSNIPassthrough_NoSNI(t *testing.T) {
	cert, _ := newLocalhostTLSCert(t)
	upstream := startEchoTLSServer(t, cert)

	proxyAddr, getResults := startSNIPassthroughProxy(t, []string{"localhost"}, upstream)

	conn, err := net.Dial("tcp", proxyAddr)
	require.NoError(t, err)
	defer conn.Close()

	// Client with no ServerName → ClientHello with no SNI extension.
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
	})
	_ = tlsConn.Handshake() // will fail; proxy rejects empty SNI

	require.Eventually(t, func() bool {
		return len(getResults()) > 0
	}, 2*time.Second, 10*time.Millisecond)

	results := getResults()
	require.Len(t, results, 1)
	require.Equal(t, "", results[0].SNI)
	require.Equal(t, transform.ActionReject, results[0].Action)
}

func TestSNIPassthrough_MalformedClientHello(t *testing.T) {
	cert, _ := newLocalhostTLSCert(t)
	upstream := startEchoTLSServer(t, cert)

	proxyAddr, getResults := startSNIPassthroughProxy(t, []string{"localhost"}, upstream)

	conn, err := net.Dial("tcp", proxyAddr)
	require.NoError(t, err)
	_, _ = conn.Write([]byte("definitely not a tls client hello"))

	// Proxy should close. Give it a moment, then confirm no audit record
	// claims success.
	time.Sleep(200 * time.Millisecond)
	_ = conn.Close()

	results := getResults()
	// Malformed input is rejected before the pipeline runs, so no audit
	// record is emitted.
	require.Len(t, results, 0)
}

func TestSNIPassthrough_ShutdownClosesInFlight(t *testing.T) {
	cert, pool := newLocalhostTLSCert(t)
	upstream := startEchoTLSServer(t, cert)
	_, upstreamPort, err := net.SplitHostPort(upstream)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	al, err := allowlist.New([]string{"localhost"}, nil, &staticResolver{hosts: map[string][]string{
		"localhost": {"127.0.0.1"},
	}})
	require.NoError(t, err)
	pipeline := transform.NewPipeline([]transform.Transformer{al}, transform.BodyLimits{}, logger)
	holder := transform.NewPipelineHolder(pipeline)

	p := New(Options{
		HTTPAddr:  "127.0.0.1:0",
		HTTPSAddr: "127.0.0.1:0",
		TLSMode:   "sni-only",
		Pipeline:  holder,
		Logger:    logger,
	})
	p.sniUpstreamPort = upstreamPort

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	done := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			close(done)
			return
		}
		_ = p.serveSNIPassthrough(conn)
		close(done)
	}()

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		ServerName: "localhost",
		RootCAs:    pool,
	})
	require.NoError(t, err)
	defer conn.Close()

	// Handshake is complete and connection is idle — proxyBidi goroutines
	// are blocked on reads in both directions. Calling Shutdown should
	// cancel shutdownCtx and close both conns so serveSNIPassthrough returns.
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
	// A full end-to-end test via the CONNECT tunnel path in sni-only mode.
	cert, pool := newLocalhostTLSCert(t)
	upstream := startEchoTLSServer(t, cert)
	upstreamHost, upstreamPort, err := net.SplitHostPort(upstream)
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", upstreamHost)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	al, err := allowlist.New([]string{"localhost"}, nil, &staticResolver{hosts: map[string][]string{
		"localhost": {"127.0.0.1"},
	}})
	require.NoError(t, err)
	pipeline := transform.NewPipeline([]transform.Transformer{al}, transform.BodyLimits{}, logger)
	holder := transform.NewPipelineHolder(pipeline)

	p := New(Options{
		HTTPAddr:   "127.0.0.1:0",
		HTTPSAddr:  "127.0.0.1:0",
		TunnelAddr: "127.0.0.1:0",
		TLSMode:    "sni-only",
		Pipeline:   holder,
		Logger:     logger,
	})
	p.sniUpstreamPort = upstreamPort

	tunnelLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	tunnelAddr := tunnelLn.Addr().String()
	p.tunnelListener = tunnelLn
	go func() {
		for {
			conn, err := tunnelLn.Accept()
			if err != nil {
				return
			}
			go p.handleTunnel(conn)
		}
	}()
	t.Cleanup(func() {
		_ = tunnelLn.Close()
		close(p.tunnelDone)
	})

	// Connect to tunnel and send CONNECT for localhost:upstreamPort.
	conn, err := net.Dial("tcp", tunnelAddr)
	require.NoError(t, err)
	defer conn.Close()

	connectReq := fmt.Sprintf("CONNECT localhost:%s HTTP/1.1\r\nHost: localhost:%s\r\n\r\n", upstreamPort, upstreamPort)
	_, err = conn.Write([]byte(connectReq))
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode)

	// Now do TLS over the tunnel, verifying it TCP-passthroughs rather than
	// MITMs (cert chain must validate against the upstream's real cert).
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: "localhost",
		RootCAs:    pool,
	})
	require.NoError(t, tlsConn.Handshake())

	_, err = tlsConn.Write([]byte("GET /tunneled HTTP/1.1\r\nHost: localhost\r\n\r\n"))
	require.NoError(t, err)

	bufR := bufio.NewReader(tlsConn)
	upResp, err := http.ReadResponse(bufR, nil)
	require.NoError(t, err)
	defer upResp.Body.Close()
	require.Equal(t, 200, upResp.StatusCode)
	body, err := io.ReadAll(upResp.Body)
	require.NoError(t, err)
	require.Equal(t, "echo /tunneled\n", string(body))
}

// TestSNIPassthrough_IgnoresCONNECTPort verifies that in sni-only mode a
// client-supplied CONNECT port does not influence the upstream port the
// proxy dials. This prevents a malicious client from pivoting an
// allowlisted hostname onto a different port (e.g. SMTP).
func TestSNIPassthrough_IgnoresCONNECTPort(t *testing.T) {
	cert, pool := newLocalhostTLSCert(t)
	upstream := startEchoTLSServer(t, cert)
	_, upstreamPort, err := net.SplitHostPort(upstream)
	require.NoError(t, err)

	// Start a second listener that we expect NEVER to be dialed. If the
	// proxy respected the CONNECT port, it would try to connect here.
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

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	al, err := allowlist.New([]string{"localhost"}, nil, &staticResolver{hosts: map[string][]string{
		"localhost": {"127.0.0.1"},
	}})
	require.NoError(t, err)
	pipeline := transform.NewPipeline([]transform.Transformer{al}, transform.BodyLimits{}, logger)
	holder := transform.NewPipelineHolder(pipeline)

	p := New(Options{
		HTTPAddr:   "127.0.0.1:0",
		HTTPSAddr:  "127.0.0.1:0",
		TunnelAddr: "127.0.0.1:0",
		TLSMode:    "sni-only",
		Pipeline:   holder,
		Logger:     logger,
	})
	p.sniUpstreamPort = upstreamPort // proxy should dial here, not decoyPort

	tunnelLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	tunnelAddr := tunnelLn.Addr().String()
	p.tunnelListener = tunnelLn
	go func() {
		for {
			conn, err := tunnelLn.Accept()
			if err != nil {
				return
			}
			go p.handleTunnel(conn)
		}
	}()
	t.Cleanup(func() {
		_ = tunnelLn.Close()
		close(p.tunnelDone)
	})

	// Client CONNECTs to localhost:decoyPort but the proxy should ignore
	// that port and dial upstream on sniUpstreamPort.
	conn, err := net.Dial("tcp", tunnelAddr)
	require.NoError(t, err)
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "CONNECT localhost:%s HTTP/1.1\r\nHost: localhost:%s\r\n\r\n", decoyPort, decoyPort)
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode)

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: "localhost",
		RootCAs:    pool,
	})
	require.NoError(t, tlsConn.Handshake(), "handshake should succeed against the real upstream, not the decoy")

	select {
	case <-decoyHit:
		t.Fatal("proxy dialed the CONNECT port instead of the fixed sni upstream port")
	case <-time.After(300 * time.Millisecond):
		// no connection to decoy, as expected.
	}
}
