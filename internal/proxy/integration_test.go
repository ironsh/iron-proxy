package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/certcache"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/allowlist"
)

// integrationCA bundles the test CA certificate, cert cache, and trust pool.
type integrationCA struct {
	certCache *certcache.Cache
	caPool    *x509.CertPool
}

// newIntegrationCA generates a test CA and returns the cert cache and CA pool.
func newIntegrationCA(t *testing.T) integrationCA {
	t.Helper()

	caCert, caKey := generateTestCA(t)
	cache, err := certcache.NewFromCA(caCert, caKey, 100, 72*time.Hour)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	return integrationCA{certCache: cache, caPool: pool}
}

// startTunnelIntegrationProxy creates a proxy with an allowlist and tunnel
// listener, returning the proxy, tunnel address, and CA pool.
func startTunnelIntegrationProxy(t *testing.T, allowedHosts []string, logger *slog.Logger) (*Proxy, string, *x509.CertPool) {
	t.Helper()

	ca := newIntegrationCA(t)

	al, err := allowlist.New(allowedHosts, nil, &staticResolver{})
	require.NoError(t, err)
	pipeline := transform.NewPipeline([]transform.Transformer{al}, transform.BodyLimits{}, logger)

	p := New("127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0", ca.certCache, pipeline, nil, logger)

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
		tunnelLn.Close()
		close(p.tunnelDone)
	})

	return p, tunnelAddr, ca.caPool
}

// TestIntegration_DNSToProxyToUpstream is an end-to-end test that exercises:
// DNS interception -> TLS MITM -> allowlist transform -> upstream -> response.
func TestIntegration_DNSToProxyToUpstream(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// 1. Start an upstream HTTPS server
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "true")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "integration test response")
	}))
	defer upstream.Close()

	upstreamAddr := upstream.Listener.Addr().String()

	// We use a fake hostname for SNI since the proxy needs a domain, not an IP.
	const fakeHost = "test-upstream.example.com"

	// 2. Generate CA and cert cache
	ca := newIntegrationCA(t)

	// 3. Build transform pipeline with allowlist
	al, err := allowlist.New(
		[]string{fakeHost},
		nil,
		&staticResolver{},
	)
	require.NoError(t, err)

	pipeline := transform.NewPipeline([]transform.Transformer{al}, transform.BodyLimits{}, logger)

	// 4. Start proxy with HTTPS
	p := New("127.0.0.1:0", "127.0.0.1:0", "", ca.certCache, pipeline, nil, logger)

	// Start HTTP listener
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	httpAddr := httpLn.Addr().String()

	// Start HTTPS listener
	httpsLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	tlsLn := tls.NewListener(httpsLn, p.httpsServer.TLSConfig)
	httpsAddr := httpsLn.Addr().String()

	go func() { _ = p.httpServer.Serve(httpLn) }()
	go func() { _ = p.httpsServer.Serve(tlsLn) }()
	t.Cleanup(func() {
		_ = p.httpServer.Close()
		_ = p.httpsServer.Close()
	})

	// 6. Override upstream transport to route fakeHost to the real upstream
	p.transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		// Redirect all dials to the actual upstream address
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, upstreamAddr)
		},
	}

	// 7. Test: allowed request through HTTPS proxy
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    ca.caPool,
				ServerName: fakeHost,
			},
		},
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/test", httpsAddr), nil)
	require.NoError(t, err)
	req.Host = fakeHost

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "true", resp.Header.Get("X-Upstream"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "integration test response", string(body))

	// 8. Test: denied request (host not in allowlist)
	req2, err := http.NewRequest("GET", fmt.Sprintf("http://%s/test", httpAddr), nil)
	require.NoError(t, err)
	req2.Host = "evil.example.com"

	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err)
	defer resp2.Body.Close()

	require.Equal(t, http.StatusForbidden, resp2.StatusCode)
}

// TestIntegration_CONNECT exercises the full CONNECT tunnel flow:
// client CONNECT -> tunnel handshake -> TLS MITM -> allowlist -> upstream -> response.
func TestIntegration_CONNECT(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// 1. Start upstream HTTPS server
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "true")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "connect integration response")
	}))
	defer upstream.Close()
	upstreamAddr := upstream.Listener.Addr().String()

	const allowedHost = "allowed.example.com"
	const deniedHost = "denied.example.com"

	p, tunnelAddr, caPool := startTunnelIntegrationProxy(t, []string{allowedHost}, logger)

	// Override transport to route all dials to the real upstream
	p.transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, upstreamAddr)
		},
	}

	// 2. Test: allowed CONNECT -> TLS MITM -> success
	t.Run("allowed", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
		require.NoError(t, err)
		defer conn.Close()

		// Send CONNECT
		_, err = fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", allowedHost, allowedHost)
		require.NoError(t, err)

		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// TLS handshake over the tunnel
		tlsConn := tls.Client(conn, &tls.Config{
			RootCAs:    caPool,
			ServerName: allowedHost,
		})
		defer func() { _ = tlsConn.Close() }()
		require.NoError(t, tlsConn.Handshake())

		// HTTP request over the TLS tunnel
		req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/test", allowedHost), nil)
		require.NoError(t, err)
		require.NoError(t, req.Write(tlsConn))

		resp2, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
		require.NoError(t, err)
		defer resp2.Body.Close()

		require.Equal(t, http.StatusOK, resp2.StatusCode)
		require.Equal(t, "true", resp2.Header.Get("X-Upstream"))
		body, err := io.ReadAll(resp2.Body)
		require.NoError(t, err)
		require.Equal(t, "connect integration response", string(body))
	})

	// 3. Test: denied CONNECT -> 403
	t.Run("denied", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
		require.NoError(t, err)
		defer conn.Close()

		_, err = fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", deniedHost, deniedHost)
		require.NoError(t, err)

		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	// 4. Test: allowed CONNECT -> plain HTTP (non-TLS)
	t.Run("allowed_plain_http", func(t *testing.T) {
		// Start a plain HTTP upstream
		plainUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, "plain http response")
		}))
		defer plainUpstream.Close()
		plainAddr := plainUpstream.Listener.Addr().String()

		// Override transport for this sub-test to route to the plain upstream
		origTransport := p.transport
		p.transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, plainAddr)
			},
		}
		defer func() { p.transport = origTransport }()

		conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
		require.NoError(t, err)
		defer conn.Close()

		_, err = fmt.Fprintf(conn, "CONNECT %s:80 HTTP/1.1\r\nHost: %s:80\r\n\r\n", allowedHost, allowedHost)
		require.NoError(t, err)

		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// Send plain HTTP through the tunnel
		_, err = fmt.Fprintf(conn, "GET /test HTTP/1.1\r\nHost: %s\r\n\r\n", allowedHost)
		require.NoError(t, err)

		resp2, err := http.ReadResponse(br, nil)
		require.NoError(t, err)
		defer resp2.Body.Close()

		require.Equal(t, http.StatusOK, resp2.StatusCode)
		body, err := io.ReadAll(resp2.Body)
		require.NoError(t, err)
		require.Equal(t, "plain http response", string(body))
	})
}

// TestIntegration_SOCKS5 exercises the full SOCKS5 tunnel flow:
// client SOCKS5 -> tunnel handshake -> TLS MITM -> allowlist -> upstream -> response.
func TestIntegration_SOCKS5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// 1. Start upstream HTTPS server
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "true")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "socks5 integration response")
	}))
	defer upstream.Close()
	upstreamAddr := upstream.Listener.Addr().String()

	const allowedHost = "allowed.example.com"
	const deniedHost = "denied.example.com"

	p, tunnelAddr, caPool := startTunnelIntegrationProxy(t, []string{allowedHost}, logger)

	// Override transport to route all dials to the real upstream
	p.transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, upstreamAddr)
		},
	}

	// Helper: perform SOCKS5 handshake with domain-name address type
	socks5Connect := func(t *testing.T, conn net.Conn, host string, port uint16) {
		t.Helper()

		// Auth: offer no-auth
		_, err := conn.Write([]byte{0x05, 0x01, 0x00})
		require.NoError(t, err)

		authResp := make([]byte, 2)
		_, err = io.ReadFull(conn, authResp)
		require.NoError(t, err)
		require.Equal(t, []byte{0x05, 0x00}, authResp)

		// Connect request with domain name
		req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
		req = append(req, []byte(host)...)
		portBuf := make([]byte, 2)
		portBuf[0] = byte(port >> 8)
		portBuf[1] = byte(port)
		req = append(req, portBuf...)
		_, err = conn.Write(req)
		require.NoError(t, err)
	}

	readSocks5Reply := func(t *testing.T, conn net.Conn) byte {
		t.Helper()
		reply := make([]byte, 10) // IPv4 reply is always 10 bytes
		_, err := io.ReadFull(conn, reply)
		require.NoError(t, err)
		require.Equal(t, byte(0x05), reply[0])
		return reply[1] // status
	}

	// 2. Test: allowed SOCKS5 -> TLS MITM -> success
	t.Run("allowed_tls", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
		require.NoError(t, err)
		defer conn.Close()

		socks5Connect(t, conn, allowedHost, 443)
		status := readSocks5Reply(t, conn)
		require.Equal(t, byte(0x00), status, "expected SOCKS5 success")

		// TLS handshake
		tlsConn := tls.Client(conn, &tls.Config{
			RootCAs:    caPool,
			ServerName: allowedHost,
		})
		defer func() { _ = tlsConn.Close() }()
		require.NoError(t, tlsConn.Handshake())

		// HTTP request
		req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/test", allowedHost), nil)
		require.NoError(t, err)
		require.NoError(t, req.Write(tlsConn))

		resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, "true", resp.Header.Get("X-Upstream"))
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, "socks5 integration response", string(body))
	})

	// 3. Test: denied SOCKS5 -> connection not allowed
	t.Run("denied", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
		require.NoError(t, err)
		defer conn.Close()

		socks5Connect(t, conn, deniedHost, 443)
		status := readSocks5Reply(t, conn)
		require.Equal(t, byte(0x02), status, "expected SOCKS5 connection not allowed")
	})

	// 4. Test: allowed SOCKS5 -> plain HTTP
	t.Run("allowed_plain_http", func(t *testing.T) {
		plainUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, "socks5 plain http")
		}))
		defer plainUpstream.Close()
		plainAddr := plainUpstream.Listener.Addr().String()

		origTransport := p.transport
		p.transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, plainAddr)
			},
		}
		defer func() { p.transport = origTransport }()

		conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
		require.NoError(t, err)
		defer conn.Close()

		socks5Connect(t, conn, allowedHost, 80)
		status := readSocks5Reply(t, conn)
		require.Equal(t, byte(0x00), status, "expected SOCKS5 success")

		// Send plain HTTP
		_, err = fmt.Fprintf(conn, "GET /test HTTP/1.1\r\nHost: %s\r\n\r\n", allowedHost)
		require.NoError(t, err)

		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, "socks5 plain http", string(body))
	})

	// 5. Test: non-HTTP/TLS protocol -> proxy closes the connection
	t.Run("unsupported_protocol", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
		require.NoError(t, err)
		defer conn.Close()

		socks5Connect(t, conn, allowedHost, 22)
		status := readSocks5Reply(t, conn)
		require.Equal(t, byte(0x00), status, "SOCKS5 handshake should succeed")

		// Send something that is neither TLS (0x16) nor an HTTP method (A-Z).
		// SSH banner starts with "SSH-", but let's send raw binary to be explicit.
		_, err = conn.Write([]byte{0x00, 0x01, 0x02, 0x03})
		require.NoError(t, err)

		// The proxy should close the connection without forwarding anything.
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
		buf := make([]byte, 1)
		_, err = conn.Read(buf)
		require.ErrorIs(t, err, io.EOF, "expected proxy to close the connection")
	})
}

// staticResolver is a test resolver that returns preconfigured addresses.
type staticResolver struct {
	hosts map[string][]string
}

func (r *staticResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	addrs, ok := r.hosts[host]
	if !ok {
		return nil, fmt.Errorf("no such host: %s", host)
	}
	return addrs, nil
}
