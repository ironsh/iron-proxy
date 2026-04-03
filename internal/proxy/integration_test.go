package proxy

import (
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
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/certcache"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/allowlist"
)

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
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Integration Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	certCache, err := certcache.NewFromCA(caCert, caKey, 100, 72*time.Hour)
	require.NoError(t, err)

	// 3. Build transform pipeline with allowlist
	al, err := allowlist.New(
		[]string{fakeHost},
		nil,
		&staticResolver{},
	)
	require.NoError(t, err)

	pipeline := transform.NewPipeline([]transform.Transformer{al}, transform.BodyLimits{}, logger)

	// 4. Start proxy with HTTPS
	p := New("127.0.0.1:0", "127.0.0.1:0", certCache, pipeline, logger)

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
	origTransport := upstreamTransport
	upstreamTransport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		// Redirect all dials to the actual upstream address
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, upstreamAddr)
		},
	}
	defer func() { upstreamTransport = origTransport }()

	// 7. Test: allowed request through HTTPS proxy
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caPool,
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
