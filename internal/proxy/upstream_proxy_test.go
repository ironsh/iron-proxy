package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/ironsh/iron-proxy/internal/dnsguard"
	"github.com/stretchr/testify/require"
)

// TestBuildTransport_RoutesThroughUpstreamProxy proves that a non-nil
// proxyFunc causes the upstream transport to send plain-HTTP requests via the
// upstream proxy rather than dialing the origin directly.
func TestBuildTransport_RoutesThroughUpstreamProxy(t *testing.T) {
	// Origin the proxy would dial directly if no upstream proxy were used.
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "origin")
	}))
	defer origin.Close()

	// Fake upstream forward proxy: for plain HTTP it receives the full
	// absolute-URL request. Record that it was hit and answer directly.
	var proxied atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.True(t, r.URL.IsAbs(), "upstream proxy should receive absolute-URI request, got %q", r.URL.String())
		proxied.Add(1)
		_, _ = io.WriteString(w, "via-proxy")
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	proxyFunc := func(*http.Request) (*url.URL, error) { return upstreamURL, nil }

	guard, err := dnsguard.New(nil)
	require.NoError(t, err)
	transport := buildTransport(nil, guard, 0, proxyFunc)
	defer transport.CloseIdleConnections()

	req, err := http.NewRequest(http.MethodGet, origin.URL, nil)
	require.NoError(t, err)
	resp, err := transport.RoundTrip(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "via-proxy", string(body))
	require.Equal(t, int32(1), proxied.Load(), "request should have traversed the upstream proxy")
}

// TestBuildTransport_NilProxyFuncDialsDirect confirms the default (no proxy)
// behavior is preserved: a nil proxyFunc dials the origin directly.
func TestBuildTransport_NilProxyFuncDialsDirect(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "origin")
	}))
	defer origin.Close()

	guard, err := dnsguard.New(nil)
	require.NoError(t, err)
	transport := buildTransport(nil, guard, 0, nil)
	defer transport.CloseIdleConnections()

	req, err := http.NewRequest(http.MethodGet, origin.URL, nil)
	require.NoError(t, err)
	resp, err := transport.RoundTrip(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "origin", string(body))
}
