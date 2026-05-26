package integration_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// TestManagementReload boots the proxy with config A (allowlist + secret rule
// matching host-a.test, secret resolved from env var ..._SECRET_A), verifies
// requests for host-a.test are allowed and the secret is swapped while
// host-b.test is rejected, then overwrites the config file with config B
// (allowlist + secret rule for host-b.test, env var ..._SECRET_B), POSTs
// /v1/reload, and verifies the allow/block and the swapped value have flipped.
func TestManagementReload(t *testing.T) {
	tmpDir := t.TempDir()
	binary := proxyBinary(t)

	const (
		secretValueA = "reload-secret-value-a"
		secretValueB = "reload-secret-value-b"
		apiKey       = "reload-itest-api-key"
	)

	t.Setenv("IRON_RELOAD_ITEST_SECRET_A", secretValueA)
	t.Setenv("IRON_RELOAD_ITEST_SECRET_B", secretValueB)
	t.Setenv("IRON_RELOAD_ITEST_API_KEY", apiKey)

	// Upstream: echoes back the secret header so we can verify the swap.
	upstreamHost := echoHeadersUpstream(t, "X-Reload-Secret")
	_, port, err := net.SplitHostPort(upstreamHost)
	require.NoError(t, err)
	upstreamPort, err := strconv.Atoi(port)
	require.NoError(t, err)

	// In-process DNS server that resolves host-a.test and host-b.test to
	// 127.0.0.1. The proxy's upstream_resolver is pointed at this so the
	// proxy can dial those hostnames to our local httptest upstream. The
	// server binds a real port, so there's no preallocate-and-race.
	testDNSAddr := startTestDNSResolver(t)

	data := struct{ TestDNSAddr string }{TestDNSAddr: testDNSAddr}

	// Render config A; this writes <tmpDir>/config.yaml.
	cfgPath := renderConfig(t, tmpDir, "reload_a.yaml", data)
	proxy := startProxy(t, binary, cfgPath, nil)
	mgmtAddr := proxy.AddrFor(t, "management server starting")

	hostA := fmt.Sprintf("host-a.test:%d", upstreamPort)
	hostB := fmt.Sprintf("host-b.test:%d", upstreamPort)

	reloadHeaders := map[string]string{"X-Reload-Secret": "proxy-reload-token"}

	t.Run("config_a_active", func(t *testing.T) {
		// host-a.test is allowed and its secret is swapped.
		status, hdr := proxyGet(t, proxy.HTTPAddr, hostA, reloadHeaders)
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, secretValueA, hdr.Get("X-Got-Reload-Secret"))

		// host-b.test is rejected by config A's allowlist.
		status, _ = proxyGet(t, proxy.HTTPAddr, hostB, reloadHeaders)
		require.Equal(t, http.StatusForbidden, status)
	})

	// Overwrite the config file in place with config B and reload.
	_ = renderConfig(t, tmpDir, "reload_b.yaml", data)

	t.Run("reload_to_config_b", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://%s/v1/reload", mgmtAddr), nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+apiKey)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode, "reload response: %s", body)
	})

	t.Run("config_b_active", func(t *testing.T) {
		// host-b.test is now allowed and its secret is swapped.
		status, hdr := proxyGet(t, proxy.HTTPAddr, hostB, reloadHeaders)
		got := hdr.Get("X-Got-Reload-Secret")
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, secretValueB, got)
		require.NotEqual(t, secretValueA, got)

		// host-a.test is now rejected by config B's allowlist.
		status, _ = proxyGet(t, proxy.HTTPAddr, hostA, reloadHeaders)
		require.Equal(t, http.StatusForbidden, status)
	})
}

// startTestDNSResolver starts a tiny UDP DNS server on a random port that
// resolves host-a.test and host-b.test to 127.0.0.1 and returns its addr.
// The server is shut down when the test completes.
func startTestDNSResolver(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	answers := map[string]string{
		"host-a.test.": "127.0.0.1",
		"host-b.test.": "127.0.0.1",
	}

	srv := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, m *dns.Msg) {
			resp := new(dns.Msg)
			resp.SetReply(m)
			resp.Authoritative = true
			for _, q := range m.Question {
				if q.Qtype != dns.TypeA {
					continue
				}
				ip, ok := answers[strings.ToLower(q.Name)]
				if !ok {
					continue
				}
				rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN A %s", q.Name, ip))
				if err != nil {
					continue
				}
				resp.Answer = append(resp.Answer, rr)
			}
			_ = w.WriteMsg(resp)
		}),
	}

	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	<-started

	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}
