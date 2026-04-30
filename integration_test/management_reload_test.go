package integration_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

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
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Got-Reload-Secret", r.Header.Get("X-Reload-Secret"))
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamPort := upstream.Listener.Addr().(*net.TCPAddr).Port

	// Pre-allocate fixed ports for the management server (TCP) and the
	// proxy's DNS server (UDP). The management server logs only its
	// configured Addr (not the resolved listener), and the DNS port has
	// to be known up front so we can point the proxy's upstream resolver
	// back at itself in the YAML.
	mgmtAddr := "127.0.0.1:" + freePort(t)
	dnsPort := freeUDPPort(t)

	data := struct {
		MgmtAddr string
		DNSPort  string
	}{
		MgmtAddr: mgmtAddr,
		DNSPort:  dnsPort,
	}

	// Render config A; this writes <tmpDir>/config.yaml.
	cfgPath := renderConfig(t, tmpDir, "reload_a.yaml", data)
	proxy := startProxy(t, binary, cfgPath, nil)
	waitForTCP(t, mgmtAddr)

	hostA := fmt.Sprintf("host-a.test:%d", upstreamPort)
	hostB := fmt.Sprintf("host-b.test:%d", upstreamPort)

	t.Run("config_a_active", func(t *testing.T) {
		// host-a.test is allowed and its secret is swapped.
		got, status := doSecretRequest(t, proxy.HTTPAddr, hostA)
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, secretValueA, got)

		// host-b.test is rejected by config A's allowlist.
		_, status = doSecretRequest(t, proxy.HTTPAddr, hostB)
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
		got, status := doSecretRequest(t, proxy.HTTPAddr, hostB)
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, secretValueB, got)
		require.NotEqual(t, secretValueA, got)

		// host-a.test is now rejected by config B's allowlist.
		_, status = doSecretRequest(t, proxy.HTTPAddr, hostA)
		require.Equal(t, http.StatusForbidden, status)
	})
}

// doSecretRequest sends a request through the proxy with the proxy-token in
// the X-Reload-Secret header and returns the value the upstream observed
// (echoed back via X-Got-Reload-Secret) along with the response status.
// When the request is rejected by the proxy, the value will be empty.
func doSecretRequest(t *testing.T, proxyAddr, hostHeader string) (string, int) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/", proxyAddr), nil)
	require.NoError(t, err)
	req.Host = hostHeader
	req.Header.Set("X-Reload-Secret", "proxy-reload-token")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	return resp.Header.Get("X-Got-Reload-Secret"), resp.StatusCode
}

// waitForTCP polls addr until a TCP connect succeeds. The management server
// starts in its own goroutine after the proxy logs "http proxy starting", so
// it may not be listening yet when startProxy returns.
func waitForTCP(t *testing.T, addr string) {
	t.Helper()
	require.Eventually(t, func() bool {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	}, 5*time.Second, 50*time.Millisecond, "tcp listener never accepted at %s", addr)
}

// freeUDPPort asks the OS for a free UDP port and returns it as a string.
// Used to pin the proxy's DNS server to a port we know in advance so we can
// point upstream_resolver back at it.
func freeUDPPort(t *testing.T) string {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	port := c.LocalAddr().(*net.UDPAddr).Port
	require.NoError(t, c.Close())
	return strconv.Itoa(port)
}
