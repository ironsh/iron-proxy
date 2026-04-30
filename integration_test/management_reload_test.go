package integration_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestManagementReload boots the proxy with config A, verifies the secret
// transform swaps in config A's value, then rewrites the config file to
// config B (different allowlist + secret env var), POSTs /v1/reload, and
// verifies subsequent requests now see config B's resolved secret.
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
	upstreamHost := upstream.Listener.Addr().String()

	// Pre-bind a free port for the management server. The management
	// server logs only its configured Addr (not the resolved listener
	// address), so we cannot use :0.
	mgmtAddr := "127.0.0.1:" + freePort(t)
	data := struct{ MgmtAddr string }{MgmtAddr: mgmtAddr}

	// Render config A; this writes <tmpDir>/config.yaml.
	cfgPath := renderConfig(t, tmpDir, "reload_a.yaml", data)
	proxy := startProxy(t, binary, cfgPath, nil)

	waitForTCP(t, mgmtAddr)

	t.Run("config_a_active", func(t *testing.T) {
		got := doSecretRequest(t, proxy.HTTPAddr, upstreamHost)
		require.Equal(t, secretValueA, got)
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
		got := doSecretRequest(t, proxy.HTTPAddr, upstreamHost)
		require.Equal(t, secretValueB, got)
		require.NotEqual(t, secretValueA, got)
	})
}

// doSecretRequest sends a request through the proxy with the proxy-token in
// the X-Reload-Secret header and returns the value the upstream observed
// (which the upstream echoes back as X-Got-Reload-Secret).
func doSecretRequest(t *testing.T, proxyAddr, upstreamHost string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/", proxyAddr), nil)
	require.NoError(t, err)
	req.Host = upstreamHost
	req.Header.Set("X-Reload-Secret", "proxy-reload-token")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return resp.Header.Get("X-Got-Reload-Secret")
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
	}, 5*time.Second, 50*time.Millisecond, "management server never accepted connections at %s", addr)
}
