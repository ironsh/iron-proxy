package integration_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAWSSecretsManager boots the proxy with real AWS Secrets Manager secrets
// and verifies that proxy tokens in request headers are swapped for real values.
func TestAWSSecretsManager(t *testing.T) {
	tmpDir := t.TempDir()
	binary := proxyBinary(t)

	// Upstream: echoes back the secret headers so we can verify the swap.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Got-Raw-Secret", r.Header.Get("X-Raw-Secret"))
		w.Header().Set("X-Got-KV-Secret", r.Header.Get("X-KV-Secret"))
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfgPath := renderConfig(t, tmpDir, "aws_sm.yaml", nil)
	proxy := startProxy(t, binary, cfgPath, nil)
	upstreamHost := upstream.Listener.Addr().String()

	t.Run("raw_secret", func(t *testing.T) {
		req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", proxy.HTTPAddr), nil)
		require.NoError(t, err)
		req.Host = upstreamHost
		req.Header.Set("X-Raw-Secret", "proxy-raw-secret")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		_, err = io.Copy(io.Discard, resp.Body)
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, "example-value", resp.Header.Get("X-Got-Raw-Secret"))
	})

	t.Run("kv_secret", func(t *testing.T) {
		req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", proxy.HTTPAddr), nil)
		require.NoError(t, err)
		req.Host = upstreamHost
		req.Header.Set("X-KV-Secret", "proxy-kv-secret")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		_, err = io.Copy(io.Discard, resp.Body)
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, "example-value", resp.Header.Get("X-Got-KV-Secret"))
	})
}
