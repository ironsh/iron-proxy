package integration_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestOnePasswordConnect boots the proxy against a real 1Password Connect
// server and verifies that proxy tokens in request headers are swapped for the
// resolved value. Reuses the same vault and item as TestOnePassword.
func TestOnePasswordConnect(t *testing.T) {
	tmpDir := t.TempDir()
	binary := proxyBinary(t)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Got-OP-Connect-Secret", r.Header.Get("X-OP-Connect-Secret"))
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfgPath := renderConfig(t, tmpDir, "onepassword_connect.yaml", nil)
	proxy := startProxy(t, binary, cfgPath, nil)
	upstreamHost := upstream.Listener.Addr().String()

	t.Run("op connect secret", func(t *testing.T) {
		req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", proxy.HTTPAddr), nil)
		require.NoError(t, err)
		req.Host = upstreamHost
		req.Header.Set("X-OP-Connect-Secret", "proxy-op-connect-secret")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		_, err = io.Copy(io.Discard, resp.Body)
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, "1password-example-password", resp.Header.Get("X-Got-OP-Connect-Secret"))
	})
}
