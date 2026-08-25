package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestOnePasswordConnect boots the proxy against a real 1Password Connect
// server and verifies that proxy tokens in request headers are swapped for the
// resolved value. Reuses the same vault and item as TestOnePassword.
func TestOnePasswordConnect(t *testing.T) {
	upstreamHost := echoHeadersUpstream(t, "X-OP-Connect-Secret")

	cfgPath := renderConfig(t, t.TempDir(), "onepassword_connect.yaml", nil)
	proxy := startProxy(t, proxyBinary(t), cfgPath, nil)

	t.Run("op connect secret", func(t *testing.T) {
		status, hdr := proxyGet(t, proxy.HTTPAddr, upstreamHost, map[string]string{"X-OP-Connect-Secret": "proxy-op-connect-secret"})
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, "1password-example-password", hdr.Get("X-Got-OP-Connect-Secret"))
	})
}
