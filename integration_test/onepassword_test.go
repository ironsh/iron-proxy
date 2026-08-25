package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestOnePassword boots the proxy with a real 1Password secret and verifies
// that proxy tokens in request headers are swapped for the resolved value.
func TestOnePassword(t *testing.T) {
	upstreamHost := echoHeadersUpstream(t, "X-OP-Secret")

	cfgPath := renderConfig(t, t.TempDir(), "onepassword.yaml", nil)
	proxy := startProxy(t, proxyBinary(t), cfgPath, nil)

	t.Run("op_secret", func(t *testing.T) {
		status, hdr := proxyGet(t, proxy.HTTPAddr, upstreamHost, map[string]string{"X-OP-Secret": "proxy-op-secret"})
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, "1password-example-password", hdr.Get("X-Got-OP-Secret"))
	})
}
