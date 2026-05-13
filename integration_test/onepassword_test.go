package integration_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// runOPSDKTestEnv is an opt-in gate for the 1Password SDK integration test.
// The SDK resolver hits the live 1Password service via a Wasm-based client,
// and the shared service account gets rate-limited when CI runs it on every
// push. The Connect-based test (TestOnePasswordConnect) covers the same
// resolver code paths against a self-hosted server with no rate limit, so the
// SDK test is only useful when explicitly exercising the upstream SDK.
const runOPSDKTestEnv = "RUN_OP_SDK_INTEGRATION"

// TestOnePassword boots the proxy with a real 1Password secret and verifies
// that proxy tokens in request headers are swapped for the resolved value.
func TestOnePassword(t *testing.T) {
	if os.Getenv(runOPSDKTestEnv) == "" {
		t.Skipf("%s not set; skipping 1Password SDK integration test (rate-limited; set to 1 to run)", runOPSDKTestEnv)
	}
	tmpDir := t.TempDir()
	binary := proxyBinary(t)

	// Upstream: echoes back the secret header so we can verify the swap.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Got-OP-Secret", r.Header.Get("X-OP-Secret"))
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfgPath := renderConfig(t, tmpDir, "onepassword.yaml", nil)
	proxy := startProxy(t, binary, cfgPath, nil)
	upstreamHost := upstream.Listener.Addr().String()

	t.Run("op_secret", func(t *testing.T) {
		req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", proxy.HTTPAddr), nil)
		require.NoError(t, err)
		req.Host = upstreamHost
		req.Header.Set("X-OP-Secret", "proxy-op-secret")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		_, err = io.Copy(io.Discard, resp.Body)
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, "1password-example-password", resp.Header.Get("X-Got-OP-Secret"))
	})
}
