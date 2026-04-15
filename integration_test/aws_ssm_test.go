package integration_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAWSSystemsManagerParameterStore boots the proxy with real AWS SSM
// Parameter Store parameters and verifies proxy token replacement.
func TestAWSSystemsManagerParameterStore(t *testing.T) {
	tmpDir := t.TempDir()
	binary := proxyBinary(t)

	// Upstream: echoes back the parameter headers so we can verify the swap.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Got-Raw-Param", r.Header.Get("X-Raw-Param"))
		w.Header().Set("X-Got-JSON-Param", r.Header.Get("X-JSON-Param"))
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfgPath := renderConfig(t, tmpDir, "aws_ssm.yaml", nil)
	proxy := startProxy(t, binary, cfgPath, nil)
	upstreamHost := upstream.Listener.Addr().String()

	t.Run("raw_parameter", func(t *testing.T) {
		req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", proxy.HTTPAddr), nil)
		require.NoError(t, err)
		req.Host = upstreamHost
		req.Header.Set("X-Raw-Param", "proxy-raw-param")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		_, err = io.Copy(io.Discard, resp.Body)
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, "example_raw_value", resp.Header.Get("X-Got-Raw-Param"))
	})

	t.Run("json_parameter", func(t *testing.T) {
		req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", proxy.HTTPAddr), nil)
		require.NoError(t, err)
		req.Host = upstreamHost
		req.Header.Set("X-JSON-Param", "proxy-json-param")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		_, err = io.Copy(io.Discard, resp.Body)
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, "example_value", resp.Header.Get("X-Got-JSON-Param"))
	})
}
