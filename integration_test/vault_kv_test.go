package integration_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestVaultKV boots the proxy against a Vault-compatible KV v2 endpoint and
// verifies that the official client configuration and secret transform work
// together without requiring external Vault credentials.
func TestVaultKV(t *testing.T) {
	type vaultRequest struct {
		path  string
		token string
	}
	requests := make(chan vaultRequest, 1)
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- vaultRequest{path: r.URL.Path, token: r.Header.Get("X-Vault-Token")}
		w.Header().Set("Content-Type", "application/json")
		// The in-memory server has no useful recovery for a client disconnect;
		// the proxy request below reports the resulting read failure.
		_, _ = io.WriteString(w, `{"data":{"data":{"api_key":"real-vault-secret"},"metadata":{}}}`)
	}))
	t.Cleanup(vault.Close)

	upstreamHost := echoHeadersUpstream(t, "X-Vault-Secret")
	cfgPath := renderConfig(t, t.TempDir(), "vault_kv.yaml", nil)
	proxy := startProxy(t, proxyBinary(t), cfgPath, []string{
		"VAULT_ADDR=" + vault.URL,
		"VAULT_TOKEN=integration-token",
		"VAULT_NAMESPACE=",
		"VAULT_AGENT_ADDR=",
		"VAULT_PROXY_ADDR=",
		"VAULT_CACERT=",
		"VAULT_CAPATH=",
		"VAULT_CLIENT_CERT=",
		"VAULT_CLIENT_KEY=",
	})

	status, headers := proxyGet(t, proxy.HTTPAddr, upstreamHost, map[string]string{
		"X-Vault-Secret": "proxy-vault-secret",
	})
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "real-vault-secret", headers.Get("X-Got-Vault-Secret"))

	request := <-requests
	require.Equal(t, "/v1/secret/data/services/openai", request.path)
	require.Equal(t, "integration-token", request.token)
}
