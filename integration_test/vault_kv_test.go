package integration_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ironsh/iron-proxy/internal/cagen"
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

	upstreamValues := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamValues <- r.Header.Get("X-Vault-Secret")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	upstreamHost := upstream.Listener.Addr().String()
	tmpDir := t.TempDir()
	ca, err := cagen.Generate(cagen.Options{Name: "vault-kv-test", ExpiryHours: 1, Algorithm: cagen.Ed25519})
	require.NoError(t, err)
	certPath, keyPath, err := cagen.WriteFiles(tmpDir, ca)
	require.NoError(t, err)
	cfgPath := renderConfig(t, tmpDir, "vault_kv.yaml", struct {
		CACert string
		CAKey  string
	}{CACert: certPath, CAKey: keyPath})
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

	status, _ := proxyGet(t, proxy.HTTPAddr, upstreamHost, map[string]string{
		"X-Vault-Secret": "proxy-vault-secret",
	})
	require.Equal(t, http.StatusNoContent, status)
	require.Equal(t, "real-vault-secret", <-upstreamValues)

	request := <-requests
	require.Equal(t, "/v1/secret/data/services/openai", request.path)
	require.Equal(t, "integration-token", request.token)
}
