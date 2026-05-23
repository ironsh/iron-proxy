package integration_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestGCPAuthWorkloadIdentity drives credentials_provider: workload_identity
// end-to-end without real GCP infra by steering ADC at a synthetic
// service-account JSON whose token_uri is a local httptest server.
func TestGCPAuthWorkloadIdentity(t *testing.T) {
	tmpDir := t.TempDir()
	binary := proxyBinary(t)

	const wantToken = "workload-identity-bearer"
	var tokenCalls atomic.Int64
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenCalls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": wantToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenSrv.Close()

	var (
		mu      sync.Mutex
		gotAuth string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	keyfile := writeWorkloadIdentityKeyfile(t, tmpDir, tokenSrv.URL)

	cfgPath := renderConfig(t, tmpDir, "gcp_auth_workload_identity.yaml", nil)
	env := []string{
		"GOOGLE_APPLICATION_CREDENTIALS=" + keyfile,
	}
	proxy := startProxy(t, binary, cfgPath, env)
	upstreamHost := upstream.Listener.Addr().String()

	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/v1/projects", proxy.HTTPAddr), nil)
	require.NoError(t, err)
	req.Host = upstreamHost
	// The agent SDK would have a placeholder bearer of its own. gcp_auth
	// overwrites Authorization unconditionally, so the placeholder is not
	// load-bearing for the assertion; we set one anyway to mirror the agent
	// flow and confirm it is replaced.
	req.Header.Set("Authorization", "Bearer agent-placeholder")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, "Bearer "+wantToken, gotAuth, "minted workload-identity bearer must reach upstream")
	require.NotContains(t, gotAuth, "agent-placeholder", "agent placeholder bearer must be replaced")
	require.Equal(t, int64(1), tokenCalls.Load(), "token endpoint should be hit exactly once and then cached")
}

// writeWorkloadIdentityKeyfile writes a minimal service-account JSON whose
// token_uri points at a local fake. Loadable via GOOGLE_APPLICATION_CREDENTIALS.
func writeWorkloadIdentityKeyfile(t *testing.T, dir, tokenURI string) string {
	t.Helper()
	keyfile := map[string]string{
		"type":         "service_account",
		"project_id":   "iron-proxy-workload-identity-test",
		"private_key":  generateServiceAccountKeyPEM(t),
		"client_email": "workload-identity@iron-proxy-test.iam.gserviceaccount.com",
		"token_uri":    tokenURI,
	}
	data, err := json.MarshalIndent(keyfile, "", "  ")
	require.NoError(t, err)

	path := filepath.Join(dir, "workload-identity-sa.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

