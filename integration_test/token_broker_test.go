package integration_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	testBrokerBearer  = "test-broker-bearer"
	testOAuthClientID = "test-client-id"
	testRefreshToken  = "test-refresh-token-1"
)

// TestTokenBroker boots iron-token-broker and iron-proxy against an in-process
// fake OAuth provider, then verifies a proxy request comes out with an
// Authorization header carrying the broker-issued access token. A second
// request within the cache TTL must not produce a second token-endpoint hit.
func TestTokenBroker(t *testing.T) {
	tmpDir := t.TempDir()
	proxyBin := proxyBinary(t)
	brokerBin := brokerBinary(t)

	// Fake OAuth provider — accepts a refresh_token grant, rotates the
	// refresh_token on every call, and returns a unique access_token so the
	// upstream assertion can distinguish requests.
	oauth := newFakeOAuthProvider(t)
	defer oauth.Close()

	// Upstream echoes back the Authorization header for assertion.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Got-Authorization", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamHost := upstream.Listener.Addr().String()

	// Bootstrap the broker's file store with a refresh_token blob.
	blobPath := filepath.Join(tmpDir, "openai-codex.json")
	require.NoError(t, writeBootstrapBlob(blobPath, testRefreshToken))

	brokerCfg := renderConfig(t, tmpDir, "token_broker_broker.yaml", map[string]string{
		"TokenEndpoint": oauth.URL() + "/token",
		"BlobPath":      blobPath,
	})
	// renderConfig writes to <tmpDir>/config.yaml; rename so we can render the
	// proxy config into the same directory without collision.
	brokerCfgPath := filepath.Join(tmpDir, "broker.yaml")
	require.NoError(t, os.Rename(brokerCfg, brokerCfgPath))

	broker := startBroker(t, brokerBin, brokerCfgPath, []string{
		"TEST_BROKER_BEARER=" + testBrokerBearer,
		"TEST_OAUTH_CLIENT_ID=" + testOAuthClientID,
	})

	proxyCfgPath := renderConfig(t, tmpDir, "token_broker_proxy.yaml", nil)
	proxy := startProxy(t, proxyBin, proxyCfgPath, []string{
		"IRON_BROKER_URL=http://" + broker.HTTPAddr,
		"IRON_BROKER_TOKEN=" + testBrokerBearer,
	})

	// The broker bootstraps its first refresh asynchronously. Poll the
	// access-token endpoint directly until it returns 200, so the proxy
	// test below isn't racing the bootstrap.
	require.Eventually(t, func() bool {
		req, _ := http.NewRequest("GET", "http://"+broker.HTTPAddr+"/credentials/openai-codex/access_token", nil)
		req.Header.Set("Authorization", "Bearer "+testBrokerBearer)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode == http.StatusOK
	}, 10*time.Second, 100*time.Millisecond, "broker never finished bootstrap refresh")

	refreshesAfterBootstrap := oauth.Refreshes()
	require.GreaterOrEqual(t, refreshesAfterBootstrap, int64(1), "broker should have refreshed at least once during bootstrap")

	t.Run("proxy injects broker-issued token", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://"+proxy.HTTPAddr+"/", nil)
		require.NoError(t, err)
		req.Host = upstreamHost

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		_, err = io.Copy(io.Discard, resp.Body)
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, resp.StatusCode)
		got := resp.Header.Get("X-Got-Authorization")
		require.Truef(t, len(got) > len("Bearer ") && got[:len("Bearer ")] == "Bearer ", "expected Bearer access token in Authorization header, got %q", got)
		require.Containsf(t, got, "access-token-", "expected fake OAuth access token in Authorization header, got %q", got)
	})

	t.Run("second request within TTL does not trigger another OAuth refresh", func(t *testing.T) {
		before := oauth.Refreshes()
		req, err := http.NewRequest("GET", "http://"+proxy.HTTPAddr+"/", nil)
		require.NoError(t, err)
		req.Host = upstreamHost

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		_, err = io.Copy(io.Discard, resp.Body)
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, before, oauth.Refreshes(), "second proxy request must not trigger another OAuth refresh within the broker's early-refresh window")
	})
}

// fakeOAuthProvider implements just enough of RFC 6749 4.5 (refresh_token
// grant) for the broker's refresh loop. It rotates the refresh_token on
// every call so the broker's persistence path is exercised, and assigns
// each access_token a unique suffix so callers can distinguish requests.
type fakeOAuthProvider struct {
	server         *httptest.Server
	refreshes      atomic.Int64
	currentRefresh atomic.Value // string
}

func newFakeOAuthProvider(t *testing.T) *fakeOAuthProvider {
	t.Helper()
	fp := &fakeOAuthProvider{}
	fp.currentRefresh.Store(testRefreshToken)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.PostForm.Get("grant_type") != "refresh_token" {
			http.Error(w, `{"error":"unsupported_grant_type"}`, http.StatusBadRequest)
			return
		}
		if r.PostForm.Get("client_id") != testOAuthClientID {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		want := fp.currentRefresh.Load().(string)
		if got := r.PostForm.Get("refresh_token"); got != want {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}

		n := fp.refreshes.Add(1)
		nextRefresh := fmt.Sprintf("refresh-token-%d", n+1)
		fp.currentRefresh.Store(nextRefresh)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  fmt.Sprintf("access-token-%d", n),
			"refresh_token": nextRefresh,
			"expires_in":    3600,
			"token_type":    "Bearer",
		})
	})

	fp.server = httptest.NewServer(mux)
	return fp
}

func (fp *fakeOAuthProvider) Close()              { fp.server.Close() }
func (fp *fakeOAuthProvider) URL() string         { return fp.server.URL }
func (fp *fakeOAuthProvider) Refreshes() int64    { return fp.refreshes.Load() }

// writeBootstrapBlob writes the JSON document the broker expects in its
// store on startup. Only refresh_token is required; the broker mints
// access_token and expires_at on its first refresh.
func writeBootstrapBlob(path, refreshToken string) error {
	blob := map[string]string{"refresh_token": refreshToken}
	raw, err := json.MarshalIndent(blob, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}
