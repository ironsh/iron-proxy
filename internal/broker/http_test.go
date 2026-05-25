package broker

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/broker/store"
)

func newTestHTTPServer(t *testing.T, creds map[string]*credentialState, bearer string) *httptest.Server {
	t.Helper()
	srv := newHTTPServer(httpOptions{
		Addr:        ":0",
		Credentials: creds,
		BearerToken: bearer,
		Logger:      slog.Default(),
		Metrics:     newMetrics(),
	})
	httpSrv := httptest.NewServer(srv.server.Handler)
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func TestHTTPReturns404ForUnknownCredential(t *testing.T) {
	srv := newTestHTTPServer(t, map[string]*credentialState{}, "")
	resp, err := http.Get(srv.URL + "/credentials/missing/access_token")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestHTTPReturns401WhenBearerMissing(t *testing.T) {
	srv := newTestHTTPServer(t, map[string]*credentialState{"x": nil}, "expected-token")
	resp, err := http.Get(srv.URL + "/credentials/x/access_token")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestHTTPReturns401WhenBearerWrong(t *testing.T) {
	srv := newTestHTTPServer(t, map[string]*credentialState{"x": nil}, "expected-token")
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/credentials/x/access_token", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestHTTPReturns200ForCachedToken(t *testing.T) {
	handle, _ := newFileHandle(t, store.CredentialBlob{
		AccessToken:  "at-cached",
		RefreshToken: "rt-0",
		ExpiresAt:    time.Now().Add(time.Hour),
		LastRefresh:  time.Now(),
	})
	c := newCredentialUnderTest(t, "unused", handle, newMetrics())
	require.NoError(t, c.load(t.Context()))
	srv := newTestHTTPServer(t, map[string]*credentialState{"test": c}, "")

	resp, err := http.Get(srv.URL + "/credentials/test/access_token")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	// Token responses must never be cached by intermediaries or clients.
	require.Equal(t, "no-store", resp.Header.Get("Cache-Control"))

	var body accessTokenBody
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Equal(t, "at-cached", body.AccessToken)
	require.False(t, body.ExpiresAt.IsZero())
}

func TestHTTPReturns422WhenCredentialDead(t *testing.T) {
	handle, _ := newFileHandle(t, store.CredentialBlob{RefreshToken: "rt-0"})
	c := newCredentialUnderTest(t, "unused", handle, newMetrics())
	require.NoError(t, c.load(t.Context()))
	c.markDead("invalid_grant")
	srv := newTestHTTPServer(t, map[string]*credentialState{"test": c}, "")

	resp, err := http.Get(srv.URL + "/credentials/test/access_token")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	require.Contains(t, string(body), "invalid_grant")
	require.Contains(t, string(body), "credential dead")
}

func TestHTTPReturns503WhenBootstrapping(t *testing.T) {
	handle, _ := newFileHandle(t, store.CredentialBlob{})
	c := newCredentialUnderTest(t, "unused", handle, newMetrics())
	// Do NOT call c.load; haveBlob stays false.
	srv := newTestHTTPServer(t, map[string]*credentialState{"test": c}, "")

	resp, err := http.Get(srv.URL + "/credentials/test/access_token")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	require.NotEmpty(t, resp.Header.Get("Retry-After"))
}

func TestHTTPHealthzReturns200(t *testing.T) {
	srv := newTestHTTPServer(t, map[string]*credentialState{}, "")
	resp, err := http.Get(srv.URL + "/healthz")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, "OK", strings.TrimSpace(string(body)))
}

func TestHTTPMethodNotAllowedForOtherVerbs(t *testing.T) {
	srv := newTestHTTPServer(t, map[string]*credentialState{}, "")
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/credentials/x/access_token", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	// Go 1.22+ http.ServeMux with "GET /..." pattern returns 405 for
	// other methods on the same path.
	require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}
