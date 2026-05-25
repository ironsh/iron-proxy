package broker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/broker/config"
	"github.com/ironsh/iron-proxy/internal/broker/store"
)

// rotatingIdP serves a fresh access_token and refresh_token on every
// request. Versioned values let the test assert that a rotation
// propagated through the broker and was persisted to the store.
type rotatingIdP struct {
	t       *testing.T
	calls   atomic.Int64
	srv     *httptest.Server
	failNext atomic.Bool
	failBody string
	failCode int
}

func newRotatingIdP(t *testing.T) *rotatingIdP {
	r := &rotatingIdP{t: t}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		_ = body // not asserting form contents here; refresh_test covers it
		if r.failNext.Load() {
			w.WriteHeader(r.failCode)
			_, _ = io.WriteString(w, r.failBody)
			return
		}
		n := r.calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"access_token":"at-%d","refresh_token":"rt-%d","expires_in":3600}`, n, n)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func TestBrokerEndToEnd(t *testing.T) {
	// Bootstrap a file-backed credential.
	dir := t.TempDir()
	storePath := filepath.Join(dir, "creds.json")
	handle, err := store.BuildHandle(mustStoreNode(t, `{type: file, path: `+storePath+`}`), slog.Default())
	require.NoError(t, err)
	require.NoError(t, handle.Put(t.Context(), store.CredentialBlob{
		RefreshToken: "rt-0",
		ExpiresAt:    time.Now().Add(-time.Minute), // expired so the first call refreshes
		LastRefresh:  time.Now().Add(-time.Hour),
	}))

	idp := newRotatingIdP(t)

	cfg := &config.Config{
		Listen:        ":0",
		MetricsListen: ":0",
		Log:           config.Log{Level: "info", Format: "text"},
		Defaults: config.Defaults{
			EarlyRefreshSlack:    config.Duration(5 * time.Minute),
			EarlyRefreshFraction: 0.2,
			MaxRefreshInterval:   config.Duration(24 * time.Hour),
			RefreshTimeout:       config.Duration(5 * time.Second),
		},
	}
	built := []config.BuiltCredential{{
		ID:                   "test",
		TokenEndpoint:        idp.srv.URL,
		ClientID:             newConstantSource("client_id", "client-A"),
		Store:                handle,
		EarlyRefreshSlack:    5 * time.Minute,
		EarlyRefreshFraction: 0.2,
		MaxRefreshInterval:   24 * time.Hour,
		RefreshTimeout:       5 * time.Second,
	}}

	b, err := New(Options{
		Config:      cfg,
		Credentials: built,
		Logger:      slog.Default(),
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	b.Start(ctx)

	// Wait for the initial refresh to land by polling the cached token.
	require.Eventually(t, func() bool {
		tok, _, err := b.creds["test"].AccessToken(ctx)
		return err == nil && tok != ""
	}, 3*time.Second, 20*time.Millisecond, "broker should mint an access token after startup")

	// Drive the HTTP API directly via the registered mux.
	rec := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "/credentials/test/access_token", nil)
	require.NoError(t, err)
	b.api.server.Handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var first accessTokenBody
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&first))
	require.NotEmpty(t, first.AccessToken)

	// And it was persisted to the file backend.
	persisted, err := handle.Get(t.Context())
	require.NoError(t, err)
	require.NotEqual(t, "rt-0", persisted.RefreshToken, "refresh token should have rotated")

	// Flip the IdP into invalid_grant and force a refresh via an
	// in-band call after expiring the cached token. The credential
	// transitions to dead and the HTTP API returns 422.
	idp.failNext.Store(true)
	idp.failCode = http.StatusBadRequest
	idp.failBody = `{"error":"invalid_grant","error_description":"rotated by another writer"}`

	// Push the cached blob's expiry into the past via a direct mutation
	// (we own the credential state for the test).
	c := b.creds["test"]
	c.mu.Lock()
	c.blob.ExpiresAt = time.Now().Add(-time.Minute)
	c.mu.Unlock()

	rec = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, "/credentials/test/access_token", nil)
	b.api.server.Handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	require.Contains(t, rec.Body.String(), "invalid_grant")

	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	require.NoError(t, b.Shutdown(shutdownCtx))
	b.Wait()
}

// mustStoreNode is a tiny helper for decoding inline YAML into the
// single root node store.BuildHandle expects.
func mustStoreNode(t *testing.T, src string) yaml.Node {
	t.Helper()
	var n yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(src), &n))
	require.Equal(t, 1, len(n.Content))
	return *n.Content[0]
}
