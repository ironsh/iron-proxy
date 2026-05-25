package broker

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/broker/config"
	"github.com/ironsh/iron-proxy/internal/broker/store"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

// constantSource is a secrets.Source returning a fixed string. Tests
// drive client_id resolution this way to avoid wiring up env vars.
type constantSource struct {
	name string
	val  string
}

func (c constantSource) Name() string                          { return c.name }
func (c constantSource) Get(context.Context) (string, error)   { return c.val, nil }
func newConstantSource(name, val string) secrets.Source         { return constantSource{name: name, val: val} }

// fakeIdP is a token endpoint that drives test scenarios.
type fakeIdP struct {
	mu        sync.Mutex
	calls     int
	responses []idpResponse
	srv       *httptest.Server
}

type idpResponse struct {
	status int
	body   string
}

func newFakeIdP(t *testing.T, responses ...idpResponse) *fakeIdP {
	t.Helper()
	f := &fakeIdP{responses: responses}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		idx := f.calls
		if idx >= len(f.responses) {
			idx = len(f.responses) - 1
		}
		f.calls++
		resp := f.responses[idx]
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.status)
		_, _ = io.WriteString(w, resp.body)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIdP) URL() string {
	return f.srv.URL
}

func (f *fakeIdP) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func newFileHandle(t *testing.T, initial store.CredentialBlob) (store.Handle, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "creds.json")
	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(`{type: file, path: `+path+`}`), &node))
	h, err := store.BuildHandle(*node.Content[0], slog.Default())
	require.NoError(t, err)
	if initial.RefreshToken != "" {
		require.NoError(t, h.Put(t.Context(), initial))
	}
	return h, path
}

func newCredentialUnderTest(t *testing.T, idpURL string, handle store.Handle, met *metrics) *credentialState {
	t.Helper()
	built := config.BuiltCredential{
		ID:                   "test",
		TokenEndpoint:        idpURL,
		ClientID:             newConstantSource("test_client_id", "client-A"),
		Store:                handle,
		EarlyRefreshSlack:    1 * time.Minute,
		EarlyRefreshFraction: 0.2,
		MaxRefreshInterval:   24 * time.Hour,
		RefreshTimeout:       5 * time.Second,
	}
	return newCredentialState(built, slog.Default(), met, &http.Client{Timeout: 5 * time.Second})
}

func TestCredentialFirstRefreshRotates(t *testing.T) {
	bootstrap := store.CredentialBlob{
		RefreshToken: "rt-0",
		ExpiresAt:    time.Now().Add(-time.Minute), // already stale
		LastRefresh:  time.Now().Add(-time.Hour),
	}
	handle, _ := newFileHandle(t, bootstrap)
	idp := newFakeIdP(t, idpResponse{
		status: 200,
		body:   `{"access_token":"at-1","refresh_token":"rt-1","expires_in":3600}`,
	})
	met := newMetrics()
	c := newCredentialUnderTest(t, idp.URL(), handle, met)
	require.NoError(t, c.load(t.Context()))
	require.NoError(t, c.refreshOnce(t.Context()))

	blob, ready, dead, _ := c.snapshot()
	require.True(t, ready)
	require.False(t, dead)
	require.Equal(t, "at-1", blob.AccessToken)
	require.Equal(t, "rt-1", blob.RefreshToken)

	// And the new blob is persisted.
	persisted, err := handle.Get(t.Context())
	require.NoError(t, err)
	require.Equal(t, "rt-1", persisted.RefreshToken)
}

func TestCredentialInvalidGrantMarksDead(t *testing.T) {
	bootstrap := store.CredentialBlob{RefreshToken: "rt-0"}
	handle, _ := newFileHandle(t, bootstrap)
	idp := newFakeIdP(t, idpResponse{
		status: 400,
		body:   `{"error":"invalid_grant","error_description":"refresh token rotated by another writer"}`,
	})
	met := newMetrics()
	c := newCredentialUnderTest(t, idp.URL(), handle, met)
	require.NoError(t, c.load(t.Context()))
	err := c.refreshOnce(t.Context())
	require.Error(t, err)

	_, _, dead, reason := c.snapshot()
	require.True(t, dead)
	require.Equal(t, "invalid_grant", reason)
}

func TestCredentialBlobNotBootstrapped(t *testing.T) {
	handle, _ := newFileHandle(t, store.CredentialBlob{}) // no initial Put
	idp := newFakeIdP(t)
	met := newMetrics()
	c := newCredentialUnderTest(t, idp.URL(), handle, met)
	err := c.load(t.Context())
	require.ErrorIs(t, err, store.ErrNotFound)
}

// flakyStore wraps a real store.Handle and fails the first N Get calls
// with a synthetic error, then delegates. Used to verify loadWithBackoff
// rides through transient store outages.
type flakyStore struct {
	inner    store.Handle
	failures *atomic.Int32
}

func (f *flakyStore) Name() string { return f.inner.Name() }
func (f *flakyStore) Get(ctx context.Context) (store.CredentialBlob, error) {
	if f.failures.Add(-1) >= 0 {
		return store.CredentialBlob{}, io.ErrUnexpectedEOF
	}
	return f.inner.Get(ctx)
}
func (f *flakyStore) Put(ctx context.Context, blob store.CredentialBlob) error {
	return f.inner.Put(ctx, blob)
}

func TestCredentialLoadWithBackoffRetriesTransientFailures(t *testing.T) {
	bootstrap := store.CredentialBlob{
		AccessToken:  "at-cached",
		RefreshToken: "rt-0",
		ExpiresAt:    time.Now().Add(time.Hour),
		LastRefresh:  time.Now(),
	}
	inner, _ := newFileHandle(t, bootstrap)
	failures := &atomic.Int32{}
	failures.Store(2)
	flaky := &flakyStore{inner: inner, failures: failures}

	built := config.BuiltCredential{
		ID:                 "flaky",
		TokenEndpoint:      "unused",
		ClientID:           newConstantSource("client_id", "c"),
		Store:              flaky,
		EarlyRefreshSlack:  1 * time.Minute,
		MaxRefreshInterval: 24 * time.Hour,
		RefreshTimeout:     5 * time.Second,
	}
	c := newCredentialState(built, slog.Default(), newMetrics(), &http.Client{})

	// Shorten the test by overriding the initial interval indirectly:
	// loadWithBackoff uses 2s initial → 4s → 8s, so two failures plus
	// success happens within a few seconds. Bound the test with a tight
	// context to keep CI fast.
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	require.NoError(t, c.loadWithBackoff(ctx))

	_, ready, dead, _ := c.snapshot()
	require.True(t, ready)
	require.False(t, dead)
}

func TestCredentialLoadWithBackoffShortCircuitsOnNotFound(t *testing.T) {
	handle, _ := newFileHandle(t, store.CredentialBlob{}) // no initial Put
	built := config.BuiltCredential{
		ID:                 "missing",
		TokenEndpoint:      "unused",
		ClientID:           newConstantSource("client_id", "c"),
		Store:              handle,
		EarlyRefreshSlack:  1 * time.Minute,
		MaxRefreshInterval: 24 * time.Hour,
		RefreshTimeout:     5 * time.Second,
	}
	c := newCredentialState(built, slog.Default(), newMetrics(), &http.Client{})
	err := c.loadWithBackoff(t.Context())
	require.ErrorIs(t, err, store.ErrNotFound)
}

func TestCredentialAccessTokenWaitsForBootstrap(t *testing.T) {
	handle, _ := newFileHandle(t, store.CredentialBlob{})
	idp := newFakeIdP(t)
	met := newMetrics()
	c := newCredentialUnderTest(t, idp.URL(), handle, met)
	// load not called yet; AccessToken should report not-ready.
	_, _, err := c.AccessToken(t.Context())
	require.ErrorIs(t, err, errNotReady)
}

func TestCredentialAccessTokenServesCached(t *testing.T) {
	bootstrap := store.CredentialBlob{
		AccessToken:  "at-cached",
		RefreshToken: "rt-0",
		ExpiresAt:    time.Now().Add(time.Hour),
		LastRefresh:  time.Now().Add(-time.Minute),
	}
	handle, _ := newFileHandle(t, bootstrap)
	idp := newFakeIdP(t)
	met := newMetrics()
	c := newCredentialUnderTest(t, idp.URL(), handle, met)
	require.NoError(t, c.load(t.Context()))

	tok, _, err := c.AccessToken(t.Context())
	require.NoError(t, err)
	require.Equal(t, "at-cached", tok)
	require.Zero(t, idp.Calls(), "fresh token should not hit the IdP")
}

func TestCredentialIsolation(t *testing.T) {
	// One failing credential must not block a healthy sibling.
	bootstrap := store.CredentialBlob{
		AccessToken:  "at-good",
		RefreshToken: "rt-good",
		ExpiresAt:    time.Now().Add(time.Hour),
		LastRefresh:  time.Now(),
	}
	goodHandle, _ := newFileHandle(t, bootstrap)
	badHandle, _ := newFileHandle(t, store.CredentialBlob{RefreshToken: "rt-bad"})

	badIdP := newFakeIdP(t, idpResponse{
		status: 400, body: `{"error":"invalid_grant"}`,
	})
	goodIdP := newFakeIdP(t, idpResponse{
		status: 200, body: `{"access_token":"at-good","refresh_token":"rt-good","expires_in":3600}`,
	})

	met := newMetrics()
	good := newCredentialUnderTest(t, goodIdP.URL(), goodHandle, met)
	good.cfg.ID = "good"
	good.log = slog.Default().With(slog.String("credential_id", "good"))
	bad := newCredentialUnderTest(t, badIdP.URL(), badHandle, met)
	bad.cfg.ID = "bad"
	bad.log = slog.Default().With(slog.String("credential_id", "bad"))

	require.NoError(t, good.load(t.Context()))
	require.NoError(t, bad.load(t.Context()))

	// Bad fails permanently; good keeps serving cached.
	require.Error(t, bad.refreshOnce(t.Context()))
	_, _, dead, _ := bad.snapshot()
	require.True(t, dead)

	tok, _, err := good.AccessToken(t.Context())
	require.NoError(t, err)
	require.Equal(t, "at-good", tok)
}

func TestNextRefreshAtEnforcesCeiling(t *testing.T) {
	c := &credentialState{}
	c.cfg.EarlyRefreshSlack = 5 * time.Minute
	c.cfg.MaxRefreshInterval = 1 * time.Hour
	now := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }
	c.haveBlob = true
	c.blob = store.CredentialBlob{
		LastRefresh: now.Add(-30 * time.Minute),
		ExpiresAt:   now.Add(24 * time.Hour), // far in the future
	}
	next := c.nextRefreshAt()
	// Ceiling wins because expiry is 24h out but ceiling is 30m from now.
	require.True(t, next.Equal(now.Add(30*time.Minute)),
		"expected ceiling at %s, got %s", now.Add(30*time.Minute), next)
}

func TestNextRefreshAtPicksEarlyWhenNearExpiry(t *testing.T) {
	c := &credentialState{}
	c.cfg.EarlyRefreshSlack = 5 * time.Minute
	c.cfg.MaxRefreshInterval = 1 * time.Hour
	now := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }
	c.haveBlob = true
	c.blob = store.CredentialBlob{
		LastRefresh: now,
		ExpiresAt:   now.Add(15 * time.Minute),
	}
	next := c.nextRefreshAt()
	// expires in 15m, slack 5m → refresh at expires - 5m = +10m.
	require.True(t, next.Equal(now.Add(10*time.Minute)),
		"expected early at %s, got %s", now.Add(10*time.Minute), next)
}

func TestAccessTokenWithExpiredCachedTriggersRefresh(t *testing.T) {
	bootstrap := store.CredentialBlob{
		AccessToken:  "at-stale",
		RefreshToken: "rt-0",
		ExpiresAt:    time.Now().Add(-time.Minute),
		LastRefresh:  time.Now().Add(-time.Hour),
	}
	handle, _ := newFileHandle(t, bootstrap)
	idp := newFakeIdP(t, idpResponse{
		status: 200,
		body:   `{"access_token":"at-fresh","refresh_token":"rt-1","expires_in":3600}`,
	})
	met := newMetrics()
	c := newCredentialUnderTest(t, idp.URL(), handle, met)
	require.NoError(t, c.load(t.Context()))

	tok, _, err := c.AccessToken(t.Context())
	require.NoError(t, err)
	require.Equal(t, "at-fresh", tok)
	require.Equal(t, 1, idp.Calls())
}

func TestLeaderCancelDoesNotPoisonWaiters(t *testing.T) {
	// Two HTTP requests arrive stale at roughly the same time. The
	// leader's caller context is cancelled mid-refresh; the waiter's
	// context is still alive. The waiter must still receive a fresh
	// token because the singleflight closure runs on a detached ctx.
	bootstrap := store.CredentialBlob{
		RefreshToken: "rt-0",
		ExpiresAt:    time.Now().Add(-time.Minute),
		LastRefresh:  time.Now().Add(-time.Hour),
	}
	handle, _ := newFileHandle(t, bootstrap)

	releaseIdP := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-releaseIdP
		_, _ = io.WriteString(w, `{"access_token":"at-fresh","refresh_token":"rt-1","expires_in":3600}`)
	}))
	t.Cleanup(srv.Close)

	met := newMetrics()
	c := newCredentialUnderTest(t, srv.URL, handle, met)
	require.NoError(t, c.load(t.Context()))

	leaderCtx, leaderCancel := context.WithCancel(t.Context())
	waiterCtx, waiterCancel := context.WithCancel(t.Context())
	defer waiterCancel()

	leaderErr := make(chan error, 1)
	waiterTok := make(chan string, 1)
	waiterErr := make(chan error, 1)

	go func() {
		_, _, err := c.AccessToken(leaderCtx)
		leaderErr <- err
	}()
	// Give the leader a head start so it owns the singleflight slot.
	time.Sleep(50 * time.Millisecond)
	go func() {
		tok, _, err := c.AccessToken(waiterCtx)
		waiterTok <- tok
		waiterErr <- err
	}()
	time.Sleep(50 * time.Millisecond)

	// Cancel the leader before the IdP responds.
	leaderCancel()

	// Release the IdP. The detached inner ctx is still alive, so the
	// refresh should complete and the waiter should see the new token.
	close(releaseIdP)

	select {
	case err := <-leaderErr:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("leader did not return")
	}
	select {
	case tok := <-waiterTok:
		require.Equal(t, "at-fresh", tok)
		require.NoError(t, <-waiterErr)
	case <-time.After(2 * time.Second):
		t.Fatal("waiter did not receive a fresh token")
	}
}

func TestSingleflightCoalescesConcurrentRefresh(t *testing.T) {
	bootstrap := store.CredentialBlob{
		RefreshToken: "rt-0",
		ExpiresAt:    time.Now().Add(-time.Minute),
		LastRefresh:  time.Now().Add(-time.Hour),
	}
	handle, _ := newFileHandle(t, bootstrap)

	// Slow IdP so the concurrent calls overlap.
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		time.Sleep(150 * time.Millisecond)
		_, _ = io.WriteString(w, `{"access_token":"at","refresh_token":"rt-1","expires_in":3600}`)
	}))
	t.Cleanup(srv.Close)

	met := newMetrics()
	c := newCredentialUnderTest(t, srv.URL, handle, met)
	require.NoError(t, c.load(t.Context()))

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := c.AccessToken(t.Context())
			require.NoError(t, err)
		}()
	}
	wg.Wait()
	require.Equal(t, int64(1), calls.Load(), "single-flight should coalesce concurrent refreshes")
}

