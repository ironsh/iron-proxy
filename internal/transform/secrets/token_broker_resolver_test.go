package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testBrokerBearer = "test-bearer-token"

// newTestTokenBrokerBuilder wires the builder against a real httptest.Server.
// The returned baseURL/bearer are what the cache would read from env in
// production. now lets tests freeze time so expires_at validation is
// deterministic.
func newTestTokenBrokerBuilder(t *testing.T, baseURL, bearer string, now func() time.Time) *tokenBrokerBuilder {
	t.Helper()
	return &tokenBrokerBuilder{
		clientFor: func() (brokerHTTPClient, string, string, error) {
			return http.DefaultClient, baseURL, bearer, nil
		},
		logger: slog.Default(),
		now:    now,
	}
}

// fakeBroker is a configurable test double for the broker's HTTP API. Each
// test wires its own handler via respond. The server tracks call counts and
// captured request paths/headers so assertions can verify caching behavior
// and auth wiring.
type fakeBroker struct {
	server   *httptest.Server
	calls    atomic.Int64
	lastAuth atomic.Value // string
	lastPath atomic.Value // string
}

func newFakeBroker(t *testing.T, respond http.HandlerFunc) *fakeBroker {
	t.Helper()
	fb := &fakeBroker{}
	fb.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fb.calls.Add(1)
		fb.lastAuth.Store(r.Header.Get("Authorization"))
		fb.lastPath.Store(r.URL.Path)
		respond(w, r)
	}))
	t.Cleanup(fb.server.Close)
	return fb
}

func (fb *fakeBroker) URL() string  { return fb.server.URL }
func (fb *fakeBroker) Calls() int64 { return fb.calls.Load() }

func (fb *fakeBroker) LastAuth() string {
	v := fb.lastAuth.Load()
	if v == nil {
		return ""
	}
	return v.(string)
}

func (fb *fakeBroker) LastPath() string {
	v := fb.lastPath.Load()
	if v == nil {
		return ""
	}
	return v.(string)
}

// respondAccessToken returns a handler that writes a 200 with the given
// access_token and expires_at.
func respondAccessToken(token string, expiresAt time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": token,
			"expires_at":   expiresAt.Format(time.RFC3339Nano),
		})
	}
}

// respondError returns a handler that writes the given status and a JSON
// error body shaped like the broker's real responses.
func respondError(status int, errMsg, reason string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		body := map[string]string{"error": errMsg}
		if reason != "" {
			body["reason"] = reason
		}
		_ = json.NewEncoder(w).Encode(body)
	}
}

func TestTokenBrokerBuilder_HappyPath(t *testing.T) {
	now := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	fb := newFakeBroker(t, respondAccessToken("the-token", now.Add(time.Hour)))

	r := newTestTokenBrokerBuilder(t, fb.URL(), testBrokerBearer, func() time.Time { return now })
	src, err := r.Build(yamlNode(t, map[string]string{
		"type":          "token_broker",
		"credential_id": "openai-codex",
	}))
	require.NoError(t, err)
	require.Equal(t, "token_broker:openai-codex", src.Name())

	val, err := src.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "the-token", val)
	require.Equal(t, "Bearer "+testBrokerBearer, fb.LastAuth())
	require.Equal(t, "/credentials/openai-codex/access_token", fb.LastPath())
	require.Equal(t, int64(1), fb.Calls())
}

func TestTokenBrokerBuilder_CachesWithinTTL(t *testing.T) {
	now := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	fb := newFakeBroker(t, respondAccessToken("the-token", now.Add(time.Hour)))

	r := newTestTokenBrokerBuilder(t, fb.URL(), testBrokerBearer, func() time.Time { return now })
	src, err := r.Build(yamlNode(t, map[string]string{
		"type":          "token_broker",
		"credential_id": "openai-codex",
		"ttl":           "1m",
	}))
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		val, err := src.Get(context.Background())
		require.NoError(t, err)
		require.Equal(t, "the-token", val)
	}
	require.Equal(t, int64(1), fb.Calls(), "second and subsequent gets should be served from cache")
}

func TestTokenBrokerBuilder_RejectsResponseWithExpiresAtAtOrBelowTTL(t *testing.T) {
	tests := []struct {
		name      string
		remaining time.Duration
	}{
		{"expires before ttl elapses", 30 * time.Second},
		{"expires exactly at ttl", time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
			fb := newFakeBroker(t, respondAccessToken("the-token", now.Add(tt.remaining)))

			r := newTestTokenBrokerBuilder(t, fb.URL(), testBrokerBearer, func() time.Time { return now })
			src, err := r.Build(yamlNode(t, map[string]string{
				"type":          "token_broker",
				"credential_id": "openai-codex",
				"ttl":           "1m",
			}))
			require.NoError(t, err)

			_, err = src.Get(context.Background())
			require.Error(t, err)
			require.Contains(t, err.Error(), "remaining lifetime")
		})
	}
}

func TestTokenBrokerBuilder_HTTPErrorsArePropagated(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		errMsg      string
		reason      string
		wantContains string
	}{
		{"401 unauthorized", http.StatusUnauthorized, "unauthorized", "", "401"},
		{"404 not found", http.StatusNotFound, "credential not found", "", "404"},
		{"422 credential dead", http.StatusUnprocessableEntity, "credential dead", "invalid_grant", "422"},
		{"503 bootstrapping", http.StatusServiceUnavailable, "bootstrapping", "", "503"},
		{"500 internal", http.StatusInternalServerError, "internal error", "", "500"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fb := newFakeBroker(t, respondError(tt.status, tt.errMsg, tt.reason))
			r := newTestTokenBrokerBuilder(t, fb.URL(), testBrokerBearer, time.Now)
			src, err := r.Build(yamlNode(t, map[string]string{
				"type":          "token_broker",
				"credential_id": "openai-codex",
			}))
			require.NoError(t, err)

			_, err = src.Get(context.Background())
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantContains)
			require.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

func TestTokenBrokerBuilder_RejectsMalformedJSON(t *testing.T) {
	fb := newFakeBroker(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not json"))
	})
	r := newTestTokenBrokerBuilder(t, fb.URL(), testBrokerBearer, time.Now)
	src, err := r.Build(yamlNode(t, map[string]string{
		"type":          "token_broker",
		"credential_id": "openai-codex",
	}))
	require.NoError(t, err)

	_, err = src.Get(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "decoding broker response")
}

func TestTokenBrokerBuilder_RejectsEmptyAccessToken(t *testing.T) {
	now := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	fb := newFakeBroker(t, respondAccessToken("", now.Add(time.Hour)))
	r := newTestTokenBrokerBuilder(t, fb.URL(), testBrokerBearer, func() time.Time { return now })
	src, err := r.Build(yamlNode(t, map[string]string{
		"type":          "token_broker",
		"credential_id": "openai-codex",
	}))
	require.NoError(t, err)

	_, err = src.Get(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty access_token")
}

func TestTokenBrokerBuilder_RejectsZeroExpiresAt(t *testing.T) {
	fb := newFakeBroker(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok"})
	})
	r := newTestTokenBrokerBuilder(t, fb.URL(), testBrokerBearer, time.Now)
	src, err := r.Build(yamlNode(t, map[string]string{
		"type":          "token_broker",
		"credential_id": "openai-codex",
	}))
	require.NoError(t, err)

	_, err = src.Get(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "no expires_at")
}

func TestTokenBrokerBuilder_BuildErrors(t *testing.T) {
	tests := []struct {
		name   string
		input  map[string]string
		errMsg string
	}{
		{
			name:   "missing credential_id",
			input:  map[string]string{"type": "token_broker"},
			errMsg: "\"credential_id\" field",
		},
		{
			name:   "ttl zero rejected",
			input:  map[string]string{"type": "token_broker", "credential_id": "foo", "ttl": "0s"},
			errMsg: "ttl > 0",
		},
		{
			name:   "ttl negative rejected",
			input:  map[string]string{"type": "token_broker", "credential_id": "foo", "ttl": "-1s"},
			errMsg: "ttl > 0",
		},
		{
			name:   "ttl malformed rejected",
			input:  map[string]string{"type": "token_broker", "credential_id": "foo", "ttl": "not-a-duration"},
			errMsg: "parsing ttl",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newTestTokenBrokerBuilder(t, "http://example.invalid", testBrokerBearer, time.Now)
			_, err := r.Build(yamlNode(t, tt.input))
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

func TestBrokerAccessTokenURL(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		credID  string
		want    string
		wantErr string
	}{
		{
			name:    "no path",
			baseURL: "https://broker.example.com",
			credID:  "openai-codex",
			want:    "https://broker.example.com/credentials/openai-codex/access_token",
		},
		{
			name:    "trailing slash trimmed",
			baseURL: "https://broker.example.com/",
			credID:  "openai-codex",
			want:    "https://broker.example.com/credentials/openai-codex/access_token",
		},
		{
			name:    "with subpath",
			baseURL: "https://gateway.example.com/broker",
			credID:  "openai-codex",
			want:    "https://gateway.example.com/broker/credentials/openai-codex/access_token",
		},
		{
			name:    "credential id escaped",
			baseURL: "https://broker.example.com",
			credID:  "foo/bar baz",
			want:    "https://broker.example.com/credentials/foo%2Fbar%20baz/access_token",
		},
		{
			name:    "missing scheme",
			baseURL: "broker.example.com",
			credID:  "x",
			wantErr: "must include scheme and host",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := brokerAccessTokenURL(tt.baseURL, tt.credID)
			if tt.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

// --- brokerClientCache tests ---

func TestBrokerClientCache_ReadsEnvOnFirstUse(t *testing.T) {
	calls := 0
	cache := &brokerClientCache{
		getenv: func(key string) string {
			switch key {
			case defaultBrokerURLEnv:
				return "https://broker.example.com"
			case defaultBrokerTokenEnv:
				return "tok"
			}
			return ""
		},
		newClient: func() brokerHTTPClient { calls++; return http.DefaultClient },
	}
	client, baseURL, bearer, err := cache.get()
	require.NoError(t, err)
	require.NotNil(t, client)
	require.Equal(t, "https://broker.example.com", baseURL)
	require.Equal(t, "tok", bearer)
	require.Equal(t, 1, calls)

	// Second call reuses the cached client.
	_, _, _, err = cache.get()
	require.NoError(t, err)
	require.Equal(t, 1, calls)
}

func TestBrokerClientCache_ErrorOnMissingURL(t *testing.T) {
	cache := &brokerClientCache{
		getenv:    func(string) string { return "" },
		newClient: func() brokerHTTPClient { return http.DefaultClient },
	}
	_, _, _, err := cache.get()
	require.Error(t, err)
	require.Contains(t, err.Error(), fmt.Sprintf("%q is not set or empty", defaultBrokerURLEnv))
}

func TestBrokerClientCache_ErrorOnMissingToken(t *testing.T) {
	cache := &brokerClientCache{
		getenv: func(key string) string {
			if key == defaultBrokerURLEnv {
				return "https://broker.example.com"
			}
			return ""
		},
		newClient: func() brokerHTTPClient { return http.DefaultClient },
	}
	_, _, _, err := cache.get()
	require.Error(t, err)
	require.Contains(t, err.Error(), fmt.Sprintf("%q is not set or empty", defaultBrokerTokenEnv))
}

func TestDefaultRegistry_IncludesTokenBroker(t *testing.T) {
	reg := defaultRegistry(slog.Default())
	_, ok := reg["token_broker"]
	require.True(t, ok, "token_broker must be registered in defaultRegistry")
}

func TestBrokerClientCache_ErrorNotCached(t *testing.T) {
	var url string
	cache := &brokerClientCache{
		getenv: func(key string) string {
			switch key {
			case defaultBrokerURLEnv:
				return url
			case defaultBrokerTokenEnv:
				return "tok"
			}
			return ""
		},
		newClient: func() brokerHTTPClient { return http.DefaultClient },
	}
	_, _, _, err := cache.get()
	require.Error(t, err)

	url = "https://broker.example.com"
	_, baseURL, _, err := cache.get()
	require.NoError(t, err)
	require.Equal(t, "https://broker.example.com", baseURL)
}
