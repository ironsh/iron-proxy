package broker

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func newRefreshTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func TestRefreshSuccessRotatesToken(t *testing.T) {
	var seenForm string
	srv := newRefreshTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		seenForm = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"at-new","refresh_token":"rt-new","expires_in":3600,"token_type":"Bearer"}`)
	})

	rc := newRefreshClient(nil)
	out, err := rc.Refresh(t.Context(), refreshRequest{
		TokenEndpoint: srv.URL,
		ClientID:      "client-A",
		ClientSecret:  "secret-A",
		RefreshToken:  "rt-old",
		Scopes:        []string{"a", "b"},
	})
	require.NoError(t, err)
	require.Equal(t, "at-new", out.AccessToken)
	require.Equal(t, "rt-new", out.RefreshToken)
	require.Equal(t, time.Hour, out.ExpiresIn)
	require.Contains(t, seenForm, "grant_type=refresh_token")
	require.Contains(t, seenForm, "refresh_token=rt-old")
	require.Contains(t, seenForm, "client_id=client-A")
	require.Contains(t, seenForm, "client_secret=secret-A")
	require.Contains(t, seenForm, "scope=a+b")
}

func TestRefreshOmitsEmptyClientSecret(t *testing.T) {
	var seenForm string
	srv := newRefreshTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenForm = string(body)
		_, _ = io.WriteString(w, `{"access_token":"at","expires_in":60}`)
	})

	rc := newRefreshClient(nil)
	_, err := rc.Refresh(t.Context(), refreshRequest{
		TokenEndpoint: srv.URL,
		ClientID:      "public-client",
		RefreshToken:  "rt",
	})
	require.NoError(t, err)
	require.NotContains(t, seenForm, "client_secret")
}

func TestRefreshHandlesNoRefreshTokenRotation(t *testing.T) {
	srv := newRefreshTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"access_token":"at","expires_in":3600}`)
	})

	rc := newRefreshClient(nil)
	out, err := rc.Refresh(t.Context(), refreshRequest{
		TokenEndpoint: srv.URL,
		ClientID:      "c",
		RefreshToken:  "rt",
	})
	require.NoError(t, err)
	require.Equal(t, "at", out.AccessToken)
	require.Empty(t, out.RefreshToken, "caller carries old refresh_token forward")
}

func TestRefreshInvalidGrantNotRetryable(t *testing.T) {
	srv := newRefreshTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_grant","error_description":"refresh token rotated"}`)
	})

	rc := newRefreshClient(nil)
	_, err := rc.Refresh(t.Context(), refreshRequest{
		TokenEndpoint: srv.URL,
		ClientID:      "c",
		RefreshToken:  "rt-stale",
	})
	require.Error(t, err)
	var rErr *refreshError
	require.True(t, errors.As(err, &rErr))
	require.Equal(t, refreshStageOAuth, rErr.Stage)
	require.Equal(t, "invalid_grant", rErr.Code)
	require.False(t, rErr.Retryable)
}

func TestRefreshUnrecoverableCodes(t *testing.T) {
	for _, code := range []string{"invalid_grant", "invalid_client", "unauthorized_client"} {
		code := code
		t.Run(code, func(t *testing.T) {
			srv := newRefreshTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"error":"`+code+`"}`)
			})
			rc := newRefreshClient(nil)
			_, err := rc.Refresh(t.Context(), refreshRequest{
				TokenEndpoint: srv.URL,
				ClientID:      "c",
				RefreshToken:  "rt",
			})
			var rErr *refreshError
			require.True(t, errors.As(err, &rErr))
			require.False(t, rErr.Retryable, "%s must not be retryable", code)
		})
	}
}

func TestRefresh5xxIsRetryable(t *testing.T) {
	srv := newRefreshTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	rc := newRefreshClient(nil)
	_, err := rc.Refresh(t.Context(), refreshRequest{
		TokenEndpoint: srv.URL,
		ClientID:      "c",
		RefreshToken:  "rt",
	})
	var rErr *refreshError
	require.True(t, errors.As(err, &rErr))
	require.True(t, rErr.Retryable)
	require.Equal(t, refreshStageHTTP, rErr.Stage)
	require.Equal(t, http.StatusBadGateway, rErr.StatusCode)
}

func TestRefreshAnyOAuthErrorCodeIsUnrecoverable(t *testing.T) {
	// Every RFC 6749 5.2 code is structural (invalid_request,
	// invalid_client, invalid_grant, unauthorized_client,
	// unsupported_grant_type, invalid_scope), and so is every
	// IdP-specific extension we've encountered (refresh_token_reused,
	// token_revoked, expired_token). If the IdP returned an OAuth code
	// at all, retrying is pointless and — for reuse-detecting IdPs —
	// actively destructive. The broker must mark the credential dead.
	for _, code := range []string{
		"invalid_request",
		"unsupported_grant_type",
		"invalid_scope",
		"refresh_token_reused",
		"token_revoked",
		"expired_token",
		"some_future_vendor_code",
	} {
		code := code
		t.Run(code, func(t *testing.T) {
			srv := newRefreshTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"error":"`+code+`"}`)
			})
			rc := newRefreshClient(nil)
			_, err := rc.Refresh(t.Context(), refreshRequest{
				TokenEndpoint: srv.URL,
				ClientID:      "c",
				RefreshToken:  "rt",
			})
			var rErr *refreshError
			require.True(t, errors.As(err, &rErr))
			require.False(t, rErr.Retryable, "%s must mark the credential dead", code)
			require.Equal(t, code, rErr.Code)
		})
	}
}

func TestRefreshNetworkErrorIsRetryable(t *testing.T) {
	rc := newRefreshClient(&http.Client{Timeout: 200 * time.Millisecond})
	_, err := rc.Refresh(t.Context(), refreshRequest{
		// Address in the documentation block — guaranteed to never connect.
		TokenEndpoint: "http://192.0.2.1:1",
		ClientID:      "c",
		RefreshToken:  "rt",
	})
	var rErr *refreshError
	require.True(t, errors.As(err, &rErr))
	require.True(t, rErr.Retryable)
	require.Equal(t, refreshStageNetwork, rErr.Stage)
}

func TestRefreshEmptyAccessTokenIsRetryable(t *testing.T) {
	// A misbehaving gateway can deliver a malformed 2xx without the
	// credential being invalid. Treat as transient so a single bad
	// response can't permanently kill the credential.
	srv := newRefreshTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"access_token":""}`)
	})
	rc := newRefreshClient(nil)
	_, err := rc.Refresh(t.Context(), refreshRequest{
		TokenEndpoint: srv.URL,
		ClientID:      "c",
		RefreshToken:  "rt",
	})
	var rErr *refreshError
	require.True(t, errors.As(err, &rErr))
	require.True(t, rErr.Retryable)
	require.Equal(t, refreshStageParse, rErr.Stage)
}

func TestRefreshMalformedJSONIsRetryable(t *testing.T) {
	srv := newRefreshTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `not json at all`)
	})
	rc := newRefreshClient(nil)
	_, err := rc.Refresh(t.Context(), refreshRequest{
		TokenEndpoint: srv.URL,
		ClientID:      "c",
		RefreshToken:  "rt",
	})
	var rErr *refreshError
	require.True(t, errors.As(err, &rErr))
	require.True(t, rErr.Retryable)
}

func TestRefreshHandlesRetryAfterMultipleCalls(t *testing.T) {
	// Verify each request is independent — server sees the new
	// refresh_token on the second call. The caller drives this loop.
	var calls atomic.Int64
	srv := newRefreshTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		n := calls.Add(1)
		if n == 1 {
			require.Contains(t, string(body), "refresh_token=rt-0")
		} else {
			require.Contains(t, string(body), "refresh_token=rt-1")
		}
		_, _ = io.WriteString(w, `{"access_token":"at","refresh_token":"rt-`+strings.Repeat("1", int(n))+`","expires_in":60}`)
	})

	rc := newRefreshClient(nil)
	out, err := rc.Refresh(t.Context(), refreshRequest{
		TokenEndpoint: srv.URL,
		ClientID:      "c",
		RefreshToken:  "rt-0",
	})
	require.NoError(t, err)
	require.Equal(t, "rt-1", out.RefreshToken)
	out, err = rc.Refresh(t.Context(), refreshRequest{
		TokenEndpoint: srv.URL,
		ClientID:      "c",
		RefreshToken:  "rt-1",
	})
	require.NoError(t, err)
	require.Equal(t, "rt-11", out.RefreshToken)
}
