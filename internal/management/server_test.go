package management

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func newTestServer(t *testing.T, key string, reload ReloadFunc) *Server {
	t.Helper()
	return New(Options{
		Addr:   "127.0.0.1:0",
		APIKey: key,
		Reload: reload,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

func do(t *testing.T, s *Server, method, path, auth string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(rec, req)
	return rec
}

func decodeError(t *testing.T, body io.Reader) string {
	t.Helper()
	var resp errorResponse
	require.NoError(t, json.NewDecoder(body).Decode(&resp))
	return resp.Error
}

func TestReload_MissingAuth(t *testing.T) {
	s := newTestServer(t, "secret", func() error { return nil })
	rec := do(t, s, http.MethodPost, "/reload", "")
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Equal(t, "unauthorized", decodeError(t, rec.Body))
}

func TestReload_WrongAuth(t *testing.T) {
	s := newTestServer(t, "secret", func() error { return nil })
	rec := do(t, s, http.MethodPost, "/reload", "Bearer nope")
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestReload_NonBearerAuth(t *testing.T) {
	s := newTestServer(t, "secret", func() error { return nil })
	rec := do(t, s, http.MethodPost, "/reload", "Basic c2VjcmV0")
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestReload_WrongMethod(t *testing.T) {
	s := newTestServer(t, "secret", func() error {
		t.Fatal("reload should not run on GET")
		return nil
	})
	rec := do(t, s, http.MethodGet, "/reload", "Bearer secret")
	require.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	require.Equal(t, http.MethodPost, rec.Header().Get("Allow"))
}

func TestReload_Success(t *testing.T) {
	called := 0
	s := newTestServer(t, "secret", func() error {
		called++
		return nil
	})
	rec := do(t, s, http.MethodPost, "/reload", "Bearer secret")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, 1, called)

	var resp statusResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Equal(t, "ok", resp.Status)
}

func TestReload_ValidationError(t *testing.T) {
	s := newTestServer(t, "secret", func() error {
		return &ValidationError{Err: errors.New("bad transform: missing field")}
	})
	rec := do(t, s, http.MethodPost, "/reload", "Bearer secret")
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	msg := decodeError(t, rec.Body)
	require.True(t, strings.Contains(msg, "bad transform"), "got %q", msg)
}

func TestReload_WrappedValidationError(t *testing.T) {
	// A ValidationError wrapped further down the chain still maps to 422.
	s := newTestServer(t, "secret", func() error {
		inner := &ValidationError{Err: errors.New("parse failure")}
		return errors.Join(errors.New("wrapper"), inner)
	})
	rec := do(t, s, http.MethodPost, "/reload", "Bearer secret")
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
}

func TestReload_InternalError(t *testing.T) {
	s := newTestServer(t, "secret", func() error {
		return errors.New("disk on fire")
	})
	rec := do(t, s, http.MethodPost, "/reload", "Bearer secret")
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	// Internal errors are not echoed back to the client.
	require.Equal(t, "internal error", decodeError(t, rec.Body))
}

func TestUnknownPath(t *testing.T) {
	s := newTestServer(t, "secret", func() error { return nil })
	rec := do(t, s, http.MethodPost, "/anything-else", "Bearer secret")
	require.Equal(t, http.StatusNotFound, rec.Code)
}
