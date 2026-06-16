package management

import (
	"context"
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
	s := newTestServer(t, "secret", func(context.Context) error { return nil })
	rec := do(t, s, http.MethodPost, "/v1/reload", "")
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Equal(t, "unauthorized", decodeError(t, rec.Body))
}

func TestReload_WrongAuth(t *testing.T) {
	s := newTestServer(t, "secret", func(context.Context) error { return nil })
	rec := do(t, s, http.MethodPost, "/v1/reload", "Bearer nope")
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestReload_NonBearerAuth(t *testing.T) {
	s := newTestServer(t, "secret", func(context.Context) error { return nil })
	rec := do(t, s, http.MethodPost, "/v1/reload", "Basic c2VjcmV0")
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestReload_WrongMethod(t *testing.T) {
	s := newTestServer(t, "secret", func(context.Context) error {
		t.Fatal("reload should not run on GET")
		return nil
	})
	rec := do(t, s, http.MethodGet, "/v1/reload", "Bearer secret")
	require.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	require.Equal(t, http.MethodPost, rec.Header().Get("Allow"))
}

func TestReload_Success(t *testing.T) {
	called := 0
	s := newTestServer(t, "secret", func(context.Context) error {
		called++
		return nil
	})
	rec := do(t, s, http.MethodPost, "/v1/reload", "Bearer secret")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, 1, called)

	var resp statusResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Equal(t, "ok", resp.Status)
}

func TestReload_ValidationError(t *testing.T) {
	s := newTestServer(t, "secret", func(context.Context) error {
		return &ValidationError{Err: errors.New("bad transform: missing field")}
	})
	rec := do(t, s, http.MethodPost, "/v1/reload", "Bearer secret")
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	msg := decodeError(t, rec.Body)
	require.True(t, strings.Contains(msg, "bad transform"), "got %q", msg)
}

func TestReload_WrappedValidationError(t *testing.T) {
	// A ValidationError wrapped further down the chain still maps to 422.
	s := newTestServer(t, "secret", func(context.Context) error {
		inner := &ValidationError{Err: errors.New("parse failure")}
		return errors.Join(errors.New("wrapper"), inner)
	})
	rec := do(t, s, http.MethodPost, "/v1/reload", "Bearer secret")
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
}

func TestReload_InternalError(t *testing.T) {
	s := newTestServer(t, "secret", func(context.Context) error {
		return errors.New("disk on fire")
	})
	rec := do(t, s, http.MethodPost, "/v1/reload", "Bearer secret")
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	// Internal errors are not echoed back to the client.
	require.Equal(t, "internal error", decodeError(t, rec.Body))
}

func TestUnknownPath(t *testing.T) {
	s := newTestServer(t, "secret", func(context.Context) error { return nil })
	rec := do(t, s, http.MethodPost, "/anything-else", "Bearer secret")
	require.Equal(t, http.StatusNotFound, rec.Code)
}

func newManagedTestServer(t *testing.T, key string, status func() any, syncNow func()) *Server {
	t.Helper()
	return New(Options{
		Addr:    "127.0.0.1:0",
		APIKey:  key,
		Status:  status,
		SyncNow: syncNow,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

func TestStatus_Success(t *testing.T) {
	s := newManagedTestServer(t, "secret", func() any {
		return map[string]any{"principal_id": "prn_1", "synced_once": true}
	}, func() {})
	rec := do(t, s, http.MethodGet, "/v1/status", "Bearer secret")
	require.Equal(t, http.StatusOK, rec.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.Equal(t, "prn_1", body["principal_id"])
	require.Equal(t, true, body["synced_once"])
}

func TestStatus_MissingAuth(t *testing.T) {
	s := newManagedTestServer(t, "secret", func() any { return nil }, func() {})
	rec := do(t, s, http.MethodGet, "/v1/status", "")
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestStatus_WrongMethod(t *testing.T) {
	s := newManagedTestServer(t, "secret", func() any { return nil }, func() {})
	rec := do(t, s, http.MethodPost, "/v1/status", "Bearer secret")
	require.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestStatus_StandaloneUnavailable(t *testing.T) {
	s := newTestServer(t, "secret", func(context.Context) error { return nil })
	rec := do(t, s, http.MethodGet, "/v1/status", "Bearer secret")
	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestSync_Success(t *testing.T) {
	var poked bool
	s := newManagedTestServer(t, "secret", func() any { return nil }, func() { poked = true })
	rec := do(t, s, http.MethodPost, "/v1/sync", "Bearer secret")
	require.Equal(t, http.StatusAccepted, rec.Code)
	require.True(t, poked)
}

func TestSync_MissingAuth(t *testing.T) {
	s := newManagedTestServer(t, "secret", func() any { return nil }, func() {})
	rec := do(t, s, http.MethodPost, "/v1/sync", "")
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestSync_WrongMethod(t *testing.T) {
	s := newManagedTestServer(t, "secret", func() any { return nil }, func() {})
	rec := do(t, s, http.MethodGet, "/v1/sync", "Bearer secret")
	require.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestSync_StandaloneUnavailable(t *testing.T) {
	s := newTestServer(t, "secret", func(context.Context) error { return nil })
	rec := do(t, s, http.MethodPost, "/v1/sync", "Bearer secret")
	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestReload_ManagedUnavailable(t *testing.T) {
	s := newManagedTestServer(t, "secret", func() any { return nil }, func() {})
	rec := do(t, s, http.MethodPost, "/v1/reload", "Bearer secret")
	require.Equal(t, http.StatusNotFound, rec.Code)
}
