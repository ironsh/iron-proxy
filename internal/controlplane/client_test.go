package controlplane

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func apiError(code, message string) map[string]any {
	m := map[string]any{"code": code}
	if message != "" {
		m["message"] = message
	}
	return map[string]any{"error": m}
}

func TestSyncSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/proxy/sync", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)

		// Verify the bearer token is sent.
		require.Equal(t, "Bearer irpt_test", r.Header.Get("Authorization"))

		var body syncRequest
		err := json.NewDecoder(r.Body).Decode(&body)
		require.NoError(t, err)
		require.Equal(t, "sha256:abc", body.ConfigHash)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(SyncResponse{
			ConfigHash:  "sha256:def",
			Rules:       json.RawMessage(`[{"name":"allowlist"}]`),
			Secrets:     json.RawMessage(`{"API_KEY":"secret"}`),
			IngestToken: "ingest_token_abc",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "irpt_test", testLogger())

	resp, err := client.Sync(context.Background(), "sha256:abc")
	require.NoError(t, err)
	require.Equal(t, "sha256:def", resp.ConfigHash)
	require.NotNil(t, resp.Rules)
	require.NotNil(t, resp.Secrets)
	require.Equal(t, "ingest_token_abc", resp.IngestToken)
}

func TestSyncUnchanged(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(SyncResponse{
			ConfigHash: "sha256:abc",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "irpt_test", testLogger())

	resp, err := client.Sync(context.Background(), "sha256:abc")
	require.NoError(t, err)
	require.Equal(t, "sha256:abc", resp.ConfigHash)
	require.True(t, resp.Rules == nil || string(resp.Rules) == "null")
	require.True(t, resp.Secrets == nil || string(resp.Secrets) == "null")
}

func TestSyncRevoked(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(apiError("proxy_revoked", ""))
	}))
	defer server.Close()

	client := NewClient(server.URL, "irpt_test", testLogger())

	_, err := client.Sync(context.Background(), "")
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, ErrProxyRevoked, apiErr.Code)
}
