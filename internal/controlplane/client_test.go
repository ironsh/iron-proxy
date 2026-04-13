package controlplane

import (
	"context"
	"encoding/hex"
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

func TestRegisterSuccess(t *testing.T) {
	secret := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/proxies/register", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)

		var body registerRequest
		err := json.NewDecoder(r.Body).Decode(&body)
		require.NoError(t, err)
		require.Equal(t, "irbs_test123", body.BootstrapToken)
		require.Equal(t, []string{"ci", "prod"}, body.Tags)
		require.Equal(t, "1.0.0", body.Version)

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(registerResponse{
			ProxyID: "irnp_01JX",
			Secret:  hex.EncodeToString(secret),
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, testLogger())
	cred, err := client.Register(context.Background(), "irbs_test123", RegisterMetadata{
		Tags:    []string{"ci", "prod"},
		Version: "1.0.0",
	})
	require.NoError(t, err)
	require.Equal(t, "irnp_01JX", cred.ProxyID)
	require.Equal(t, secret, cred.Secret)
}

func TestRegisterExpiredToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(apiError("token_expired", "token expired at 2025-01-01"))
	}))
	defer server.Close()

	client := NewClient(server.URL, testLogger())
	_, err := client.Register(context.Background(), "irbs_expired", RegisterMetadata{})
	require.Error(t, err)

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, ErrTokenExpired, apiErr.Code)
	require.Equal(t, 401, apiErr.StatusCode)
}

func TestRegisterExhaustedToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(apiError("token_exhausted", ""))
	}))
	defer server.Close()

	client := NewClient(server.URL, testLogger())
	_, err := client.Register(context.Background(), "irbs_exhausted", RegisterMetadata{})

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, ErrTokenExhausted, apiErr.Code)
}

func TestRegisterLabelNotPermitted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(apiError("tag_not_permitted", "tag 'admin' is not allowed"))
	}))
	defer server.Close()

	client := NewClient(server.URL, testLogger())
	_, err := client.Register(context.Background(), "irbs_test", RegisterMetadata{Tags: []string{"admin"}})

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, ErrTagNotPermitted, apiErr.Code)
	require.Contains(t, apiErr.Detail, "admin")
}

func TestRegisterRateLimitedThenSuccess(t *testing.T) {
	calls := 0
	secret := []byte{0x01, 0x02}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(apiError("rate_limited", ""))
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(registerResponse{
			ProxyID: "irnp_retry",
			Secret:  hex.EncodeToString(secret),
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, testLogger())
	cred, err := client.Register(context.Background(), "irbs_test", RegisterMetadata{})
	require.NoError(t, err)
	require.Equal(t, "irnp_retry", cred.ProxyID)
	require.Equal(t, 2, calls)
}

func TestSyncSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/proxy/sync", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)

		// Verify HMAC headers are present.
		require.NotEmpty(t, r.Header.Get("X-Iron-Proxy-Id"))
		require.NotEmpty(t, r.Header.Get("X-Iron-Timestamp"))
		require.NotEmpty(t, r.Header.Get("X-Iron-Signature"))

		var body syncRequest
		err := json.NewDecoder(r.Body).Decode(&body)
		require.NoError(t, err)
		require.Equal(t, "sha256:abc", body.ConfigHash)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(SyncResponse{
			ConfigHash: "sha256:def",
			Rules:      json.RawMessage(`[{"name":"allowlist"}]`),
			Secrets:    json.RawMessage(`{"API_KEY":"secret"}`),
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, testLogger())
	client.SetCredential(&Credential{
		ProxyID: "irnp_test",
		Secret:  []byte("hmac-secret"),
	})

	resp, err := client.Sync(context.Background(), "sha256:abc")
	require.NoError(t, err)
	require.Equal(t, "sha256:def", resp.ConfigHash)
	require.NotNil(t, resp.Rules)
	require.NotNil(t, resp.Secrets)
}

func TestSyncUnchanged(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(SyncResponse{
			ConfigHash: "sha256:abc",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, testLogger())
	client.SetCredential(&Credential{ProxyID: "irnp_test", Secret: []byte("s")})

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

	client := NewClient(server.URL, testLogger())
	client.SetCredential(&Credential{ProxyID: "irnp_test", Secret: []byte("s")})

	_, err := client.Sync(context.Background(), "")
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, ErrProxyRevoked, apiErr.Code)
}

func TestSyncHMACSignatureValid(t *testing.T) {
	cred := &Credential{
		ProxyID: "irnp_verify",
		Secret:  []byte("verify-secret"),
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		ts := r.Header.Get("X-Iron-Timestamp")
		sig := r.Header.Get("X-Iron-Signature")
		expected := ComputeSignature(cred.Secret, ts, r.Method, r.URL.Path, body)
		require.Equal(t, expected, sig, "HMAC signature mismatch")

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(SyncResponse{ConfigHash: "sha256:ok"})
	}))
	defer server.Close()

	client := NewClient(server.URL, testLogger())
	client.SetCredential(cred)

	_, err := client.Sync(context.Background(), "sha256:test")
	require.NoError(t, err)
}
