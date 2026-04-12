package controlplane

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPollerInitialSync(t *testing.T) {
	var syncCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		syncCalls.Add(1)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(SyncResponse{
			ConfigHash: "sha256:initial",
			Rules:      json.RawMessage(`[{"name":"test"}]`),
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, testLogger())
	client.SetCredential(&Credential{ProxyID: "irnp_test", Secret: []byte("s")})

	var updateCalled atomic.Int32
	poller := NewPoller(client, "", func(rules json.RawMessage, secrets json.RawMessage) error {
		updateCalled.Add(1)
		require.NotNil(t, rules)
		return nil
	}, testLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_ = poller.Run(ctx)

	require.GreaterOrEqual(t, syncCalls.Load(), int32(1))
	require.GreaterOrEqual(t, updateCalled.Load(), int32(1))
}

func TestPollerNoUpdateOnNullRulesSecrets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(SyncResponse{ConfigHash: "sha256:same"})
	}))
	defer server.Close()

	client := NewClient(server.URL, slog.New(slog.NewTextHandler(io.Discard, nil)))
	client.SetCredential(&Credential{ProxyID: "irnp_test", Secret: []byte("s")})

	var updateCalled atomic.Int32
	poller := NewPoller(client, "sha256:same", func(rules json.RawMessage, secrets json.RawMessage) error {
		updateCalled.Add(1)
		return nil
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_ = poller.Run(ctx)
	require.Equal(t, int32(0), updateCalled.Load())
}

func TestPollerStopsOnRevocation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "proxy_revoked"}})
	}))
	defer server.Close()

	client := NewClient(server.URL, slog.New(slog.NewTextHandler(io.Discard, nil)))
	client.SetCredential(&Credential{ProxyID: "irnp_test", Secret: []byte("s")})

	poller := NewPoller(client, "", nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	err := poller.Run(context.Background())
	require.Error(t, err)

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, ErrProxyRevoked, apiErr.Code)
}

func TestPollerContinuesOnTransientError(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":{"code":"internal_error"}}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(SyncResponse{ConfigHash: "sha256:recovered"})
	}))
	defer server.Close()

	client := NewClient(server.URL, slog.New(slog.NewTextHandler(io.Discard, nil)))
	client.SetCredential(&Credential{ProxyID: "irnp_test", Secret: []byte("s")})

	poller := NewPoller(client, "", nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Run briefly -- the 30s interval means we won't get past the initial sync in 200ms,
	// but the initial sync error should be handled gracefully.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err := poller.Run(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, calls.Load(), int32(1))
}

func TestPollerGracefulShutdown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(SyncResponse{ConfigHash: "sha256:ok"})
	}))
	defer server.Close()

	client := NewClient(server.URL, slog.New(slog.NewTextHandler(io.Discard, nil)))
	client.SetCredential(&Credential{ProxyID: "irnp_test", Secret: []byte("s")})

	poller := NewPoller(client, "", nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- poller.Run(ctx)
	}()

	// Give the poller time to start and do initial sync.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("poller did not shut down in time")
	}
}
