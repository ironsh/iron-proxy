package controlplane

import (
	"context"
	"encoding/json"
	"errors"
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

	client := NewClient(server.URL, "irpt_test", testLogger())

	var updateCalled atomic.Int32
	poller := NewPoller(client, "", func(u SyncUpdate) error {
		updateCalled.Add(1)
		require.NotNil(t, u.Rules)
		return nil
	}, testLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := poller.Run(ctx)
	require.NoError(t, err)

	require.GreaterOrEqual(t, syncCalls.Load(), int32(1))
	require.GreaterOrEqual(t, updateCalled.Load(), int32(1))
}

func TestPollerInitialSyncDeliversMCP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(SyncResponse{
			ConfigHash: "sha256:mcp",
			MCP:        json.RawMessage(`{"servers":[]}`),
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "irpt_test", testLogger())

	var got SyncUpdate
	var called atomic.Int32
	poller := NewPoller(client, "", func(u SyncUpdate) error {
		called.Add(1)
		got = u
		return nil
	}, testLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := poller.Run(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, called.Load(), int32(1))
	require.JSONEq(t, `{"servers":[]}`, string(got.MCP))
	require.False(t, isNonNullJSON(got.Rules))
	require.False(t, isNonNullJSON(got.Secrets))
}

func TestPollerInitialSyncDeliversTransforms(t *testing.T) {
	transformsRaw := `[{"name":"oauth_token","config":{"tokens":[]}}]`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(SyncResponse{
			ConfigHash: "sha256:transforms",
			Transforms: json.RawMessage(transformsRaw),
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "irpt_test", testLogger())

	var got SyncUpdate
	var called atomic.Int32
	poller := NewPoller(client, "", func(u SyncUpdate) error {
		called.Add(1)
		got = u
		return nil
	}, testLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := poller.Run(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, called.Load(), int32(1))
	require.JSONEq(t, transformsRaw, string(got.Transforms))
	require.False(t, isNonNullJSON(got.Rules))
	require.False(t, isNonNullJSON(got.Secrets))
}

func TestPollerNoUpdateOnNullRulesSecrets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(SyncResponse{ConfigHash: "sha256:same"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "irpt_test", slog.New(slog.NewTextHandler(io.Discard, nil)))

	var updateCalled atomic.Int32
	poller := NewPoller(client, "sha256:same", func(u SyncUpdate) error {
		updateCalled.Add(1)
		return nil
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := poller.Run(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(0), updateCalled.Load())
}

func TestPollerStopsOnRevocation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "proxy_revoked"}})
	}))
	defer server.Close()

	client := NewClient(server.URL, "irpt_test", slog.New(slog.NewTextHandler(io.Discard, nil)))

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

	client := NewClient(server.URL, "irpt_test", slog.New(slog.NewTextHandler(io.Discard, nil)))

	poller := NewPoller(client, "", nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Run briefly. The 10s interval means we won't get past the initial sync in 200ms,
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

	client := NewClient(server.URL, "irpt_test", slog.New(slog.NewTextHandler(io.Discard, nil)))

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

func TestPollerPokeTriggersImmediateSync(t *testing.T) {
	var syncCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := syncCalls.Add(1)
		resp := SyncResponse{ConfigHash: "sha256:one"}
		if n > 1 {
			resp = SyncResponse{
				ConfigHash:  "sha256:two",
				Status:      "assigned",
				PrincipalID: "prn_session",
				Secrets:     json.RawMessage(`[]`),
			}
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "irpt_test", testLogger())
	poller := NewPoller(client, "", nil, testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- poller.Run(ctx) }()

	// The initial sync runs immediately; wait for it.
	require.Eventually(t, func() bool {
		return poller.Status().SyncedOnce
	}, 2*time.Second, 10*time.Millisecond)
	require.Equal(t, "sha256:one", poller.Status().ConfigHash)

	// A poke must trigger the second sync long before the 10s poll interval.
	poller.Poke()
	require.Eventually(t, func() bool {
		return poller.Status().ConfigHash == "sha256:two"
	}, 2*time.Second, 10*time.Millisecond)

	status := poller.Status()
	require.Equal(t, "prn_session", status.PrincipalID)
	require.Equal(t, "assigned", status.PrincipalStatus)
	require.True(t, status.SyncedOnce)
	require.False(t, status.LastSyncAt.IsZero())

	cancel()
	require.NoError(t, <-done)
}

func TestPollerCustomIntervalTriggersSync(t *testing.T) {
	var syncCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		syncCalls.Add(1)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(SyncResponse{ConfigHash: "sha256:ok"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "irpt_test", testLogger())
	poller := NewPollerWithInterval(client, "", nil, testLogger(), 20*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	err := poller.Run(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, syncCalls.Load(), int32(2))
}

func TestJitteredIntervalRange(t *testing.T) {
	base := time.Second
	for range 100 {
		got := jitteredInterval(base, 0.1)
		require.GreaterOrEqual(t, got, 900*time.Millisecond)
		require.LessOrEqual(t, got, 1100*time.Millisecond)
	}
}

func TestPollerStatusRetainsPrincipalOnHashMatch(t *testing.T) {
	var syncCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := syncCalls.Add(1)
		resp := SyncResponse{ConfigHash: "sha256:same"}
		if n == 1 {
			resp.Status = "assigned"
			resp.PrincipalID = "prn_keep"
			resp.Secrets = json.RawMessage(`[]`)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "irpt_test", testLogger())
	poller := NewPoller(client, "", nil, testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- poller.Run(ctx) }()

	require.Eventually(t, func() bool {
		return poller.Status().PrincipalID == "prn_keep"
	}, 2*time.Second, 10*time.Millisecond)

	// Hash-match responses omit the assignment fields; they must be retained.
	poller.Poke()
	require.Eventually(t, func() bool {
		return syncCalls.Load() >= 2
	}, 2*time.Second, 10*time.Millisecond)
	require.Equal(t, "prn_keep", poller.Status().PrincipalID)
	require.Equal(t, "assigned", poller.Status().PrincipalStatus)

	cancel()
	require.NoError(t, <-done)
}

func TestPollerDoesNotAdvanceStatusWhenApplyFails(t *testing.T) {
	var syncCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := syncCalls.Add(1)
		resp := SyncResponse{
			ConfigHash:  "sha256:one",
			Status:      "assigned",
			PrincipalID: "prn_one",
			Secrets:     json.RawMessage(`[]`),
		}
		if n > 1 {
			resp.ConfigHash = "sha256:two"
			resp.PrincipalID = "prn_two"
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "irpt_test", testLogger())
	var updates atomic.Int32
	poller := NewPoller(client, "", func(SyncUpdate) error {
		if updates.Add(1) > 1 {
			return errors.New("apply failed")
		}
		return nil
	}, testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- poller.Run(ctx) }()

	require.Eventually(t, func() bool {
		return poller.Status().PrincipalID == "prn_one"
	}, 2*time.Second, 10*time.Millisecond)

	poller.Poke()
	require.Eventually(t, func() bool {
		return syncCalls.Load() >= 2
	}, 2*time.Second, 10*time.Millisecond)

	status := poller.Status()
	require.Equal(t, "sha256:one", status.ConfigHash)
	require.Equal(t, "prn_one", status.PrincipalID)

	cancel()
	require.NoError(t, <-done)
}

func TestPollerSeedStatus(t *testing.T) {
	client := NewClient("http://127.0.0.1:0", "irpt_test", testLogger())
	poller := NewPoller(client, "", nil, testLogger())
	require.False(t, poller.Status().SyncedOnce)

	poller.SeedStatus(nil)
	require.False(t, poller.Status().SyncedOnce)

	poller.SeedStatus(&SyncResponse{
		ConfigHash:  "sha256:seed",
		Status:      "assigned",
		PrincipalID: "prn_boot",
	})
	status := poller.Status()
	require.True(t, status.SyncedOnce)
	require.Equal(t, "sha256:seed", status.ConfigHash)
	require.Equal(t, "prn_boot", status.PrincipalID)
}
