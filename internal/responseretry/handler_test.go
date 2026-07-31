package responseretry

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testAttemptID = "8ace71a1-4e12-47e5-9df4-f2f660db6a82"

func TestHandlerAuthorizeAndComplete(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer proxy-token", r.Header.Get("Authorization"))
		var request DecisionRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		require.Equal(t, "service.example", request.Host)
		require.Equal(t, "/v1/search?q=one", request.Path)
		require.Equal(t, "sandbox-1", request.SandboxID)
		require.Equal(t, "00-trace-span-01", request.Traceparent)
		require.True(t, request.Replayable)
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(`{"retry":true,"attempt_id":"` + testAttemptID + `","traceparent":"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01","headers":{"Authorization":"credential"}}`))
		require.NoError(t, err)
	})
	mux.HandleFunc("/complete", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer proxy-token", r.Header.Get("Authorization"))
		var request CompletionRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		require.Equal(t, testAttemptID, request.AttemptID)
		require.NotNil(t, request.ReplayStatus)
		require.Equal(t, http.StatusOK, *request.ReplayStatus)
		require.Equal(t, []string{"receipt"}, request.ResponseHeaders["Payment-Receipt"])
		require.Empty(t, request.ResponseHeaders["Set-Cookie"])
		require.Equal(t, "00-trace-span-01", request.Traceparent)
		require.EqualValues(t, 25, request.ReplayDurationMS)
		require.EqualValues(t, 50, request.ChargeDurationMS)
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	handler, err := New(server.URL+"/authorize", server.URL+"/complete", "proxy-token", "sandbox-1", []int{http.StatusPaymentRequired}, false, server.Client())
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, "https://service.example/v1/search?q=one", nil)
	require.NoError(t, err)
	req.Header.Set("Traceparent", "00-trace-span-01")
	resp := &http.Response{
		StatusCode: http.StatusPaymentRequired,
		Header:     http.Header{"Www-Authenticate": {"Payment challenge"}},
	}

	decision, retry, err := handler.Decide(context.Background(), req, resp, true)

	require.NoError(t, err)
	require.True(t, retry)
	require.Equal(t, "credential", decision.Headers.Get("Authorization"))
	require.Equal(t, testAttemptID, decision.AttemptID)
	require.Equal(t, "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", decision.Traceparent)

	replayResp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Payment-Receipt": {"receipt"},
			"Set-Cookie":      {"secret"},
		},
	}
	require.NoError(t, handler.Complete(
		context.Background(),
		decision.AttemptID,
		replayResp,
		"",
		"00-trace-span-01",
		25*time.Millisecond,
		50*time.Millisecond,
	))
}

func TestHandlerSkipsUnconfiguredStatus(t *testing.T) {
	handler, err := New(
		"http://127.0.0.1/authorize",
		"http://127.0.0.1/complete",
		"proxy-token",
		"sandbox-1",
		[]int{http.StatusPaymentRequired},
		false,
		nil,
	)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, "https://service.example/", nil)
	require.NoError(t, err)

	decision, retry, err := handler.Decide(context.Background(), req, &http.Response{StatusCode: http.StatusTooManyRequests}, true)

	require.NoError(t, err)
	require.False(t, retry)
	require.Nil(t, decision)
}

func TestHandlerRejectsForbiddenReplayHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte(`{"retry":true,"attempt_id":"` + testAttemptID + `","headers":{"Host":"other.example"}}`))
		require.NoError(t, err)
	}))
	defer server.Close()
	handler, err := New(server.URL, server.URL, "proxy-token", "sandbox-1", []int{http.StatusPaymentRequired}, false, server.Client())
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, "https://service.example/", nil)
	require.NoError(t, err)

	_, _, err = handler.Decide(context.Background(), req, &http.Response{StatusCode: http.StatusPaymentRequired}, true)

	require.ErrorContains(t, err, "forbidden header Host")
}

func TestHandlerRejectsAuthorizedNonReplayableRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte(`{"retry":true,"attempt_id":"` + testAttemptID + `","headers":{"Authorization":"credential"}}`))
		require.NoError(t, err)
	}))
	defer server.Close()
	handler, err := New(server.URL, server.URL, "proxy-token", "sandbox-1", []int{http.StatusPaymentRequired}, false, server.Client())
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, "https://service.example/", nil)
	require.NoError(t, err)

	_, _, err = handler.Decide(context.Background(), req, &http.Response{StatusCode: http.StatusPaymentRequired}, false)

	require.ErrorContains(t, err, "non-replayable")
}

func TestHandlerRejectsInvalidReturnedTraceparent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte(`{"retry":true,"attempt_id":"` + testAttemptID + `","traceparent":"invalid","headers":{"Authorization":"credential"}}`))
		require.NoError(t, err)
	}))
	defer server.Close()
	handler, err := New(server.URL, server.URL, "proxy-token", "sandbox-1", []int{http.StatusPaymentRequired}, false, server.Client())
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, "https://service.example/", nil)
	require.NoError(t, err)

	_, _, err = handler.Decide(context.Background(), req, &http.Response{StatusCode: http.StatusPaymentRequired}, true)

	require.ErrorContains(t, err, "invalid traceparent")
}
