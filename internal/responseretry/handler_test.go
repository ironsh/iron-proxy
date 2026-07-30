package responseretry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHandlerDecide(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer proxy-token", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(`{"retry":true,"headers":{"Authorization":"credential"}}`))
		require.NoError(t, err)
	}))
	defer server.Close()
	handler, err := New(server.URL, "proxy-token", []int{409}, server.Client())
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, "https://service.example/v1/search", nil)
	require.NoError(t, err)
	resp := &http.Response{StatusCode: 409, Header: http.Header{"Www-Authenticate": {"challenge"}}}

	headers, retry, err := handler.Decide(context.Background(), req, resp)

	require.NoError(t, err)
	require.True(t, retry)
	require.Equal(t, "credential", headers.Get("Authorization"))
}

func TestHandlerSkipsUnconfiguredStatus(t *testing.T) {
	handler, err := New("http://127.0.0.1/decide", "proxy-token", []int{409}, nil)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, "https://service.example/", nil)
	require.NoError(t, err)

	headers, retry, err := handler.Decide(context.Background(), req, &http.Response{StatusCode: 429})

	require.NoError(t, err)
	require.False(t, retry)
	require.Nil(t, headers)
}

func TestHandlerRejectsForbiddenReplayHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte(`{"retry":true,"headers":{"Host":"other.example"}}`))
		require.NoError(t, err)
	}))
	defer server.Close()
	handler, err := New(server.URL, "proxy-token", []int{409}, server.Client())
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, "https://service.example/", nil)
	require.NoError(t, err)

	_, _, err = handler.Decide(context.Background(), req, &http.Response{StatusCode: 409})

	require.ErrorContains(t, err, "forbidden header Host")
}
