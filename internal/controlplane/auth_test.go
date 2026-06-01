package controlplane

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBearerTransport(t *testing.T) {
	var capturedReq *http.Request
	var capturedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedReq = r
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := &bearerTransport{
		inner: http.DefaultTransport,
		token: "irpt_test123",
	}

	body := []byte(`{"config_hash":"sha256:abc"}`)
	req, err := http.NewRequest(http.MethodPost, server.URL+"/v1/proxy/sync", bytes.NewReader(body))
	require.NoError(t, err)

	resp, err := transport.RoundTrip(req)
	require.NoError(t, err)
	resp.Body.Close()

	require.Equal(t, "Bearer irpt_test123", capturedReq.Header.Get("Authorization"))
	require.Equal(t, string(body), string(capturedBody), "body should be forwarded intact")
}
