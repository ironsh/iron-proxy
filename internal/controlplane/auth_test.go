package controlplane

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestComputeSignature(t *testing.T) {
	secret := []byte("testsecret")

	tests := []struct {
		name      string
		timestamp string
		method    string
		path      string
		body      []byte
	}{
		{
			name:      "empty body",
			timestamp: "1744310400",
			method:    "POST",
			path:      "/v1/proxy/sync",
			body:      nil,
		},
		{
			name:      "with json body",
			timestamp: "1744310400",
			method:    "POST",
			path:      "/v1/register",
			body:      []byte(`{"enrollment_token":"irbs_test"}`),
		},
		{
			name:      "get request",
			timestamp: "1744310500",
			method:    "GET",
			path:      "/v1/status",
			body:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig1 := ComputeSignature(secret, tt.timestamp, tt.method, tt.path, tt.body)
			sig2 := ComputeSignature(secret, tt.timestamp, tt.method, tt.path, tt.body)
			require.Equal(t, sig1, sig2, "signature should be deterministic")
			require.Len(t, sig1, 64, "HMAC-SHA256 hex should be 64 chars")

			// Different secret produces different signature.
			sig3 := ComputeSignature([]byte("other"), tt.timestamp, tt.method, tt.path, tt.body)
			require.NotEqual(t, sig1, sig3)
		})
	}
}

func TestHMACTransport(t *testing.T) {
	cred := &Credential{
		ProxyID: "irnp_test123",
		Secret:  []byte("testsecret"),
	}

	var capturedReq *http.Request
	var capturedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedReq = r
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := &hmacTransport{
		inner: http.DefaultTransport,
		cred:  cred,
	}

	body := []byte(`{"config_hash":"sha256:abc"}`)
	req, err := http.NewRequest(http.MethodPost, server.URL+"/v1/proxy/sync", bytes.NewReader(body))
	require.NoError(t, err)

	resp, err := transport.RoundTrip(req)
	require.NoError(t, err)
	resp.Body.Close()

	require.Equal(t, "irnp_test123", capturedReq.Header.Get("X-Iron-Proxy-Id"))
	require.NotEmpty(t, capturedReq.Header.Get("X-Iron-Timestamp"))
	require.NotEmpty(t, capturedReq.Header.Get("X-Iron-Signature"))
	require.Equal(t, string(body), string(capturedBody), "body should be forwarded intact")

	// Verify signature is valid.
	ts := capturedReq.Header.Get("X-Iron-Timestamp")
	sig := capturedReq.Header.Get("X-Iron-Signature")
	expected := ComputeSignature(cred.Secret, ts, "POST", "/v1/proxy/sync", body)
	require.Equal(t, expected, sig)
}
