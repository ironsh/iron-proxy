package integration_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAWSAuth boots the proxy with the aws_auth transform configured and
// verifies that requests routed through it arrive at the upstream with a
// valid-looking AWS Signature Version 4 Authorization header.
func TestAWSAuth(t *testing.T) {
	tmpDir := t.TempDir()
	binary := proxyBinary(t)

	var (
		mu      sync.Mutex
		gotAuth string
		gotDate string
		gotTok  string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		gotDate = r.Header.Get("X-Amz-Date")
		gotTok = r.Header.Get("X-Amz-Security-Token")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfgPath := renderConfig(t, tmpDir, "awsauth.yaml", nil)
	env := []string{
		"AWS_ACCESS_KEY_ID=AKIAEXAMPLE",
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"AWS_SESSION_TOKEN=test-session-token",
	}
	proxy := startProxy(t, binary, cfgPath, env)
	upstreamHost := upstream.Listener.Addr().String()

	req, err := http.NewRequest("POST", fmt.Sprintf("http://%s/model/foo/invoke", proxy.HTTPAddr), strings.NewReader(`{"prompt":"hi"}`))
	require.NoError(t, err)
	req.Host = upstreamHost
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	mu.Lock()
	defer mu.Unlock()
	require.True(t, strings.HasPrefix(gotAuth, "AWS4-HMAC-SHA256 "), "Authorization = %q", gotAuth)
	require.Contains(t, gotAuth, "Credential=AKIAEXAMPLE/")
	require.Contains(t, gotAuth, "/us-east-1/bedrock/aws4_request")
	require.Contains(t, gotAuth, "SignedHeaders=")
	require.Contains(t, gotAuth, "Signature=")
	require.Regexp(t, `^\d{8}T\d{6}Z$`, gotDate)
	require.Equal(t, "test-session-token", gotTok)
}
