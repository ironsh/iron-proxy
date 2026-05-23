package integration_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/stretchr/testify/require"
)

// TestAWSAuth boots the proxy with the aws_auth transform configured and
// verifies that an SDK-signed request arrives at the upstream with a fresh
// signature minted from the proxy's real credentials, not the placeholder
// the client used.
func TestAWSAuth(t *testing.T) {
	tmpDir := t.TempDir()
	binary := proxyBinary(t)

	var (
		mu      sync.Mutex
		gotAuth string
		gotDate string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		gotDate = r.Header.Get("X-Amz-Date")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfgPath := renderConfig(t, tmpDir, "awsauth.yaml", nil)
	env := []string{
		"AWS_ACCESS_KEY_ID=AKIAEXAMPLE",
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}
	proxy := startProxy(t, binary, cfgPath, env)
	upstreamHost := upstream.Listener.Addr().String()

	body := []byte(`{"prompt":"hi"}`)
	req, err := http.NewRequest("POST", fmt.Sprintf("http://%s/model/foo/invoke", proxy.HTTPAddr), strings.NewReader(string(body)))
	require.NoError(t, err)
	req.Host = upstreamHost
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	// Sign with placeholder credentials, like an AWS SDK would when configured
	// to talk to a sigv4 proxy. The proxy is expected to read the scope, drop
	// this signature, and re-sign with the real env-provided credentials.
	placeholder := aws.Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}
	sum := sha256.Sum256(body)
	require.NoError(t, v4.NewSigner().SignHTTP(
		context.Background(), placeholder, req, hex.EncodeToString(sum[:]),
		"bedrock", "us-east-1", time.Now().UTC(),
	))

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
	require.NotContains(t, gotAuth, "AKIAIOSFODNN7EXAMPLE", "placeholder credential must not appear in outbound Authorization header")
	require.Contains(t, gotAuth, "/us-east-1/bedrock/aws4_request")
	require.Contains(t, gotAuth, "SignedHeaders=")
	require.Contains(t, gotAuth, "Signature=")
	require.Regexp(t, `^\d{8}T\d{6}Z$`, gotDate)
}
