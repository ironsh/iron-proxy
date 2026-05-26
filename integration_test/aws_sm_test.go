package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAWSSecretsManager boots the proxy with real AWS Secrets Manager secrets
// and verifies that proxy tokens in request headers are swapped for real values.
func TestAWSSecretsManager(t *testing.T) {
	cases := []struct {
		name, header, sent, want string
	}{
		{"raw_secret", "X-Raw-Secret", "proxy-raw-secret", "example-value"},
		{"kv_secret", "X-KV-Secret", "proxy-kv-secret", "example-value"},
	}

	headers := make([]string, len(cases))
	for i, tc := range cases {
		headers[i] = tc.header
	}
	upstreamHost := echoHeadersUpstream(t, headers...)

	cfgPath := renderConfig(t, t.TempDir(), "aws_sm.yaml", nil)
	proxy := startProxy(t, proxyBinary(t), cfgPath, nil)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, hdr := proxyGet(t, proxy.HTTPAddr, upstreamHost, map[string]string{tc.header: tc.sent})
			require.Equal(t, http.StatusOK, status)
			require.Equal(t, tc.want, hdr.Get(echoedHeaderName(tc.header)))
		})
	}
}
