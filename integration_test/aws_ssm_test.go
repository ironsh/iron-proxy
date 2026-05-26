package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAWSSystemsManagerParameterStore boots the proxy with real AWS SSM
// Parameter Store parameters and verifies proxy token replacement.
func TestAWSSystemsManagerParameterStore(t *testing.T) {
	cases := []struct {
		name, header, sent, want string
	}{
		{"raw_parameter", "X-Raw-Param", "proxy-raw-param", "example_raw_value"},
		{"json_parameter", "X-JSON-Param", "proxy-json-param", "example_value"},
	}

	headers := make([]string, len(cases))
	for i, tc := range cases {
		headers[i] = tc.header
	}
	upstreamHost := echoHeadersUpstream(t, headers...)

	cfgPath := renderConfig(t, t.TempDir(), "aws_ssm.yaml", nil)
	proxy := startProxy(t, proxyBinary(t), cfgPath, nil)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, hdr := proxyGet(t, proxy.HTTPAddr, upstreamHost, map[string]string{tc.header: tc.sent})
			require.Equal(t, http.StatusOK, status)
			require.Equal(t, tc.want, hdr.Get(echoedHeaderName(tc.header)))
		})
	}
}
