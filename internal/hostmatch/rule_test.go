package hostmatch

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCompileRules_WildcardMethodMatchesAll(t *testing.T) {
	rules, err := CompileRules([]RuleConfig{
		{Host: "example.com", Methods: []string{"*"}},
	}, "test")
	require.NoError(t, err)
	require.Len(t, rules, 1)
	require.Nil(t, rules[0].Methods, "wildcard method should result in nil Methods (match all)")

	for _, method := range []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"} {
		require.True(t, rules[0].Matches("example.com", method, "/", ""), "method %s should match", method)
	}
}

func TestCompileRules_ExplicitMethodsFiltered(t *testing.T) {
	rules, err := CompileRules([]RuleConfig{
		{Host: "example.com", Methods: []string{"GET", "post"}},
	}, "test")
	require.NoError(t, err)
	require.Len(t, rules, 1)
	require.NotNil(t, rules[0].Methods)

	require.True(t, rules[0].Matches("example.com", "GET", "/", ""))
	require.True(t, rules[0].Matches("example.com", "POST", "/", ""))
	require.False(t, rules[0].Matches("example.com", "DELETE", "/", ""))
}

func TestCompileRules_NoMethodsMatchesAll(t *testing.T) {
	rules, err := CompileRules([]RuleConfig{
		{Host: "example.com"},
	}, "test")
	require.NoError(t, err)
	require.Len(t, rules, 1)
	require.Nil(t, rules[0].Methods)

	require.True(t, rules[0].Matches("example.com", "GET", "/", ""))
	require.True(t, rules[0].Matches("example.com", "DELETE", "/", ""))
}

func TestCompileRules_SourceIPMatching(t *testing.T) {
	cases := []struct {
		name       string
		sourceIP   string
		remoteAddr string
		want       bool
	}{
		{name: "unset matches any source", sourceIP: "", remoteAddr: "203.0.113.9:5000", want: true},
		{name: "unset matches empty source", sourceIP: "", remoteAddr: "", want: true},
		{name: "cidr contains address", sourceIP: "10.1.0.0/16", remoteAddr: "10.1.2.3:44321", want: true},
		{name: "cidr excludes address", sourceIP: "10.1.0.0/16", remoteAddr: "10.2.2.3:44321", want: false},
		{name: "bare ip matches itself", sourceIP: "10.1.2.3", remoteAddr: "10.1.2.3:44321", want: true},
		{name: "bare ip rejects neighbour", sourceIP: "10.1.2.3", remoteAddr: "10.1.2.4:44321", want: false},
		{name: "address without port", sourceIP: "10.1.0.0/16", remoteAddr: "10.1.2.3", want: true},
		{name: "ipv6 cidr contains address", sourceIP: "fd00::/8", remoteAddr: "[fd00::1]:44321", want: true},
		{name: "ipv6 bare address", sourceIP: "fd00::1", remoteAddr: "fd00::1", want: true},
		{name: "unparsable address never matches", sourceIP: "10.1.0.0/16", remoteAddr: "pipe", want: false},
		{name: "empty address never matches", sourceIP: "10.1.0.0/16", remoteAddr: "", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules, err := CompileRules([]RuleConfig{
				{Host: "example.com", SourceIP: tc.sourceIP},
			}, "test")
			require.NoError(t, err)
			require.Len(t, rules, 1)
			require.Equal(t, tc.want, rules[0].Matches("example.com", "GET", "/", tc.remoteAddr))
		})
	}
}

func TestCompileRules_SourceIPCombinesWithHostAndMethod(t *testing.T) {
	rules, err := CompileRules([]RuleConfig{
		{Host: "example.com", SourceIP: "10.1.0.0/16", Methods: []string{"GET"}},
	}, "test")
	require.NoError(t, err)
	require.Len(t, rules, 1)

	require.True(t, rules[0].Matches("example.com", "GET", "/", "10.1.2.3:44321"))
	require.False(t, rules[0].Matches("other.com", "GET", "/", "10.1.2.3:44321"), "host must still gate")
	require.False(t, rules[0].Matches("example.com", "POST", "/", "10.1.2.3:44321"), "method must still gate")
}

func TestCompileRules_SourceIPInvalid(t *testing.T) {
	_, err := CompileRules([]RuleConfig{
		{Host: "example.com", SourceIP: "not-an-ip"},
	}, "test")
	require.Error(t, err)
	require.Contains(t, err.Error(), "source_ip")
}

func TestMatchAnyRule_SourceIPUsesRequestRemoteAddr(t *testing.T) {
	rules, err := CompileRules([]RuleConfig{
		{Host: "example.com", SourceIP: "10.1.0.0/16"},
	}, "test")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "10.1.2.3:44321"
	require.True(t, MatchAnyRule(rules, req))

	req.RemoteAddr = "10.2.2.3:44321"
	require.False(t, MatchAnyRule(rules, req))
}
