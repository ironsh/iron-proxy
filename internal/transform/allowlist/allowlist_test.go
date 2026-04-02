package allowlist

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/transform"
)

type mockResolver struct {
	hosts map[string][]string
}

func (m *mockResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	addrs, ok := m.hosts[host]
	if !ok {
		return nil, fmt.Errorf("no such host: %s", host)
	}
	return addrs, nil
}

func result(t *testing.T, a *Allowlist, host string) *transform.TransformResult {
	t.Helper()
	req := httptest.NewRequest("GET", "http://"+host+"/", nil)
	req.Host = host
	res, err := a.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	return res
}

func resultWithMethodAndPath(t *testing.T, a *Allowlist, host, method, path string) *transform.TransformResult {
	t.Helper()
	req := httptest.NewRequest(method, "http://"+host+path, nil)
	req.Host = host
	res, err := a.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	return res
}

// --- Existing tests (backwards compat via New) ---

func TestAllowlist_ExactDomainMatch(t *testing.T) {
	a, err := New([]string{"api.openai.com"}, nil, &mockResolver{})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, result(t, a, "api.openai.com").Action)
	require.Equal(t, transform.ActionReject, result(t, a, "evil.com").Action)
}

func TestAllowlist_WildcardDomain(t *testing.T) {
	a, err := New([]string{"*.anthropic.com"}, nil, &mockResolver{})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, result(t, a, "api.anthropic.com").Action)
	require.Equal(t, transform.ActionContinue, result(t, a, "docs.api.anthropic.com").Action)
	require.Equal(t, transform.ActionContinue, result(t, a, "anthropic.com").Action)
	require.Equal(t, transform.ActionReject, result(t, a, "notanthropic.com").Action)
}

func TestAllowlist_HostWithPort(t *testing.T) {
	a, err := New([]string{"api.openai.com"}, nil, &mockResolver{})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, result(t, a, "api.openai.com:443").Action)
	require.Equal(t, transform.ActionReject, result(t, a, "evil.com:443").Action)
}

func TestAllowlist_CIDRMatch(t *testing.T) {
	resolver := &mockResolver{
		hosts: map[string][]string{
			"internal.service": {"10.0.1.5"},
			"external.service": {"8.8.8.8"},
		},
	}
	a, err := New(nil, []string{"10.0.0.0/8"}, resolver)
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, result(t, a, "internal.service").Action)
	require.Equal(t, transform.ActionReject, result(t, a, "external.service").Action)
}

func TestAllowlist_MultipleCIDRs(t *testing.T) {
	resolver := &mockResolver{
		hosts: map[string][]string{
			"a": {"10.0.0.1"},
			"b": {"172.16.0.1"},
			"c": {"8.8.8.8"},
		},
	}
	a, err := New(nil, []string{"10.0.0.0/8", "172.16.0.0/12"}, resolver)
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, result(t, a, "a").Action)
	require.Equal(t, transform.ActionContinue, result(t, a, "b").Action)
	require.Equal(t, transform.ActionReject, result(t, a, "c").Action)
}

func TestAllowlist_DomainMatchSkipsCIDR(t *testing.T) {
	// If domain matches, CIDR check is not needed (even if resolver would fail)
	resolver := &mockResolver{} // no hosts — would fail lookup
	a, err := New([]string{"allowed.com"}, []string{"10.0.0.0/8"}, resolver)
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, result(t, a, "allowed.com").Action)
}

func TestAllowlist_UnresolvableHostDenied(t *testing.T) {
	resolver := &mockResolver{} // no hosts
	a, err := New(nil, []string{"10.0.0.0/8"}, resolver)
	require.NoError(t, err)

	require.Equal(t, transform.ActionReject, result(t, a, "unknown.host").Action)
}

func TestAllowlist_EmptyAllowlistDeniesAll(t *testing.T) {
	a, err := New(nil, nil, &mockResolver{})
	require.NoError(t, err)

	require.Equal(t, transform.ActionReject, result(t, a, "anything.com").Action)
}

func TestAllowlist_MultipleDomains(t *testing.T) {
	a, err := New([]string{"a.com", "b.com", "*.c.com"}, nil, &mockResolver{})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, result(t, a, "a.com").Action)
	require.Equal(t, transform.ActionContinue, result(t, a, "b.com").Action)
	require.Equal(t, transform.ActionContinue, result(t, a, "sub.c.com").Action)
	require.Equal(t, transform.ActionReject, result(t, a, "d.com").Action)
}

func TestAllowlist_InvalidCIDR(t *testing.T) {
	_, err := New(nil, []string{"not-a-cidr"}, &mockResolver{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "parsing CIDR")
}

func TestAllowlist_ResponseIsNoop(t *testing.T) {
	a, err := New(nil, nil, &mockResolver{})
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	resp := &http.Response{StatusCode: http.StatusOK}
	res, err := a.TransformResponse(context.Background(), &transform.TransformContext{}, req, resp)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
}

func TestAllowlist_Name(t *testing.T) {
	a, err := New(nil, nil, &mockResolver{})
	require.NoError(t, err)
	require.Equal(t, "allowlist", a.Name())
}

// --- Method matching tests ---

func TestAllowlist_MethodAllowed(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []ruleConfig{{
			Host:    "api.openai.com",
			Methods: []string{"GET", "POST"},
		}},
	}, &mockResolver{})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/").Action)
	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "POST", "/").Action)
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "api.openai.com", "DELETE", "/").Action)
}

func TestAllowlist_MethodsCaseInsensitive(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []ruleConfig{{
			Host:    "api.openai.com",
			Methods: []string{"post"},
		}},
	}, &mockResolver{})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "POST", "/").Action)
}

func TestAllowlist_NoMethodsAllowsAll(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []ruleConfig{{
			Host: "api.openai.com",
		}},
	}, &mockResolver{})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/").Action)
	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "POST", "/").Action)
	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "DELETE", "/").Action)
}

// --- Path matching tests ---

func TestAllowlist_PathGlob(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []ruleConfig{{
			Host:  "api.openai.com",
			Paths: []string{"/v1/*"},
		}},
	}, &mockResolver{})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/v1/models").Action)
	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/v1/chat/completions").Action)
	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/v1").Action)
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/v2/models").Action)
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/").Action)
}

func TestAllowlist_PathExact(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []ruleConfig{{
			Host:  "api.openai.com",
			Paths: []string{"/health"},
		}},
	}, &mockResolver{})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/health").Action)
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/health/deep").Action)
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/other").Action)
}

func TestAllowlist_NoPathsAllowsAll(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []ruleConfig{{
			Host: "api.openai.com",
		}},
	}, &mockResolver{})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/anything").Action)
	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/v1/models").Action)
}

func TestAllowlist_MultiplePaths(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []ruleConfig{{
			Host:  "api.openai.com",
			Paths: []string{"/v1/chat", "/v1/models"},
		}},
	}, &mockResolver{})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/v1/chat").Action)
	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/v1/models").Action)
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/v1/other").Action)
}

// --- Combined tests ---

func TestAllowlist_HostMethodPathCombined(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []ruleConfig{{
			Host:    "api.openai.com",
			Methods: []string{"POST"},
			Paths:   []string{"/v1/*"},
		}},
	}, &mockResolver{})
	require.NoError(t, err)

	// All three match
	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "POST", "/v1/chat").Action)
	// Wrong method
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/v1/chat").Action)
	// Wrong path
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "api.openai.com", "POST", "/v2/chat").Action)
	// Wrong host
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "evil.com", "POST", "/v1/chat").Action)
}

func TestAllowlist_MultiRuleSecondMatches(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []ruleConfig{
			{Host: "api.openai.com", Methods: []string{"POST"}},
			{Host: "api.anthropic.com", Methods: []string{"GET"}},
		},
	}, &mockResolver{})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.anthropic.com", "GET", "/").Action)
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "api.anthropic.com", "POST", "/").Action)
}

func TestAllowlist_FlatDomainsAndRulesMixed(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Domains: []string{"open.com"},
		Rules: []ruleConfig{{
			Host:    "restricted.com",
			Methods: []string{"GET"},
		}},
	}, &mockResolver{})
	require.NoError(t, err)

	// Flat domain: all methods allowed
	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "open.com", "DELETE", "/anything").Action)
	// Rule: only GET
	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "restricted.com", "GET", "/").Action)
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "restricted.com", "POST", "/").Action)
}

func TestAllowlist_RuleWithCIDR(t *testing.T) {
	resolver := &mockResolver{
		hosts: map[string][]string{
			"internal.service": {"10.0.1.5"},
		},
	}
	a, err := newFromConfig(allowlistConfig{
		Rules: []ruleConfig{{
			CIDR:    "10.0.0.0/8",
			Methods: []string{"GET"},
		}},
	}, resolver)
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "internal.service", "GET", "/").Action)
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "internal.service", "POST", "/").Action)
}

// --- Validation tests ---

func TestAllowlist_RuleBothHostAndCIDR(t *testing.T) {
	_, err := newFromConfig(allowlistConfig{
		Rules: []ruleConfig{{Host: "a.com", CIDR: "10.0.0.0/8"}},
	}, &mockResolver{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "mutually exclusive")
}

func TestAllowlist_RuleNeitherHostNorCIDR(t *testing.T) {
	_, err := newFromConfig(allowlistConfig{
		Rules: []ruleConfig{{Methods: []string{"GET"}}},
	}, &mockResolver{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "one of host or cidr is required")
}

func TestAllowlist_RuleInvalidPath(t *testing.T) {
	_, err := newFromConfig(allowlistConfig{
		Rules: []ruleConfig{{Host: "a.com", Paths: []string{"no-leading-slash"}}},
	}, &mockResolver{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "must start with /")
}

// --- matchPath unit tests ---

func TestMatchPath(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"/v1/*", "/v1/models", true},
		{"/v1/*", "/v1/chat/completions", true},
		{"/v1/*", "/v1", true},
		{"/v1/*", "/v2/models", false},
		{"/v1/*", "/", false},
		{"/health", "/health", true},
		{"/health", "/health/deep", false},
		{"/health", "/other", false},
		{"/*", "/anything", true},
		{"/*", "/", true},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_%s", tt.pattern, tt.path), func(t *testing.T) {
			require.Equal(t, tt.want, matchPath(tt.pattern, tt.path))
		})
	}
}
