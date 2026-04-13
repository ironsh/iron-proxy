package secrets

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

// fakeResolver is a test secretResolver that returns preconfigured values.
type fakeResolver struct {
	secrets map[string]string // keyed by env var name or secret ID
}

func (f *fakeResolver) Resolve(_ context.Context, raw yaml.Node) (ResolveResult, error) {
	// Try env config first, then aws_sm config.
	var env envConfig
	if err := raw.Decode(&env); err == nil && env.Var != "" {
		val, ok := f.secrets[env.Var]
		if !ok || val == "" {
			return ResolveResult{}, &resolveError{env.Var}
		}
		return ResolveResult{Name: env.Var, GetValue: staticValue(val)}, nil
	}
	var sm awsSMConfig
	if err := raw.Decode(&sm); err == nil && sm.SecretID != "" {
		val, ok := f.secrets[sm.SecretID]
		if !ok || val == "" {
			return ResolveResult{}, &resolveError{sm.SecretID}
		}
		return ResolveResult{Name: sm.SecretID, GetValue: staticValue(val)}, nil
	}
	return ResolveResult{}, &resolveError{"unknown"}
}

type resolveError struct{ name string }

func (e *resolveError) Error() string { return e.name + " not found" }

func testRegistry() resolverRegistry {
	return resolverRegistry{
		"env": &fakeResolver{secrets: map[string]string{
			"OPENAI_API_KEY":    "sk-real-openai-key",
			"ANTHROPIC_API_KEY": "sk-real-anthropic-key",
			"INTERNAL_TOKEN":    "real-internal-token",
		}},
		"aws_sm": &fakeResolver{secrets: map[string]string{
			"arn:aws:sm:test": "aws-secret-value",
		}},
	}
}

func envSource(varName string) yaml.Node {
	return yamlNode(&testing.T{}, map[string]string{"type": "env", "var": varName})
}

func awsSMSource(secretID string) yaml.Node {
	return yamlNode(&testing.T{}, map[string]string{"type": "aws_sm", "secret_id": secretID})
}

func makeSecrets(t *testing.T, entries []secretEntry) *Secrets {
	t.Helper()
	cfg := secretsConfig{Secrets: entries}
	s, err := newFromConfig(context.Background(), cfg, testRegistry())
	require.NoError(t, err)
	return s
}

func doTransform(t *testing.T, s *Secrets, req *http.Request) {
	t.Helper()
	res, err := s.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
}

func TestSecrets_HeaderSwap(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Source:       envSource("OPENAI_API_KEY"),
		ProxyValue:   "proxy-openai-abc123",
		MatchHeaders: []string{"Authorization"},
		Rules:        []hostmatch.RuleConfig{{Host: "api.openai.com"}},
	}})

	req := httptest.NewRequest("GET", "http://api.openai.com/v1/chat", nil)
	req.Host = "api.openai.com"
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")

	doTransform(t, s, req)

	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
}

func TestSecrets_QueryParamSwap(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Source:     envSource("OPENAI_API_KEY"),
		ProxyValue: "proxy-openai-abc123",
		Rules:      []hostmatch.RuleConfig{{Host: "api.openai.com"}},
	}})

	req := httptest.NewRequest("GET", "http://api.openai.com/v1/chat?token=proxy-openai-abc123&other=value", nil)
	req.Host = "api.openai.com"

	doTransform(t, s, req)

	require.Contains(t, req.URL.RawQuery, "sk-real-openai-key")
	require.NotContains(t, req.URL.RawQuery, "proxy-openai-abc123")
	require.Contains(t, req.URL.RawQuery, "other=value")
}

func TestSecrets_BodySwap(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Source:     envSource("OPENAI_API_KEY"),
		ProxyValue: "proxy-openai-abc123",
		MatchBody:  true,
		Rules:      []hostmatch.RuleConfig{{Host: "api.openai.com"}},
	}})

	body := `{"api_key": "proxy-openai-abc123", "model": "gpt-4"}`
	rb := transform.NewBufferedBody(io.NopCloser(strings.NewReader(body)), 1<<20)

	req := httptest.NewRequest("POST", "http://api.openai.com/v1/chat", nil)
	req.Host = "api.openai.com"
	req.Body = rb
	req.ContentLength = int64(len(body))

	doTransform(t, s, req)

	result, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	require.Contains(t, string(result), "sk-real-openai-key")
	require.NotContains(t, string(result), "proxy-openai-abc123")
	require.Contains(t, string(result), `"model": "gpt-4"`)
}

func TestSecrets_HostMatch(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Source:       envSource("OPENAI_API_KEY"),
		ProxyValue:   "proxy-openai-abc123",
		MatchHeaders: []string{"Authorization"},
		Rules:        []hostmatch.RuleConfig{{Host: "api.openai.com"}},
	}})

	req := httptest.NewRequest("GET", "http://api.openai.com/v1/chat", nil)
	req.Host = "api.openai.com"
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")

	doTransform(t, s, req)
	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
}

func TestSecrets_HostNoMatch(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Source:       envSource("OPENAI_API_KEY"),
		ProxyValue:   "proxy-openai-abc123",
		MatchHeaders: []string{"Authorization"},
		Rules:        []hostmatch.RuleConfig{{Host: "api.openai.com"}},
	}})

	req := httptest.NewRequest("GET", "http://evil.com/steal", nil)
	req.Host = "evil.com"
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")

	doTransform(t, s, req)

	// Token should NOT be replaced — host doesn't match
	require.Equal(t, "Bearer proxy-openai-abc123", req.Header.Get("Authorization"))
}

func TestSecrets_WildcardHost(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Source:       envSource("ANTHROPIC_API_KEY"),
		ProxyValue:   "proxy-anthropic-xyz789",
		MatchHeaders: []string{"X-Api-Key"},
		Rules:        []hostmatch.RuleConfig{{Host: "*.anthropic.com"}},
	}})

	req := httptest.NewRequest("GET", "http://api.anthropic.com/v1/messages", nil)
	req.Host = "api.anthropic.com"
	req.Header.Set("X-Api-Key", "proxy-anthropic-xyz789")

	doTransform(t, s, req)
	require.Equal(t, "sk-real-anthropic-key", req.Header.Get("X-Api-Key"))
}

func TestSecrets_MultipleSecrets(t *testing.T) {
	s := makeSecrets(t, []secretEntry{
		{
			Source:       envSource("OPENAI_API_KEY"),
			ProxyValue:   "proxy-openai-abc123",
			MatchHeaders: []string{"Authorization"},
			Rules:        []hostmatch.RuleConfig{{Host: "api.openai.com"}},
		},
		{
			Source:       envSource("INTERNAL_TOKEN"),
			ProxyValue:   "proxy-internal-tok",
			MatchHeaders: []string{"X-Internal"},
			Rules:        []hostmatch.RuleConfig{{Host: "api.openai.com"}},
		},
	})

	req := httptest.NewRequest("GET", "http://api.openai.com/v1/chat", nil)
	req.Host = "api.openai.com"
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")
	req.Header.Set("X-Internal", "proxy-internal-tok")

	doTransform(t, s, req)

	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
	require.Equal(t, "real-internal-token", req.Header.Get("X-Internal"))
}

func TestSecrets_MatchHeadersFiltering(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Source:       envSource("OPENAI_API_KEY"),
		ProxyValue:   "proxy-openai-abc123",
		MatchHeaders: []string{"Authorization"},
		Rules:        []hostmatch.RuleConfig{{Host: "api.openai.com"}},
	}})

	req := httptest.NewRequest("GET", "http://api.openai.com/v1/chat", nil)
	req.Host = "api.openai.com"
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")
	req.Header.Set("X-Custom", "proxy-openai-abc123") // not in match_headers

	doTransform(t, s, req)

	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
	// X-Custom should NOT be touched
	require.Equal(t, "proxy-openai-abc123", req.Header.Get("X-Custom"))
}

func TestSecrets_EmptyMatchHeadersSearchesAll(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Source:       envSource("OPENAI_API_KEY"),
		ProxyValue:   "proxy-openai-abc123",
		MatchHeaders: []string{}, // empty = all headers
		Rules:        []hostmatch.RuleConfig{{Host: "api.openai.com"}},
	}})

	req := httptest.NewRequest("GET", "http://api.openai.com/v1/chat", nil)
	req.Host = "api.openai.com"
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")
	req.Header.Set("X-Custom", "proxy-openai-abc123")

	doTransform(t, s, req)

	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
	require.Equal(t, "sk-real-openai-key", req.Header.Get("X-Custom"))
}

func TestSecrets_MissingEnvVar(t *testing.T) {
	cfg := secretsConfig{
		Secrets: []secretEntry{{
			Source:     envSource("NONEXISTENT_VAR"),
			ProxyValue: "proxy-value",
			Rules:      []hostmatch.RuleConfig{{Host: "example.com"}},
		}},
	}
	_, err := newFromConfig(context.Background(), cfg, testRegistry())
	require.Error(t, err)
	require.Contains(t, err.Error(), "NONEXISTENT_VAR")
}

func TestSecrets_EmptyProxyValue(t *testing.T) {
	cfg := secretsConfig{
		Secrets: []secretEntry{{
			Source:     envSource("OPENAI_API_KEY"),
			ProxyValue: "",
			Rules:      []hostmatch.RuleConfig{{Host: "example.com"}},
		}},
	}
	_, err := newFromConfig(context.Background(), cfg, testRegistry())
	require.Error(t, err)
	require.Contains(t, err.Error(), "proxy_value is required")
}

func TestSecrets_UnsupportedSourceType(t *testing.T) {
	node := yamlNode(t, map[string]string{"type": "vault"})
	cfg := secretsConfig{
		Secrets: []secretEntry{{
			Source:     node,
			ProxyValue: "proxy-value",
			Rules:      []hostmatch.RuleConfig{{Host: "example.com"}},
		}},
	}
	_, err := newFromConfig(context.Background(), cfg, testRegistry())
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported source type")
}

func TestSecrets_MissingSourceType(t *testing.T) {
	node := yamlNode(t, map[string]string{"var": "FOO"})
	cfg := secretsConfig{
		Secrets: []secretEntry{{
			Source:     node,
			ProxyValue: "proxy-value",
			Rules:      []hostmatch.RuleConfig{{Host: "example.com"}},
		}},
	}
	_, err := newFromConfig(context.Background(), cfg, testRegistry())
	require.Error(t, err)
	require.Contains(t, err.Error(), "source.type is required")
}

func TestSecrets_BodyTooLarge(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Source:     envSource("OPENAI_API_KEY"),
		ProxyValue: "proxy-openai-abc123",
		MatchBody:  true,
		Rules:      []hostmatch.RuleConfig{{Host: "api.openai.com"}},
	}})

	// Create a body larger than the max (1 MiB)
	bigBody := strings.Repeat("x", (1<<20)+100)
	rb := transform.NewBufferedBody(io.NopCloser(strings.NewReader(bigBody)), 1<<20)

	req := httptest.NewRequest("POST", "http://api.openai.com/v1/chat", nil)
	req.Host = "api.openai.com"
	req.Body = rb

	// Should not error — just skip body substitution
	doTransform(t, s, req)
}

func TestSecrets_HostWithPort(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Source:       envSource("OPENAI_API_KEY"),
		ProxyValue:   "proxy-openai-abc123",
		MatchHeaders: []string{"Authorization"},
		Rules:        []hostmatch.RuleConfig{{Host: "api.openai.com"}},
	}})

	req := httptest.NewRequest("GET", "http://api.openai.com:443/v1/chat", nil)
	req.Host = "api.openai.com:443"
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")

	doTransform(t, s, req)

	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
}

func TestSecrets_ResponseIsNoop(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Source:     envSource("OPENAI_API_KEY"),
		ProxyValue: "proxy-openai-abc123",
		Rules:      []hostmatch.RuleConfig{{Host: "api.openai.com"}},
	}})

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	resp := &http.Response{StatusCode: http.StatusOK}
	res, err := s.TransformResponse(context.Background(), &transform.TransformContext{}, req, resp)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
}

func TestSecrets_ConcurrentSafety(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Source:       envSource("OPENAI_API_KEY"),
		ProxyValue:   "proxy-openai-abc123",
		MatchHeaders: []string{"Authorization"},
		Rules:        []hostmatch.RuleConfig{{Host: "api.openai.com"}},
	}})

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest("GET", "http://api.openai.com/v1/chat", nil)
			req.Host = "api.openai.com"
			req.Header.Set("Authorization", "Bearer proxy-openai-abc123")

			doTransform(t, s, req)

			require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
		}()
	}
	wg.Wait()
}

func TestSecrets_BasicAuthSwap(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Source:       envSource("OPENAI_API_KEY"),
		ProxyValue:   "proxy-openai-abc123",
		MatchHeaders: []string{"Authorization"},
		Rules:        []hostmatch.RuleConfig{{Host: "api.openai.com"}},
	}})

	// Basic auth: "user:proxy-openai-abc123" base64-encoded
	creds := base64.StdEncoding.EncodeToString([]byte("user:proxy-openai-abc123"))
	req := httptest.NewRequest("GET", "http://api.openai.com/v1/chat", nil)
	req.Host = "api.openai.com"
	req.Header.Set("Authorization", "Basic "+creds)

	doTransform(t, s, req)

	got := req.Header.Get("Authorization")
	require.True(t, strings.HasPrefix(got, "Basic "))
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(got, "Basic "))
	require.NoError(t, err)
	require.Equal(t, "user:sk-real-openai-key", string(decoded))
}

func TestSecrets_BasicAuthNoMatch(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Source:       envSource("OPENAI_API_KEY"),
		ProxyValue:   "proxy-openai-abc123",
		MatchHeaders: []string{"Authorization"},
		Rules:        []hostmatch.RuleConfig{{Host: "api.openai.com"}},
	}})

	// Basic auth with no proxy token inside
	creds := base64.StdEncoding.EncodeToString([]byte("user:some-other-password"))
	req := httptest.NewRequest("GET", "http://api.openai.com/v1/chat", nil)
	req.Host = "api.openai.com"
	req.Header.Set("Authorization", "Basic "+creds)

	doTransform(t, s, req)

	// Should be unchanged
	require.Equal(t, "Basic "+creds, req.Header.Get("Authorization"))
}

func TestSecrets_BasicAuthAllHeaders(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Source:       envSource("OPENAI_API_KEY"),
		ProxyValue:   "proxy-openai-abc123",
		MatchHeaders: []string{}, // all headers
		Rules:        []hostmatch.RuleConfig{{Host: "api.openai.com"}},
	}})

	creds := base64.StdEncoding.EncodeToString([]byte("proxy-openai-abc123:secret"))
	req := httptest.NewRequest("GET", "http://api.openai.com/v1/chat", nil)
	req.Host = "api.openai.com"
	req.Header.Set("Authorization", "Basic "+creds)

	doTransform(t, s, req)

	got := req.Header.Get("Authorization")
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(got, "Basic "))
	require.NoError(t, err)
	require.Equal(t, "sk-real-openai-key:secret", string(decoded))
}

func TestSecrets_BasicAuthIgnoredOnNonAuthHeader(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Source:       envSource("OPENAI_API_KEY"),
		ProxyValue:   "proxy-openai-abc123",
		MatchHeaders: []string{}, // all headers
		Rules:        []hostmatch.RuleConfig{{Host: "api.openai.com"}},
	}})

	// "Basic <base64>" on a non-Authorization header should not be decoded
	creds := base64.StdEncoding.EncodeToString([]byte("proxy-openai-abc123:secret"))
	req := httptest.NewRequest("GET", "http://api.openai.com/v1/chat", nil)
	req.Host = "api.openai.com"
	req.Header.Set("X-Custom", "Basic "+creds)

	doTransform(t, s, req)

	// The base64 payload doesn't contain the literal proxy token, so no swap
	require.Equal(t, "Basic "+creds, req.Header.Get("X-Custom"))
}

func TestSecrets_RequireRejectsWithoutProxyToken(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Source:       envSource("OPENAI_API_KEY"),
		ProxyValue:   "proxy-openai-abc123",
		MatchHeaders: []string{"Authorization"},
		Require:      true,
		Rules:        []hostmatch.RuleConfig{{Host: "api.openai.com"}},
	}})

	// Request to matching host but with a different credential — should be rejected.
	req := httptest.NewRequest("GET", "http://api.openai.com/v1/chat", nil)
	req.Host = "api.openai.com"
	req.Header.Set("Authorization", "Bearer sk-some-other-key")

	res, err := s.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)
}

func TestSecrets_RequireContinuesWithProxyToken(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Source:       envSource("OPENAI_API_KEY"),
		ProxyValue:   "proxy-openai-abc123",
		MatchHeaders: []string{"Authorization"},
		Require:      true,
		Rules:        []hostmatch.RuleConfig{{Host: "api.openai.com"}},
	}})

	req := httptest.NewRequest("GET", "http://api.openai.com/v1/chat", nil)
	req.Host = "api.openai.com"
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")

	doTransform(t, s, req)
	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
}

func TestSecrets_RequireDefaultFalseAllowsThrough(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Source:       envSource("OPENAI_API_KEY"),
		ProxyValue:   "proxy-openai-abc123",
		MatchHeaders: []string{"Authorization"},
		// Require defaults to false
		Rules: []hostmatch.RuleConfig{{Host: "api.openai.com"}},
	}})

	// Request without proxy token — should still pass (require is false).
	req := httptest.NewRequest("GET", "http://api.openai.com/v1/chat", nil)
	req.Host = "api.openai.com"
	req.Header.Set("Authorization", "Bearer sk-some-other-key")

	doTransform(t, s, req)
	require.Equal(t, "Bearer sk-some-other-key", req.Header.Get("Authorization"))
}

func TestSecrets_RequireNonMatchingHostAllowsThrough(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Source:       envSource("OPENAI_API_KEY"),
		ProxyValue:   "proxy-openai-abc123",
		MatchHeaders: []string{"Authorization"},
		Require:      true,
		Rules:        []hostmatch.RuleConfig{{Host: "api.openai.com"}},
	}})

	// Request to a different host — host doesn't match, so require doesn't apply.
	req := httptest.NewRequest("GET", "http://other.com/v1/chat", nil)
	req.Host = "other.com"
	req.Header.Set("Authorization", "Bearer sk-some-other-key")

	doTransform(t, s, req)
	require.Equal(t, "Bearer sk-some-other-key", req.Header.Get("Authorization"))
}

func TestSecrets_RequireRejectsNoHeaders(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Source:       envSource("OPENAI_API_KEY"),
		ProxyValue:   "proxy-openai-abc123",
		MatchHeaders: []string{"Authorization"},
		Require:      true,
		Rules:        []hostmatch.RuleConfig{{Host: "api.openai.com"}},
	}})

	// Request to matching host with no Authorization header at all.
	req := httptest.NewRequest("GET", "http://api.openai.com/v1/chat", nil)
	req.Host = "api.openai.com"

	res, err := s.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)
}

func TestSecrets_RequireWithBodySwap(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Source:     envSource("OPENAI_API_KEY"),
		ProxyValue: "proxy-openai-abc123",
		MatchBody:  true,
		Require:    true,
		Rules:      []hostmatch.RuleConfig{{Host: "api.openai.com"}},
	}})

	body := `{"api_key": "proxy-openai-abc123"}`
	rb := transform.NewBufferedBody(io.NopCloser(strings.NewReader(body)), 1<<20)

	req := httptest.NewRequest("POST", "http://api.openai.com/v1/chat", nil)
	req.Host = "api.openai.com"
	req.Body = rb

	doTransform(t, s, req)

	result, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	require.Contains(t, string(result), "sk-real-openai-key")
}

func TestSecrets_Name(t *testing.T) {
	s := makeSecrets(t, nil)
	require.Equal(t, "secrets", s.Name())
}

// --- New tests for rules matching and mixed sources ---

func TestSecrets_MethodFiltering(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Source:       envSource("OPENAI_API_KEY"),
		ProxyValue:   "proxy-openai-abc123",
		MatchHeaders: []string{"Authorization"},
		Rules:        []hostmatch.RuleConfig{{Host: "api.openai.com", Methods: []string{"POST"}}},
	}})

	// GET request should NOT match the rule
	req := httptest.NewRequest("GET", "http://api.openai.com/v1/chat", nil)
	req.Host = "api.openai.com"
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")

	doTransform(t, s, req)
	require.Equal(t, "Bearer proxy-openai-abc123", req.Header.Get("Authorization"))

	// POST request should match
	req = httptest.NewRequest("POST", "http://api.openai.com/v1/chat", nil)
	req.Host = "api.openai.com"
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")

	doTransform(t, s, req)
	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
}

func TestSecrets_PathFiltering(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Source:       envSource("OPENAI_API_KEY"),
		ProxyValue:   "proxy-openai-abc123",
		MatchHeaders: []string{"Authorization"},
		Rules:        []hostmatch.RuleConfig{{Host: "api.openai.com", Paths: []string{"/v1/*"}}},
	}})

	// Path outside /v1/* should NOT match
	req := httptest.NewRequest("GET", "http://api.openai.com/v2/chat", nil)
	req.Host = "api.openai.com"
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")

	doTransform(t, s, req)
	require.Equal(t, "Bearer proxy-openai-abc123", req.Header.Get("Authorization"))

	// Path inside /v1/* should match
	req = httptest.NewRequest("GET", "http://api.openai.com/v1/chat", nil)
	req.Host = "api.openai.com"
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")

	doTransform(t, s, req)
	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
}

func TestSecrets_MixedSourceTypes(t *testing.T) {
	s := makeSecrets(t, []secretEntry{
		{
			Source:       envSource("OPENAI_API_KEY"),
			ProxyValue:   "proxy-openai-abc123",
			MatchHeaders: []string{"Authorization"},
			Rules:        []hostmatch.RuleConfig{{Host: "api.openai.com"}},
		},
		{
			Source:       awsSMSource("arn:aws:sm:test"),
			ProxyValue:   "proxy-aws-tok",
			MatchHeaders: []string{"X-Api-Key"},
			Rules:        []hostmatch.RuleConfig{{Host: "api.openai.com"}},
		},
	})

	req := httptest.NewRequest("GET", "http://api.openai.com/v1/chat", nil)
	req.Host = "api.openai.com"
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")
	req.Header.Set("X-Api-Key", "proxy-aws-tok")

	doTransform(t, s, req)

	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
	require.Equal(t, "aws-secret-value", req.Header.Get("X-Api-Key"))
}

