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

	"github.com/ironsh/iron-proxy/internal/transform"
)

func makeSecrets(t *testing.T, entries []secretEntry) *Secrets {
	t.Helper()
	cfg := secretsConfig{
		Source:  "env",
		Secrets: entries,
	}
	getenv := func(key string) string {
		switch key {
		case "OPENAI_API_KEY":
			return "sk-real-openai-key"
		case "ANTHROPIC_API_KEY":
			return "sk-real-anthropic-key"
		case "INTERNAL_TOKEN":
			return "real-internal-token"
		default:
			return ""
		}
	}
	s, err := newFromConfig(cfg, getenv)
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
		Var:          "OPENAI_API_KEY",
		ProxyValue:   "proxy-openai-abc123",
		MatchHeaders: []string{"Authorization"},
		Hosts:        []hostMatch{{Name: "api.openai.com"}},
	}})

	req := httptest.NewRequest("GET", "http://api.openai.com/v1/chat", nil)
	req.Host = "api.openai.com"
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")

	doTransform(t, s, req)

	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
}

func TestSecrets_QueryParamSwap(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Var:        "OPENAI_API_KEY",
		ProxyValue: "proxy-openai-abc123",
		Hosts:      []hostMatch{{Name: "api.openai.com"}},
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
		Var:        "OPENAI_API_KEY",
		ProxyValue: "proxy-openai-abc123",
		MatchBody:  true,
		Hosts:      []hostMatch{{Name: "api.openai.com"}},
	}})

	body := `{"api_key": "proxy-openai-abc123", "model": "gpt-4"}`
	rb := transform.NewReplayableBody(io.NopCloser(strings.NewReader(body)))

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
		Var:          "OPENAI_API_KEY",
		ProxyValue:   "proxy-openai-abc123",
		MatchHeaders: []string{"Authorization"},
		Hosts:        []hostMatch{{Name: "api.openai.com"}},
	}})

	req := httptest.NewRequest("GET", "http://api.openai.com/v1/chat", nil)
	req.Host = "api.openai.com"
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")

	doTransform(t, s, req)
	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
}

func TestSecrets_HostNoMatch(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Var:          "OPENAI_API_KEY",
		ProxyValue:   "proxy-openai-abc123",
		MatchHeaders: []string{"Authorization"},
		Hosts:        []hostMatch{{Name: "api.openai.com"}},
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
		Var:          "ANTHROPIC_API_KEY",
		ProxyValue:   "proxy-anthropic-xyz789",
		MatchHeaders: []string{"X-Api-Key"},
		Hosts:        []hostMatch{{Name: "*.anthropic.com"}},
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
			Var:          "OPENAI_API_KEY",
			ProxyValue:   "proxy-openai-abc123",
			MatchHeaders: []string{"Authorization"},
			Hosts:        []hostMatch{{Name: "api.openai.com"}},
		},
		{
			Var:          "INTERNAL_TOKEN",
			ProxyValue:   "proxy-internal-tok",
			MatchHeaders: []string{"X-Internal"},
			Hosts:        []hostMatch{{Name: "api.openai.com"}},
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
		Var:          "OPENAI_API_KEY",
		ProxyValue:   "proxy-openai-abc123",
		MatchHeaders: []string{"Authorization"},
		Hosts:        []hostMatch{{Name: "api.openai.com"}},
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
		Var:          "OPENAI_API_KEY",
		ProxyValue:   "proxy-openai-abc123",
		MatchHeaders: []string{}, // empty = all headers
		Hosts:        []hostMatch{{Name: "api.openai.com"}},
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
		Source: "env",
		Secrets: []secretEntry{{
			Var:        "NONEXISTENT_VAR",
			ProxyValue: "proxy-value",
			Hosts:      []hostMatch{{Name: "example.com"}},
		}},
	}
	getenv := func(string) string { return "" }

	_, err := newFromConfig(cfg, getenv)
	require.Error(t, err)
	require.Contains(t, err.Error(), "NONEXISTENT_VAR")
	require.Contains(t, err.Error(), "not set or empty")
}

func TestSecrets_EmptyProxyValue(t *testing.T) {
	cfg := secretsConfig{
		Source: "env",
		Secrets: []secretEntry{{
			Var:        "OPENAI_API_KEY",
			ProxyValue: "",
			Hosts:      []hostMatch{{Name: "example.com"}},
		}},
	}
	getenv := func(string) string { return "real-value" }

	_, err := newFromConfig(cfg, getenv)
	require.Error(t, err)
	require.Contains(t, err.Error(), "proxy_value is required")
}

func TestSecrets_UnsupportedSource(t *testing.T) {
	cfg := secretsConfig{
		Source:  "vault",
		Secrets: nil,
	}
	_, err := newFromConfig(cfg, func(string) string { return "" })
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported secrets source")
}

func TestSecrets_BodyTooLarge(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Var:        "OPENAI_API_KEY",
		ProxyValue: "proxy-openai-abc123",
		MatchBody:  true,
		Hosts:      []hostMatch{{Name: "api.openai.com"}},
	}})

	// Create a body larger than defaultBodyMaxBytes (1MB)
	bigBody := strings.Repeat("x", int(defaultBodyMaxBytes)+100)
	rb := transform.NewReplayableBody(io.NopCloser(strings.NewReader(bigBody)))

	req := httptest.NewRequest("POST", "http://api.openai.com/v1/chat", nil)
	req.Host = "api.openai.com"
	req.Body = rb

	// Should not error — just skip body substitution
	doTransform(t, s, req)

	// Body should be unchanged (not buffered, so reads from original)
	// The ReplayableBody couldn't buffer, so reading it gives nothing useful
	// since the original reader was partially consumed by the Buffer attempt.
	// The key assertion is that the transform didn't error or reject.
}

func TestSecrets_HostWithPort(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Var:          "OPENAI_API_KEY",
		ProxyValue:   "proxy-openai-abc123",
		MatchHeaders: []string{"Authorization"},
		Hosts:        []hostMatch{{Name: "api.openai.com"}},
	}})

	req := httptest.NewRequest("GET", "http://api.openai.com:443/v1/chat", nil)
	req.Host = "api.openai.com:443"
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")

	doTransform(t, s, req)

	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
}

func TestSecrets_ResponseIsNoop(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Var:        "OPENAI_API_KEY",
		ProxyValue: "proxy-openai-abc123",
		Hosts:      []hostMatch{{Name: "api.openai.com"}},
	}})

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	resp := &http.Response{StatusCode: http.StatusOK}
	res, err := s.TransformResponse(context.Background(), &transform.TransformContext{}, req, resp)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
}

func TestSecrets_ConcurrentSafety(t *testing.T) {
	s := makeSecrets(t, []secretEntry{{
		Var:          "OPENAI_API_KEY",
		ProxyValue:   "proxy-openai-abc123",
		MatchHeaders: []string{"Authorization"},
		Hosts:        []hostMatch{{Name: "api.openai.com"}},
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
		Var:          "OPENAI_API_KEY",
		ProxyValue:   "proxy-openai-abc123",
		MatchHeaders: []string{"Authorization"},
		Hosts:        []hostMatch{{Name: "api.openai.com"}},
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
		Var:          "OPENAI_API_KEY",
		ProxyValue:   "proxy-openai-abc123",
		MatchHeaders: []string{"Authorization"},
		Hosts:        []hostMatch{{Name: "api.openai.com"}},
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
		Var:          "OPENAI_API_KEY",
		ProxyValue:   "proxy-openai-abc123",
		MatchHeaders: []string{}, // all headers
		Hosts:        []hostMatch{{Name: "api.openai.com"}},
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
		Var:          "OPENAI_API_KEY",
		ProxyValue:   "proxy-openai-abc123",
		MatchHeaders: []string{}, // all headers
		Hosts:        []hostMatch{{Name: "api.openai.com"}},
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

func TestSecrets_Name(t *testing.T) {
	s := makeSecrets(t, nil)
	require.Equal(t, "secrets", s.Name())
}
