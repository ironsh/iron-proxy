package annotate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func makeAnnotate(t *testing.T, groups []annotationGroup) *Annotate {
	t.Helper()
	a, err := newFromConfig(annotateConfig{Annotations: groups}, hostmatch.NullResolver{})
	require.NoError(t, err)
	return a
}

func annotate(t *testing.T, a *Annotate, method, host, path string, headers map[string]string) (map[string]any, *transform.TransformResult) {
	t.Helper()
	req := httptest.NewRequest(method, "http://"+host+path, nil)
	req.Host = host
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	tctx := &transform.TransformContext{}
	res, err := a.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	return tctx.DrainAnnotations(), res
}

func TestAnnotate_MatchingRuleCapturesHeaders(t *testing.T) {
	a := makeAnnotate(t, []annotationGroup{{
		Rules:   []hostmatch.RuleConfig{{Host: "api.openai.com"}},
		Headers: []string{"x-request-id"},
	}})

	ann, res := annotate(t, a, "GET", "api.openai.com", "/", map[string]string{
		"X-Request-Id": "req-123",
	})
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "req-123", ann["header:X-Request-Id"])
}

func TestAnnotate_NoMatchNoAnnotation(t *testing.T) {
	a := makeAnnotate(t, []annotationGroup{{
		Rules:   []hostmatch.RuleConfig{{Host: "api.openai.com"}},
		Headers: []string{"x-request-id"},
	}})

	ann, _ := annotate(t, a, "GET", "evil.com", "/", map[string]string{
		"X-Request-Id": "req-123",
	})
	require.Nil(t, ann)
}

func TestAnnotate_MissingHeaderSkipped(t *testing.T) {
	a := makeAnnotate(t, []annotationGroup{{
		Rules:   []hostmatch.RuleConfig{{Host: "api.openai.com"}},
		Headers: []string{"x-request-id", "x-missing"},
	}})

	ann, _ := annotate(t, a, "GET", "api.openai.com", "/", map[string]string{
		"X-Request-Id": "req-123",
	})
	require.Equal(t, "req-123", ann["header:X-Request-Id"])
	require.Nil(t, ann["header:X-Missing"])
}

func TestAnnotate_MultipleGroups(t *testing.T) {
	a := makeAnnotate(t, []annotationGroup{
		{
			Rules:   []hostmatch.RuleConfig{{Host: "api.openai.com"}},
			Headers: []string{"x-openai-id"},
		},
		{
			Rules:   []hostmatch.RuleConfig{{Host: "api.anthropic.com"}},
			Headers: []string{"x-anthropic-id"},
		},
	})

	ann, _ := annotate(t, a, "GET", "api.anthropic.com", "/", map[string]string{
		"X-Openai-Id":    "oai-123",
		"X-Anthropic-Id": "ant-456",
	})
	require.Nil(t, ann["header:X-Openai-Id"])
	require.Equal(t, "ant-456", ann["header:X-Anthropic-Id"])
}

func TestAnnotate_HeaderNormalization(t *testing.T) {
	// Config uses lowercase, lookup should still work via CanonicalHeaderKey.
	a := makeAnnotate(t, []annotationGroup{{
		Rules:   []hostmatch.RuleConfig{{Host: "example.com"}},
		Headers: []string{"x-request-id"},
	}})

	ann, _ := annotate(t, a, "GET", "example.com", "/", map[string]string{
		"X-Request-Id": "req-abc",
	})
	require.Equal(t, "req-abc", ann["header:X-Request-Id"])
}

func TestAnnotate_WildcardHost(t *testing.T) {
	a := makeAnnotate(t, []annotationGroup{{
		Rules:   []hostmatch.RuleConfig{{Host: "*.anthropic.com"}},
		Headers: []string{"x-api-key"},
	}})

	ann, _ := annotate(t, a, "GET", "api.anthropic.com", "/", map[string]string{
		"X-Api-Key": "key-123",
	})
	require.Equal(t, "key-123", ann["header:X-Api-Key"])

	ann2, _ := annotate(t, a, "GET", "other.com", "/", map[string]string{
		"X-Api-Key": "key-123",
	})
	require.Nil(t, ann2)
}

func TestAnnotate_MethodFiltering(t *testing.T) {
	a := makeAnnotate(t, []annotationGroup{{
		Rules:   []hostmatch.RuleConfig{{Host: "api.openai.com", Methods: []string{"POST"}}},
		Headers: []string{"x-request-id"},
	}})

	ann, _ := annotate(t, a, "POST", "api.openai.com", "/", map[string]string{
		"X-Request-Id": "req-123",
	})
	require.Equal(t, "req-123", ann["header:X-Request-Id"])

	ann2, _ := annotate(t, a, "GET", "api.openai.com", "/", map[string]string{
		"X-Request-Id": "req-123",
	})
	require.Nil(t, ann2)
}

func TestAnnotate_PathFiltering(t *testing.T) {
	a := makeAnnotate(t, []annotationGroup{{
		Rules:   []hostmatch.RuleConfig{{Host: "api.openai.com", Paths: []string{"/v1/*"}}},
		Headers: []string{"x-request-id"},
	}})

	ann, _ := annotate(t, a, "GET", "api.openai.com", "/v1/chat", map[string]string{
		"X-Request-Id": "req-123",
	})
	require.Equal(t, "req-123", ann["header:X-Request-Id"])

	ann2, _ := annotate(t, a, "GET", "api.openai.com", "/v2/chat", map[string]string{
		"X-Request-Id": "req-123",
	})
	require.Nil(t, ann2)
}

func TestAnnotate_AlwaysContinues(t *testing.T) {
	a := makeAnnotate(t, []annotationGroup{{
		Rules:   []hostmatch.RuleConfig{{Host: "api.openai.com"}},
		Headers: []string{"x-request-id"},
	}})

	// Matching request
	_, res := annotate(t, a, "GET", "api.openai.com", "/", nil)
	require.Equal(t, transform.ActionContinue, res.Action)

	// Non-matching request
	_, res2 := annotate(t, a, "GET", "evil.com", "/", nil)
	require.Equal(t, transform.ActionContinue, res2.Action)
}

func TestAnnotate_ResponseIsNoop(t *testing.T) {
	a := makeAnnotate(t, []annotationGroup{{
		Rules:   []hostmatch.RuleConfig{{Host: "api.openai.com"}},
		Headers: []string{"x-request-id"},
	}})

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	resp := &http.Response{StatusCode: http.StatusOK}
	res, err := a.TransformResponse(context.Background(), &transform.TransformContext{}, req, resp)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
}

func TestAnnotate_Name(t *testing.T) {
	a := makeAnnotate(t, []annotationGroup{{
		Rules:   []hostmatch.RuleConfig{{Host: "example.com"}},
		Headers: []string{"x-foo"},
	}})
	require.Equal(t, "annotate", a.Name())
}

func TestAnnotate_HostWithPort(t *testing.T) {
	a := makeAnnotate(t, []annotationGroup{{
		Rules:   []hostmatch.RuleConfig{{Host: "api.openai.com"}},
		Headers: []string{"x-request-id"},
	}})

	ann, _ := annotate(t, a, "GET", "api.openai.com:443", "/", map[string]string{
		"X-Request-Id": "req-123",
	})
	require.Equal(t, "req-123", ann["header:X-Request-Id"])
}

func TestAnnotate_MultipleHeaderValues(t *testing.T) {
	// Header.Get returns the first value for multi-valued headers.
	a := makeAnnotate(t, []annotationGroup{{
		Rules:   []hostmatch.RuleConfig{{Host: "example.com"}},
		Headers: []string{"x-multi"},
	}})

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Host = "example.com"
	req.Header.Add("X-Multi", "first")
	req.Header.Add("X-Multi", "second")
	tctx := &transform.TransformContext{}
	_, err := a.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	ann := tctx.DrainAnnotations()
	require.Equal(t, "first", ann["header:X-Multi"])
}

// --- Validation tests ---

func TestAnnotate_EmptyAnnotationsValidation(t *testing.T) {
	_, err := newFromConfig(annotateConfig{}, hostmatch.NullResolver{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "at least one annotation group is required")
}

func TestAnnotate_EmptyRulesValidation(t *testing.T) {
	_, err := newFromConfig(annotateConfig{
		Annotations: []annotationGroup{{
			Headers: []string{"x-foo"},
		}},
	}, hostmatch.NullResolver{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "at least one rule is required")
}

func TestAnnotate_EmptyHeadersValidation(t *testing.T) {
	_, err := newFromConfig(annotateConfig{
		Annotations: []annotationGroup{{
			Rules: []hostmatch.RuleConfig{{Host: "example.com"}},
		}},
	}, hostmatch.NullResolver{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "at least one header is required")
}
