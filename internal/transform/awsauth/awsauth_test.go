package awsauth

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

type staticSource struct {
	name  string
	value string
	err   error
	calls atomic.Int64
}

func (s *staticSource) Name() string { return s.name }
func (s *staticSource) Get(context.Context) (string, error) {
	s.calls.Add(1)
	return s.value, s.err
}

// mapBuilder dispatches each credential node to a source keyed by the node's
// "var" field. The integration test config writes env-shaped sources so we can
// reuse the same shape.
func mapBuilder(srcs map[string]secrets.Source) sourceBuilder {
	return func(n yaml.Node, _ *slog.Logger) (secrets.Source, error) {
		var c struct {
			Var string `yaml:"var"`
		}
		if err := n.Decode(&c); err != nil {
			return nil, err
		}
		src, ok := srcs[c.Var]
		if !ok {
			return nil, fmt.Errorf("no test source for var %q", c.Var)
		}
		return src, nil
	}
}

func yamlFromString(t *testing.T, src string) yaml.Node {
	t.Helper()
	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(src), &node))
	return *node.Content[0]
}

func newContext() *transform.TransformContext {
	return &transform.TransformContext{Mode: transform.ModeMITM, Logger: slog.Default()}
}

func requestWithBody(t *testing.T, method, rawURL string, body []byte, maxBytes int64) *http.Request {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, rawURL, bodyReader)
	require.NoError(t, err)
	if body == nil {
		req.Body = transform.NewBufferedBody(http.NoBody, maxBytes)
	} else {
		req.Body = transform.NewBufferedBody(io.NopCloser(bytes.NewReader(body)), maxBytes)
		req.ContentLength = int64(len(body))
	}
	return req
}

func buildTransformWith(t *testing.T, cfgYAML string, build sourceBuilder) *AWSAuth {
	t.Helper()
	var c config
	node := yamlFromString(t, cfgYAML)
	require.NoError(t, node.Decode(&c))
	a, err := newFromConfig(c, slog.Default(), build)
	require.NoError(t, err)
	return a
}

const bedrockYAML = `
region: us-east-1
service: bedrock
access_key_id:     {type: env, var: AWS_ACCESS_KEY_ID}
secret_access_key: {type: env, var: AWS_SECRET_ACCESS_KEY}
rules:
  - host: "*.amazonaws.com"
`

func TestNewFromConfig(t *testing.T) {
	srcs := map[string]secrets.Source{
		"AWS_ACCESS_KEY_ID":     &staticSource{name: "access", value: "AKIA"},
		"AWS_SECRET_ACCESS_KEY": &staticSource{name: "secret", value: "shh"},
	}

	t.Run("missing region", func(t *testing.T) {
		var c config
		node := yamlFromString(t, `
service: bedrock
access_key_id:     {type: env, var: AWS_ACCESS_KEY_ID}
secret_access_key: {type: env, var: AWS_SECRET_ACCESS_KEY}
rules:
  - host: "*.amazonaws.com"
`)
		require.NoError(t, node.Decode(&c))
		_, err := newFromConfig(c, slog.Default(), mapBuilder(srcs))
		require.ErrorContains(t, err, "region is required")
	})

	t.Run("missing service", func(t *testing.T) {
		var c config
		node := yamlFromString(t, `
region: us-east-1
access_key_id:     {type: env, var: AWS_ACCESS_KEY_ID}
secret_access_key: {type: env, var: AWS_SECRET_ACCESS_KEY}
rules:
  - host: "*.amazonaws.com"
`)
		require.NoError(t, node.Decode(&c))
		_, err := newFromConfig(c, slog.Default(), mapBuilder(srcs))
		require.ErrorContains(t, err, "service is required")
	})

	t.Run("missing access key", func(t *testing.T) {
		var c config
		node := yamlFromString(t, `
region: us-east-1
service: bedrock
secret_access_key: {type: env, var: AWS_SECRET_ACCESS_KEY}
rules:
  - host: "*.amazonaws.com"
`)
		require.NoError(t, node.Decode(&c))
		_, err := newFromConfig(c, slog.Default(), mapBuilder(srcs))
		require.ErrorContains(t, err, "access_key_id is required")
	})

	t.Run("missing rules", func(t *testing.T) {
		var c config
		node := yamlFromString(t, `
region: us-east-1
service: bedrock
access_key_id:     {type: env, var: AWS_ACCESS_KEY_ID}
secret_access_key: {type: env, var: AWS_SECRET_ACCESS_KEY}
`)
		require.NoError(t, node.Decode(&c))
		_, err := newFromConfig(c, slog.Default(), mapBuilder(srcs))
		require.ErrorContains(t, err, `at least one entry in "rules" is required`)
	})

	t.Run("valid config", func(t *testing.T) {
		a := buildTransformWith(t, bedrockYAML, mapBuilder(srcs))
		require.Equal(t, "us-east-1", a.region)
		require.Equal(t, "bedrock", a.service)
		require.Nil(t, a.sessionToken)
	})

	t.Run("session token wired when present", func(t *testing.T) {
		srcs := map[string]secrets.Source{
			"AWS_ACCESS_KEY_ID":     &staticSource{name: "access", value: "AKIA"},
			"AWS_SECRET_ACCESS_KEY": &staticSource{name: "secret", value: "shh"},
			"AWS_SESSION_TOKEN":     &staticSource{name: "token", value: "tok"},
		}
		a := buildTransformWith(t, `
region: us-east-1
service: bedrock
access_key_id:     {type: env, var: AWS_ACCESS_KEY_ID}
secret_access_key: {type: env, var: AWS_SECRET_ACCESS_KEY}
session_token:     {type: env, var: AWS_SESSION_TOKEN}
rules:
  - host: "*.amazonaws.com"
`, mapBuilder(srcs))
		require.NotNil(t, a.sessionToken)
	})
}

func TestTransformRequest(t *testing.T) {
	srcs := map[string]secrets.Source{
		"AWS_ACCESS_KEY_ID":     &staticSource{name: "access", value: "AKIAEXAMPLE"},
		"AWS_SECRET_ACCESS_KEY": &staticSource{name: "secret", value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
	}

	t.Run("signs matching request with real SDK signer", func(t *testing.T) {
		a := buildTransformWith(t, bedrockYAML, mapBuilder(srcs))
		a.now = func() time.Time { return time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC) }

		req := requestWithBody(t, http.MethodPost, "https://bedrock-runtime.us-east-1.amazonaws.com/model/foo/invoke", []byte(`{"x":1}`), 1<<20)
		res, err := a.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)
		require.Equal(t, transform.ActionContinue, res.Action)

		auth := req.Header.Get("Authorization")
		require.True(t, strings.HasPrefix(auth, "AWS4-HMAC-SHA256 "), "Authorization header = %q", auth)
		require.Contains(t, auth, "Credential=AKIAEXAMPLE/20250102/us-east-1/bedrock/aws4_request")
		require.Contains(t, auth, "SignedHeaders=")
		require.Contains(t, auth, "Signature=")
		require.Equal(t, "20250102T030405Z", req.Header.Get("X-Amz-Date"))
		require.Empty(t, req.Header.Get("X-Amz-Security-Token"))

		// Body must remain readable downstream.
		got, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		require.Equal(t, []byte(`{"x":1}`), got)
	})

	t.Run("session token populates security-token header", func(t *testing.T) {
		srcs := map[string]secrets.Source{
			"AWS_ACCESS_KEY_ID":     &staticSource{name: "access", value: "AKIA"},
			"AWS_SECRET_ACCESS_KEY": &staticSource{name: "secret", value: "shh"},
			"AWS_SESSION_TOKEN":     &staticSource{name: "token", value: "IQoJb3JpZ2luX2VjE..."},
		}
		a := buildTransformWith(t, `
region: us-east-1
service: s3
access_key_id:     {type: env, var: AWS_ACCESS_KEY_ID}
secret_access_key: {type: env, var: AWS_SECRET_ACCESS_KEY}
session_token:     {type: env, var: AWS_SESSION_TOKEN}
rules:
  - host: "*.amazonaws.com"
`, mapBuilder(srcs))

		req := requestWithBody(t, http.MethodGet, "https://bucket.s3.us-east-1.amazonaws.com/key", nil, 1<<20)
		_, err := a.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)
		require.Equal(t, "IQoJb3JpZ2luX2VjE...", req.Header.Get("X-Amz-Security-Token"))
	})

	t.Run("rule miss leaves request untouched", func(t *testing.T) {
		a := buildTransformWith(t, bedrockYAML, mapBuilder(srcs))
		req := requestWithBody(t, http.MethodGet, "https://other.example.com/v1/foo", nil, 1<<20)
		res, err := a.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)
		require.Equal(t, transform.ActionContinue, res.Action)
		require.Empty(t, req.Header.Get("Authorization"))
		require.Empty(t, req.Header.Get("X-Amz-Date"))
	})

	t.Run("first matching rule wins", func(t *testing.T) {
		a := buildTransformWith(t, `
region: us-east-1
service: bedrock
access_key_id:     {type: env, var: AWS_ACCESS_KEY_ID}
secret_access_key: {type: env, var: AWS_SECRET_ACCESS_KEY}
rules:
  - host: "bedrock-runtime.us-east-1.amazonaws.com"
    methods: ["POST"]
  - host: "s3.amazonaws.com"
`, mapBuilder(srcs))

		// First rule matches.
		req := requestWithBody(t, http.MethodPost, "https://bedrock-runtime.us-east-1.amazonaws.com/x", []byte("{}"), 1<<20)
		_, err := a.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)
		require.NotEmpty(t, req.Header.Get("Authorization"))

		// Method mismatch on first rule + host mismatch on second rule -> no match.
		req2 := requestWithBody(t, http.MethodGet, "https://bedrock-runtime.us-east-1.amazonaws.com/x", nil, 1<<20)
		_, err = a.TransformRequest(context.Background(), newContext(), req2)
		require.NoError(t, err)
		require.Empty(t, req2.Header.Get("Authorization"))

		// Second rule matches.
		req3 := requestWithBody(t, http.MethodGet, "https://s3.amazonaws.com/bucket/key", nil, 1<<20)
		_, err = a.TransformRequest(context.Background(), newContext(), req3)
		require.NoError(t, err)
		require.NotEmpty(t, req3.Header.Get("Authorization"))
	})

	t.Run("unsigned payload skips body buffering", func(t *testing.T) {
		var captured string
		a := buildTransformWith(t, `
region: us-east-1
service: s3
access_key_id:     {type: env, var: AWS_ACCESS_KEY_ID}
secret_access_key: {type: env, var: AWS_SECRET_ACCESS_KEY}
unsigned_payload: true
rules:
  - host: "*.amazonaws.com"
`, mapBuilder(srcs))
		a.sign = func(ctx context.Context, creds aws.Credentials, req *http.Request, payloadHash, service, region string, _ time.Time) error {
			captured = payloadHash
			req.Header.Set("X-Amz-Content-Sha256", payloadHash)
			req.Header.Set("Authorization", "stub")
			req.Header.Set("X-Amz-Date", "stub")
			return nil
		}

		// Chunked body (ContentLength < 0) would normally be rejected, but
		// unsigned_payload bypasses body inspection entirely.
		req, err := http.NewRequest(http.MethodPut, "https://bucket.s3.us-east-1.amazonaws.com/key", strings.NewReader("streamed chunk"))
		require.NoError(t, err)
		req.ContentLength = -1
		req.Body = transform.NewBufferedBody(io.NopCloser(strings.NewReader("streamed chunk")), 1<<20)

		_, err = a.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)
		require.Equal(t, "UNSIGNED-PAYLOAD", captured)
	})

	t.Run("chunked body rejected by default", func(t *testing.T) {
		a := buildTransformWith(t, bedrockYAML, mapBuilder(srcs))
		req, err := http.NewRequest(http.MethodPost, "https://bedrock-runtime.us-east-1.amazonaws.com/x", strings.NewReader("body"))
		require.NoError(t, err)
		req.ContentLength = -1
		req.Body = transform.NewBufferedBody(io.NopCloser(strings.NewReader("body")), 1<<20)

		res, err := a.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)
		require.Equal(t, transform.ActionReject, res.Action)
		require.Equal(t, http.StatusBadRequest, res.Response.StatusCode)
	})

	t.Run("credential failure rejects the request", func(t *testing.T) {
		srcs := map[string]secrets.Source{
			"AWS_ACCESS_KEY_ID":     &staticSource{name: "access", err: fmt.Errorf("nope")},
			"AWS_SECRET_ACCESS_KEY": &staticSource{name: "secret", value: "shh"},
		}
		a := buildTransformWith(t, bedrockYAML, mapBuilder(srcs))
		req := requestWithBody(t, http.MethodPost, "https://bedrock-runtime.us-east-1.amazonaws.com/x", []byte("{}"), 1<<20)
		res, err := a.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)
		require.Equal(t, transform.ActionReject, res.Action)
		require.Equal(t, http.StatusBadGateway, res.Response.StatusCode)
	})
}
