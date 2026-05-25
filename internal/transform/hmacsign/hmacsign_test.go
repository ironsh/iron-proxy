package hmacsign

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/headers"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

// --- test doubles ---

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
// "var" field, so tests can give every credential its own static value.
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

// requestWithBody builds an http.Request with a properly wrapped BufferedBody.
// maxBytes mirrors the pipeline's per-request body cap.
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

func buildTransformWith(t *testing.T, cfgYAML string, build sourceBuilder) *HMACSign {
	t.Helper()
	var c config
	node := yamlFromString(t, cfgYAML)
	require.NoError(t, node.Decode(&c))
	h, err := newFromConfig(c, slog.Default(), build)
	require.NoError(t, err)
	return h
}

// fixedNow returns a now-func that always returns t.
func fixedNow(unixSeconds int64) func() time.Time {
	return func() time.Time { return time.Unix(unixSeconds, 0).UTC() }
}

const falconxYAML = `
timestamp:
  format: unix_seconds
signature:
  algorithm: sha256
  key_encoding: base64
  output_encoding: base64
  message: "{{.Timestamp}}{{.Method}}{{.PathWithQuery}}{{.Body}}"
credentials:
  key:        {type: env, var: KEY}
  secret:     {type: env, var: SECRET}
  passphrase: {type: env, var: PASSPHRASE}
headers:
  - name: "FX-ACCESS-KEY"
    value: "{{.Credentials.key}}"
  - name: "FX-ACCESS-SIGN"
    value: "{{.Signature}}"
  - name: "FX-ACCESS-TIMESTAMP"
    value: "{{.Timestamp}}"
  - name: "FX-ACCESS-PASSPHRASE"
    value: "{{.Credentials.passphrase}}"
rules:
  - host: "api.falconx.io"
`

func TestTransformRequest(t *testing.T) {
	t.Run("falconx scheme matches reference vector", func(t *testing.T) {
		// Generated offline with the FalconX docs Python snippet:
		//   secret_b64 = base64.b64encode(b'supersecretkey-bytes').decode()
		//                = "c3VwZXJzZWNyZXRrZXktYnl0ZXM="
		//   msg         = "1700000000POST/v1/quotes?account=acct1" + body
		//   sig         = base64(HMAC_SHA256(base64decode(secret_b64), msg))
		const (
			wantSig       = "osdip9KkbMtE/ZfIpdt432z++Syz0fIQ3M6mAsfbr6Q="
			wantTimestamp = "1700000000"
		)
		body := []byte(`{"base":"BTC","quote":"USD","quantity":"1"}`)

		h := buildTransformWith(t, falconxYAML, mapBuilder(map[string]secrets.Source{
			"KEY":        &staticSource{name: "key", value: "the-api-key"},
			"SECRET":     &staticSource{name: "secret", value: "c3VwZXJzZWNyZXRrZXktYnl0ZXM="},
			"PASSPHRASE": &staticSource{name: "pass", value: "the-passphrase"},
		}))
		h.now = fixedNow(1700000000)

		req := requestWithBody(t, http.MethodPost, "https://api.falconx.io/v1/quotes?account=acct1", body, 1<<20)
		res, err := h.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)
		require.Equal(t, transform.ActionContinue, res.Action)

		require.Equal(t, []string{"the-api-key"}, headers.Values(req.Header, "FX-ACCESS-KEY"))
		require.Equal(t, []string{wantSig}, headers.Values(req.Header, "FX-ACCESS-SIGN"))
		require.Equal(t, []string{wantTimestamp}, headers.Values(req.Header, "FX-ACCESS-TIMESTAMP"))
		require.Equal(t, []string{"the-passphrase"}, headers.Values(req.Header, "FX-ACCESS-PASSPHRASE"))
	})

	t.Run("sha512 hex output with raw key", func(t *testing.T) {
		// HMAC_SHA512(b"rawsecret123", "1700000000000GET/v1/accounts").hex()
		const wantSig = "188d9d5920717ac6a9bb1e8f3d8e93322d75ac7d7bb80c53a78366ef57be1759ee1a1f80a4f7b1cffa7d279702849dc1947f2b33d0b040c73c400457d54bb377"

		h := buildTransformWith(t, `
timestamp: {format: unix_millis}
signature:
  algorithm: sha512
  key_encoding: raw
  output_encoding: hex
  message: "{{.Timestamp}}{{.Method}}{{.Path}}"
credentials:
  secret: {type: env, var: SECRET}
headers:
  - name: "X-Signature"
    value: "{{.Signature}}"
  - name: "X-Timestamp"
    value: "{{.Timestamp}}"
rules:
  - host: "api.example.com"
`, mapBuilder(map[string]secrets.Source{
			"SECRET": &staticSource{name: "secret", value: "rawsecret123"},
		}))
		h.now = fixedNow(1700000000)

		req := requestWithBody(t, http.MethodGet, "https://api.example.com/v1/accounts", nil, 1<<20)
		res, err := h.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)
		require.Equal(t, transform.ActionContinue, res.Action)
		require.Equal(t, []string{wantSig}, headers.Values(req.Header, "X-Signature"))
		require.Equal(t, []string{"1700000000000"}, headers.Values(req.Header, "X-Timestamp"))
	})

	t.Run("GET request has empty body in signature", func(t *testing.T) {
		// Reference: HMAC_SHA256(b'k', "1700000000GET/v1/health") base64.
		// We don't precompute it — instead verify by mirroring with a second
		// signer over the empty-body message and comparing headers.
		h := buildTransformWith(t, `
timestamp: {format: unix_seconds}
signature:
  algorithm: sha256
  key_encoding: raw
  output_encoding: base64
  message: "{{.Timestamp}}{{.Method}}{{.Path}}{{.Body}}"
credentials:
  secret: {type: env, var: SECRET}
headers:
  - name: "X-Sig"
    value: "{{.Signature}}"
rules:
  - host: "api.example.com"
`, mapBuilder(map[string]secrets.Source{
			"SECRET": &staticSource{name: "secret", value: "k"},
		}))
		h.now = fixedNow(1700000000)

		req := requestWithBody(t, http.MethodGet, "https://api.example.com/v1/health", nil, 1<<20)
		res, err := h.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)
		require.Equal(t, transform.ActionContinue, res.Action)
		require.NotEmpty(t, req.Header.Get("X-Sig"))

		// The same config with an explicit empty-body request must produce the
		// same signature, proving .Body resolves to "" for both GET and
		// zero-length-body requests.
		req2 := requestWithBody(t, http.MethodGet, "https://api.example.com/v1/health", []byte(""), 1<<20)
		req2.ContentLength = 0
		_, err = h.TransformRequest(context.Background(), newContext(), req2)
		require.NoError(t, err)
		require.Equal(t, headers.Values(req.Header, "X-Sig"), headers.Values(req2.Header, "X-Sig"))
	})

	t.Run("rule miss skips transform", func(t *testing.T) {
		h := buildTransformWith(t, falconxYAML, mapBuilder(map[string]secrets.Source{
			"KEY":        &staticSource{name: "key", value: "k"},
			"SECRET":     &staticSource{name: "secret", value: "c3VwZXJzZWNyZXQ="},
			"PASSPHRASE": &staticSource{name: "pass", value: "p"},
		}))
		h.now = fixedNow(1700000000)

		req := requestWithBody(t, http.MethodGet, "https://other.example.com/v1/health", nil, 1<<20)
		res, err := h.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)
		require.Equal(t, transform.ActionContinue, res.Action)
		require.Empty(t, req.Header.Get("FX-ACCESS-KEY"))
		require.Empty(t, req.Header.Get("FX-ACCESS-SIGN"))
	})

	t.Run("header casing preserved verbatim", func(t *testing.T) {
		h := buildTransformWith(t, `
timestamp: {format: unix_seconds}
signature:
  algorithm: sha256
  key_encoding: raw
  output_encoding: hex
  message: "{{.Method}}"
credentials:
  secret: {type: env, var: SECRET}
headers:
  - name: "FX-ACCESS-KEY"
    value: "v"
  - name: "X-Mixed-Case-Header"
    value: "v"
rules:
  - host: "api.example.com"
`, mapBuilder(map[string]secrets.Source{
			"SECRET": &staticSource{name: "secret", value: "k"},
		}))
		req := requestWithBody(t, http.MethodGet, "https://api.example.com/", nil, 1<<20)
		_, err := h.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)
		// HeaderValuesByExactName bypasses http.Header.Get's canonicalization
		// so we can verify the user's exact casing landed on the wire.
		require.NotEmpty(t, headers.Values(req.Header, "FX-ACCESS-KEY"), "FX-ACCESS-KEY must be set with this exact casing")
		require.NotEmpty(t, headers.Values(req.Header, "X-Mixed-Case-Header"), "X-Mixed-Case-Header must be set with this exact casing")
	})

	t.Run("body still readable downstream", func(t *testing.T) {
		body := []byte(`{"hello":"world"}`)
		h := buildTransformWith(t, falconxYAML, mapBuilder(map[string]secrets.Source{
			"KEY":        &staticSource{name: "key", value: "k"},
			"SECRET":     &staticSource{name: "secret", value: "c3VwZXJzZWNyZXQ="},
			"PASSPHRASE": &staticSource{name: "pass", value: "p"},
		}))
		req := requestWithBody(t, http.MethodPost, "https://api.falconx.io/v1/quotes", body, 1<<20)
		_, err := h.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)

		got, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		require.Equal(t, body, got, "downstream transforms must still see the original body bytes")
	})

	t.Run("query string included in path with query", func(t *testing.T) {
		// Two requests, same body and timestamp, differing only in query;
		// signatures must differ because PathWithQuery includes the query.
		h := buildTransformWith(t, falconxYAML, mapBuilder(map[string]secrets.Source{
			"KEY":        &staticSource{name: "key", value: "k"},
			"SECRET":     &staticSource{name: "secret", value: "c3VwZXJzZWNyZXQ="},
			"PASSPHRASE": &staticSource{name: "pass", value: "p"},
		}))
		h.now = fixedNow(1700000000)

		req1 := requestWithBody(t, http.MethodGet, "https://api.falconx.io/v1/quotes", nil, 1<<20)
		req2 := requestWithBody(t, http.MethodGet, "https://api.falconx.io/v1/quotes?foo=bar", nil, 1<<20)
		_, err := h.TransformRequest(context.Background(), newContext(), req1)
		require.NoError(t, err)
		_, err = h.TransformRequest(context.Background(), newContext(), req2)
		require.NoError(t, err)
		sig1 := headers.Values(req1.Header, "FX-ACCESS-SIGN")
		sig2 := headers.Values(req2.Header, "FX-ACCESS-SIGN")
		require.NotEmpty(t, sig1)
		require.NotEmpty(t, sig2)
		require.NotEqual(t, sig1, sig2)
	})

	t.Run("body truncated by global limit rejects", func(t *testing.T) {
		body := bytes.Repeat([]byte("a"), 1024)
		h := buildTransformWith(t, falconxYAML, mapBuilder(map[string]secrets.Source{
			"KEY":        &staticSource{name: "key", value: "k"},
			"SECRET":     &staticSource{name: "secret", value: "c3VwZXJzZWNyZXQ="},
			"PASSPHRASE": &staticSource{name: "pass", value: "p"},
		}))
		// maxBytes shorter than the body simulates the proxy's global cap
		// silently truncating: io.LimitReader returns EOF after 512 bytes.
		req := requestWithBody(t, http.MethodPost, "https://api.falconx.io/v1/quotes", body, 512)

		tctx := newContext()
		res, err := h.TransformRequest(context.Background(), tctx, req)
		require.NoError(t, err)
		require.Equal(t, transform.ActionReject, res.Action)
		require.Equal(t, http.StatusRequestEntityTooLarge, res.Response.StatusCode)
		require.Empty(t, headers.Values(req.Header, "FX-ACCESS-SIGN"), "must not sign a truncated body")
		require.Equal(t, "body_truncated", tctx.DrainAnnotations()["rejected"])
	})

	t.Run("chunked body rejected by default", func(t *testing.T) {
		h := buildTransformWith(t, falconxYAML, mapBuilder(map[string]secrets.Source{
			"KEY":        &staticSource{name: "key", value: "k"},
			"SECRET":     &staticSource{name: "secret", value: "c3VwZXJzZWNyZXQ="},
			"PASSPHRASE": &staticSource{name: "pass", value: "p"},
		}))
		req := requestWithBody(t, http.MethodPost, "https://api.falconx.io/v1/quotes", []byte(`{"x":1}`), 1<<20)
		req.ContentLength = -1 // simulate chunked / unknown length

		tctx := newContext()
		res, err := h.TransformRequest(context.Background(), tctx, req)
		require.NoError(t, err)
		require.Equal(t, transform.ActionReject, res.Action)
		require.Equal(t, http.StatusBadRequest, res.Response.StatusCode)
		require.Equal(t, "chunked_body_not_allowed", tctx.DrainAnnotations()["rejected"])
	})

	t.Run("chunked body signed when opted in", func(t *testing.T) {
		yamlWithChunked := falconxYAML + "allow_chunked_body: true\n"
		h := buildTransformWith(t, yamlWithChunked, mapBuilder(map[string]secrets.Source{
			"KEY":        &staticSource{name: "key", value: "k"},
			"SECRET":     &staticSource{name: "secret", value: "c3VwZXJzZWNyZXQ="},
			"PASSPHRASE": &staticSource{name: "pass", value: "p"},
		}))
		h.now = fixedNow(1700000000)

		req := requestWithBody(t, http.MethodPost, "https://api.falconx.io/v1/quotes", []byte(`{"x":1}`), 1<<20)
		req.ContentLength = -1

		res, err := h.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)
		require.Equal(t, transform.ActionContinue, res.Action)
		require.NotEmpty(t, headers.Values(req.Header, "FX-ACCESS-SIGN"))
	})

	t.Run("credential unavailable rejects with 502", func(t *testing.T) {
		h := buildTransformWith(t, falconxYAML, mapBuilder(map[string]secrets.Source{
			"KEY":        &staticSource{name: "key", value: "k"},
			"SECRET":     &staticSource{name: "secret", err: io.ErrUnexpectedEOF},
			"PASSPHRASE": &staticSource{name: "pass", value: "p"},
		}))
		req := requestWithBody(t, http.MethodPost, "https://api.falconx.io/v1/quotes", []byte(`{}`), 1<<20)
		tctx := newContext()
		res, err := h.TransformRequest(context.Background(), tctx, req)
		require.NoError(t, err)
		require.Equal(t, transform.ActionReject, res.Action)
		require.Equal(t, http.StatusBadGateway, res.Response.StatusCode)
		require.Equal(t, "credential_unavailable", tctx.DrainAnnotations()["rejected"])
	})

	t.Run("base64 key decode error rejects", func(t *testing.T) {
		h := buildTransformWith(t, falconxYAML, mapBuilder(map[string]secrets.Source{
			"KEY":        &staticSource{name: "key", value: "k"},
			"SECRET":     &staticSource{name: "secret", value: "not!!!valid!!!base64"},
			"PASSPHRASE": &staticSource{name: "pass", value: "p"},
		}))
		req := requestWithBody(t, http.MethodPost, "https://api.falconx.io/v1/quotes", []byte(`{}`), 1<<20)
		tctx := newContext()
		res, err := h.TransformRequest(context.Background(), tctx, req)
		require.NoError(t, err)
		require.Equal(t, transform.ActionReject, res.Action)
		require.Equal(t, "key_decode_failed", tctx.DrainAnnotations()["rejected"])
	})
}

// --- factory validation ---

func TestFactoryValidation(t *testing.T) {
	cases := []struct {
		name      string
		yaml      string
		wantError string
	}{
		{
			name: "missing message",
			yaml: `
signature: {algorithm: sha256, key_encoding: raw, output_encoding: hex}
credentials: {secret: {type: env, var: S}}
headers: [{name: X, value: v}]
rules: [{host: "x.example.com"}]
`,
			wantError: "signature.message is required",
		},
		{
			name: "unknown algorithm",
			yaml: `
signature: {algorithm: md5, key_encoding: raw, output_encoding: hex, message: "x"}
credentials: {secret: {type: env, var: S}}
headers: [{name: X, value: v}]
rules: [{host: "x.example.com"}]
`,
			wantError: "unknown signature.algorithm",
		},
		{
			name: "unknown key encoding",
			yaml: `
signature: {algorithm: sha256, key_encoding: rot13, output_encoding: hex, message: "x"}
credentials: {secret: {type: env, var: S}}
headers: [{name: X, value: v}]
rules: [{host: "x.example.com"}]
`,
			wantError: "unknown signature.key_encoding",
		},
		{
			name: "unknown output encoding",
			yaml: `
signature: {algorithm: sha256, key_encoding: raw, output_encoding: morse, message: "x"}
credentials: {secret: {type: env, var: S}}
headers: [{name: X, value: v}]
rules: [{host: "x.example.com"}]
`,
			wantError: "unknown signature.output_encoding",
		},
		{
			name: "unknown timestamp format",
			yaml: `
timestamp: {format: nanos}
signature: {algorithm: sha256, key_encoding: raw, output_encoding: hex, message: "x"}
credentials: {secret: {type: env, var: S}}
headers: [{name: X, value: v}]
rules: [{host: "x.example.com"}]
`,
			wantError: "unknown timestamp.format",
		},
		{
			name: "missing secret credential",
			yaml: `
signature: {algorithm: sha256, key_encoding: raw, output_encoding: hex, message: "x"}
credentials: {key: {type: env, var: K}}
headers: [{name: X, value: v}]
rules: [{host: "x.example.com"}]
`,
			wantError: `"credentials" must include "secret"`,
		},
		{
			name: "missing headers",
			yaml: `
signature: {algorithm: sha256, key_encoding: raw, output_encoding: hex, message: "x"}
credentials: {secret: {type: env, var: S}}
rules: [{host: "x.example.com"}]
`,
			wantError: `at least one entry in "headers"`,
		},
		{
			name: "missing rules",
			yaml: `
signature: {algorithm: sha256, key_encoding: raw, output_encoding: hex, message: "x"}
credentials: {secret: {type: env, var: S}}
headers: [{name: X, value: v}]
`,
			wantError: `at least one entry in "rules"`,
		},
		{
			name: "header missing name",
			yaml: `
signature: {algorithm: sha256, key_encoding: raw, output_encoding: hex, message: "x"}
credentials: {secret: {type: env, var: S}}
headers: [{value: v}]
rules: [{host: "x.example.com"}]
`,
			wantError: "headers[0].name is required",
		},
		{
			name: "header missing value",
			yaml: `
signature: {algorithm: sha256, key_encoding: raw, output_encoding: hex, message: "x"}
credentials: {secret: {type: env, var: S}}
headers: [{name: X}]
rules: [{host: "x.example.com"}]
`,
			wantError: "headers[0].value is required",
		},
		{
			name: "bad message template",
			yaml: `
signature: {algorithm: sha256, key_encoding: raw, output_encoding: hex, message: "{{.NotAField"}
credentials: {secret: {type: env, var: S}}
headers: [{name: X, value: v}]
rules: [{host: "x.example.com"}]
`,
			wantError: "parsing signature.message",
		},
	}
	build := mapBuilder(map[string]secrets.Source{
		"S": &staticSource{name: "s", value: "k"},
		"K": &staticSource{name: "k", value: "k"},
	})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c config
			node := yamlFromString(t, tc.yaml)
			require.NoError(t, node.Decode(&c))
			_, err := newFromConfig(c, slog.Default(), build)
			require.ErrorContains(t, err, tc.wantError)
		})
	}
}

// TestFactory_EndToEnd verifies the registered factory wires up correctly
// through the real secrets.BuildSource (env source).
func TestFactory_EndToEnd(t *testing.T) {
	t.Setenv("HMAC_KEY", "the-api-key")
	t.Setenv("HMAC_SECRET", "c3VwZXJzZWNyZXRrZXktYnl0ZXM=")
	t.Setenv("HMAC_PASS", "the-passphrase")

	tr, err := factory(yamlFromString(t, falconxYAML+`# end`+"\n"), slog.Default())
	require.NoError(t, err)
	require.Equal(t, "hmac_sign", tr.Name())

	// Rebuild with env-mapped vars: the YAML refers to KEY/SECRET/PASSPHRASE
	// vars, which we map to the env vars we set above.
	tr, err = factory(yamlFromString(t, `
timestamp: {format: unix_seconds}
signature:
  algorithm: sha256
  key_encoding: base64
  output_encoding: base64
  message: "{{.Timestamp}}{{.Method}}{{.PathWithQuery}}{{.Body}}"
credentials:
  key: {type: env, var: HMAC_KEY}
  secret: {type: env, var: HMAC_SECRET}
  passphrase: {type: env, var: HMAC_PASS}
headers:
  - {name: "FX-ACCESS-KEY", value: "{{.Credentials.key}}"}
  - {name: "FX-ACCESS-SIGN", value: "{{.Signature}}"}
  - {name: "FX-ACCESS-TIMESTAMP", value: "{{.Timestamp}}"}
  - {name: "FX-ACCESS-PASSPHRASE", value: "{{.Credentials.passphrase}}"}
rules: [{host: "api.falconx.io"}]
`), slog.Default())
	require.NoError(t, err)

	req := requestWithBody(t, http.MethodPost, "https://api.falconx.io/v1/quotes", []byte(`{"a":1}`), 1<<20)
	res, err := tr.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, []string{"the-api-key"}, headers.Values(req.Header, "FX-ACCESS-KEY"))
	require.NotEmpty(t, headers.Values(req.Header, "FX-ACCESS-SIGN"))
}
