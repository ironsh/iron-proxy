package gcpidtoken

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
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

func staticBuilder(src secrets.Source) sourceBuilder {
	return func(yaml.Node, *slog.Logger) (secrets.Source, error) { return src, nil }
}

func failingBuilder(err error) sourceBuilder {
	return func(yaml.Node, *slog.Logger) (secrets.Source, error) { return nil, err }
}

func testKeyfileJSON(t *testing.T, tokenURL, email string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	keyfile := map[string]string{
		"type":         "service_account",
		"project_id":   "test-project",
		"private_key":  string(pemBytes),
		"client_email": email,
		"token_uri":    tokenURL,
	}
	data, err := json.Marshal(keyfile)
	require.NoError(t, err)
	return data
}

func fakeIDTokenServer(t *testing.T, accessToken string) (*httptest.Server, *atomic.Int64, *atomic.Value) {
	t.Helper()
	var calls atomic.Int64
	var assertion atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		require.NoError(t, r.ParseForm())
		assertion.Store(r.PostForm.Get("assertion"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id_token":   accessToken,
			"token_type": "Bearer",
			"expires_in": stubIDTokenLifetimeSeconds,
		})
	}))
	t.Cleanup(srv.Close)
	return srv, &calls, &assertion
}

func yamlFromString(t *testing.T, src string) yaml.Node {
	t.Helper()
	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(src), &node))
	return *node.Content[0]
}

func newRequest(t *testing.T, host string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, "https://"+host+"/v1/resource", nil)
	require.NoError(t, err)
	return r
}

func newContext() *transform.TransformContext {
	return &transform.TransformContext{Mode: transform.ModeMITM}
}

func decodeJWTClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3, "token is not a JWT")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(raw, &claims))
	return claims
}

func unsignedAssertion(t *testing.T, claims map[string]any) string {
	t.Helper()
	header, err := encodeJWTPart(map[string]any{"alg": "RS256", "typ": "JWT"})
	require.NoError(t, err)
	body, err := encodeJWTPart(claims)
	require.NoError(t, err)
	return header + "." + body + ".sig"
}

func TestGCPIDToken_Validation(t *testing.T) {
	cases := []struct {
		name      string
		yaml      string
		wantError string
	}{
		{
			name: "missing both keyfile sources",
			yaml: `
audience: https://service.run.app
rules:
  - host: service.run.app
`,
			wantError: "exactly one",
		},
		{
			name: "both keyfile sources set",
			yaml: `
keyfile_path: /tmp/k.json
keyfile:
  type: env
  var: X
audience: https://service.run.app
rules:
  - host: service.run.app
`,
			wantError: "exactly one",
		},
		{
			name: "missing audience",
			yaml: `
keyfile_path: /tmp/k.json
rules:
  - host: service.run.app
`,
			wantError: "audience",
		},
		{
			name: "missing rules",
			yaml: `
keyfile_path: /tmp/k.json
audience: https://service.run.app
`,
			wantError: "rules",
		},
		{
			name: "invalid header",
			yaml: `
keyfile_path: /tmp/k.json
audience: https://service.run.app
header: X-Other
rules:
  - host: service.run.app
`,
			wantError: "header",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c config
			node := yamlFromString(t, tc.yaml)
			require.NoError(t, node.Decode(&c))
			_, err := newFromConfig(c, slog.Default(), os.ReadFile, staticBuilder(&staticSource{}))
			require.ErrorContains(t, err, tc.wantError)
		})
	}
}

func TestGCPIDToken_InjectsBearerFromKeyfilePath(t *testing.T) {
	wantIDToken, err := fakeIDToken("https://service.run.app")
	require.NoError(t, err)
	srv, calls, assertion := fakeIDTokenServer(t, wantIDToken)
	path := filepath.Join(t.TempDir(), "sa.json")
	require.NoError(t, os.WriteFile(path, testKeyfileJSON(t, srv.URL, "sa@p.iam.gserviceaccount.com"), 0o600))

	cfg := config{
		KeyfilePath: path,
		Audience:    "https://service.run.app",
		Rules:       []hostmatch.RuleConfig{hostmatchRuleConfig(t, "service.run.app")},
	}
	g, err := newFromConfig(cfg, slog.Default(), os.ReadFile, staticBuilder(&staticSource{}))
	require.NoError(t, err)

	req := newRequest(t, "service.run.app")
	tctx := newContext()
	res, err := g.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "Bearer "+wantIDToken, req.Header.Get("Authorization"))
	require.Equal(t, int64(1), calls.Load())

	claims := decodeJWTClaims(t, assertion.Load().(string))
	require.Equal(t, "sa@p.iam.gserviceaccount.com", claims["iss"])
	require.Equal(t, srv.URL, claims["aud"])
	require.Equal(t, "https://service.run.app", claims["target_audience"])

	annotations := tctx.DrainAnnotations()
	require.Equal(t, "sa@p.iam.gserviceaccount.com", annotations["service_account"])
	require.Equal(t, "https://service.run.app", annotations["audience"])
}

func TestGCPIDToken_InjectsServerlessHeader(t *testing.T) {
	wantIDToken, err := fakeIDToken("https://service.run.app")
	require.NoError(t, err)
	srv, _, _ := fakeIDTokenServer(t, wantIDToken)
	path := filepath.Join(t.TempDir(), "sa.json")
	require.NoError(t, os.WriteFile(path, testKeyfileJSON(t, srv.URL, "sa@p.iam.gserviceaccount.com"), 0o600))

	cfg := config{
		KeyfilePath: path,
		Audience:    "https://service.run.app",
		Header:      "x_serverless_authorization",
		Rules:       []hostmatch.RuleConfig{hostmatchRuleConfig(t, "service.run.app")},
	}
	g, err := newFromConfig(cfg, slog.Default(), os.ReadFile, staticBuilder(&staticSource{}))
	require.NoError(t, err)

	req := newRequest(t, "service.run.app")
	res, err := g.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Empty(t, req.Header.Get("Authorization"))
	require.Equal(t, "Bearer "+wantIDToken, req.Header.Get("X-Serverless-Authorization"))
}

func TestGCPIDToken_InjectsBearerFromNestedSource(t *testing.T) {
	wantIDToken, err := fakeIDToken("https://nested.run.app")
	require.NoError(t, err)
	srv, _ := fakeIDTokenServerNoAssertion(t, wantIDToken)
	keyJSON := testKeyfileJSON(t, srv.URL, "nested@p.iam.gserviceaccount.com")
	nested := &staticSource{name: "op://vault/gcp-sa/credential", value: string(keyJSON)}

	cfg := config{
		Keyfile:  yamlFromString(t, "type: 1password_connect\nsecret_ref: \"op://vault/gcp-sa/credential\"\n"),
		Audience: "https://nested.run.app",
		Rules:    []hostmatch.RuleConfig{hostmatchRuleConfig(t, "nested.run.app")},
	}
	g, err := newFromConfig(cfg, slog.Default(), os.ReadFile, staticBuilder(nested))
	require.NoError(t, err)

	req := newRequest(t, "nested.run.app")
	res, err := g.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "Bearer "+wantIDToken, req.Header.Get("Authorization"))
	require.Equal(t, int64(1), nested.calls.Load())
}

func TestGCPIDToken_HostRulesRestrictInjection(t *testing.T) {
	wantIDToken, err := fakeIDToken("https://service.run.app")
	require.NoError(t, err)
	srv, calls, _ := fakeIDTokenServer(t, wantIDToken)
	path := filepath.Join(t.TempDir(), "sa.json")
	require.NoError(t, os.WriteFile(path, testKeyfileJSON(t, srv.URL, "sa@p.iam.gserviceaccount.com"), 0o600))

	cfg := config{
		KeyfilePath: path,
		Audience:    "https://service.run.app",
		Rules:       []hostmatch.RuleConfig{hostmatchRuleConfig(t, "service.run.app")},
	}
	g, err := newFromConfig(cfg, slog.Default(), os.ReadFile, staticBuilder(&staticSource{}))
	require.NoError(t, err)

	req := newRequest(t, "service.run.app")
	_, err = g.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, "Bearer "+wantIDToken, req.Header.Get("Authorization"))

	other := newRequest(t, "api.openai.com")
	_, err = g.TransformRequest(context.Background(), newContext(), other)
	require.NoError(t, err)
	require.Empty(t, other.Header.Get("Authorization"))
	require.Equal(t, int64(1), calls.Load())
}

func TestGCPIDToken_CachesTokenAcrossRequests(t *testing.T) {
	wantIDToken, err := fakeIDToken("https://service.run.app")
	require.NoError(t, err)
	srv, calls, _ := fakeIDTokenServer(t, wantIDToken)
	path := filepath.Join(t.TempDir(), "sa.json")
	require.NoError(t, os.WriteFile(path, testKeyfileJSON(t, srv.URL, "sa@p.iam.gserviceaccount.com"), 0o600))

	cfg := config{
		KeyfilePath: path,
		Audience:    "https://service.run.app",
		Rules:       []hostmatch.RuleConfig{hostmatchRuleConfig(t, "service.run.app")},
	}
	g, err := newFromConfig(cfg, slog.Default(), os.ReadFile, staticBuilder(&staticSource{}))
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		req := newRequest(t, "service.run.app")
		_, err := g.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)
		require.Equal(t, "Bearer "+wantIDToken, req.Header.Get("Authorization"))
	}
	require.Equal(t, int64(1), calls.Load())
}

func TestGCPIDToken_KeyfileMissing_Rejects(t *testing.T) {
	cfg := config{
		KeyfilePath: "/does/not/exist.json",
		Audience:    "https://service.run.app",
		Rules:       []hostmatch.RuleConfig{hostmatchRuleConfig(t, "service.run.app")},
	}
	g, err := newFromConfig(cfg, slog.Default(), os.ReadFile, staticBuilder(&staticSource{}))
	require.NoError(t, err)

	req := newRequest(t, "service.run.app")
	tctx := newContext()
	res, err := g.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)
	require.Empty(t, req.Header.Get("Authorization"))
	require.Equal(t, "mint_failed", tctx.DrainAnnotations()["error"])
}

func TestGCPIDToken_NestedSourceBuildError(t *testing.T) {
	cfg := config{
		Keyfile:  yamlFromString(t, "type: 1password_connect\nsecret_ref: \"op://vault/missing\"\n"),
		Audience: "https://service.run.app",
		Rules:    []hostmatch.RuleConfig{hostmatchRuleConfig(t, "service.run.app")},
	}
	_, err := newFromConfig(cfg, slog.Default(), os.ReadFile, failingBuilder(fmt.Errorf("not configured")))
	require.ErrorContains(t, err, "building keyfile source")
	require.ErrorContains(t, err, "not configured")
}

func TestGCPIDToken_StubsOAuth2IDTokenEndpoint(t *testing.T) {
	form := url.Values{}
	form.Set("grant_type", jwtBearerGrantType)
	form.Set("assertion", unsignedAssertion(t, map[string]any{
		"iss":             "stub@p.iam.gserviceaccount.com",
		"aud":             "https://oauth2.googleapis.com/token",
		"target_audience": "https://service.run.app",
	}))
	req, err := http.NewRequest(http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	g := newStubOnlyTransform(t)
	tctx := newContext()
	res, err := g.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionStub, res.Action)
	require.Equal(t, "gcp_oauth2_id_token_endpoint", tctx.DrainAnnotations()["stubbed"])

	var out struct {
		IDToken string `json:"id_token"`
	}
	require.NoError(t, json.NewDecoder(res.Response.Body).Decode(&out))
	claims := decodeJWTClaims(t, out.IDToken)
	require.Equal(t, "https://service.run.app", claims["aud"])
}

func TestGCPIDToken_DoesNotStubAccessTokenJWTBearer(t *testing.T) {
	form := url.Values{}
	form.Set("grant_type", jwtBearerGrantType)
	form.Set("assertion", unsignedAssertion(t, map[string]any{
		"iss":   "stub@p.iam.gserviceaccount.com",
		"aud":   "https://oauth2.googleapis.com/token",
		"scope": "https://www.googleapis.com/auth/cloud-platform",
	}))
	body := form.Encode()
	req, err := http.NewRequest(http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	g := newStubOnlyTransform(t)
	res, err := g.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	restored, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	require.Equal(t, body, string(restored))
}

func TestGCPIDToken_DoesNotInspectOversizedTokenEndpointBody(t *testing.T) {
	body := strings.Repeat("x", maxTokenRequestBodyBytes+1)
	req, err := http.NewRequest(http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(body))
	require.NoError(t, err)

	g := newStubOnlyTransform(t)
	res, err := g.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	restored, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	require.Equal(t, body, string(restored))
}

func TestGCPIDToken_StubsMetadataIdentityEndpoint(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=https%3A%2F%2Fservice.run.app", nil)
	require.NoError(t, err)

	g := newStubOnlyTransform(t)
	tctx := newContext()
	res, err := g.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionStub, res.Action)
	require.Equal(t, "gcp_metadata_identity_endpoint", tctx.DrainAnnotations()["stubbed"])
	body, err := io.ReadAll(res.Response.Body)
	require.NoError(t, err)
	claims := decodeJWTClaims(t, string(body))
	require.Equal(t, "https://service.run.app", claims["aud"])
}

func TestGCPIDToken_DoesNotStubMetadataIdentityWithoutAudience(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity", nil)
	require.NoError(t, err)

	g := newStubOnlyTransform(t)
	res, err := g.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
}

func TestGCPIDToken_MintFailureRejectsWithSanitizedReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.Copy(io.Discard, r.Body)
		require.NoError(t, err)
		http.Error(w, "upstream token endpoint failed", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	path := filepath.Join(t.TempDir(), "sa.json")
	require.NoError(t, os.WriteFile(path, testKeyfileJSON(t, srv.URL, "sa@p.iam.gserviceaccount.com"), 0o600))

	cfg := config{
		KeyfilePath: path,
		Audience:    "https://service.run.app",
		Rules:       []hostmatch.RuleConfig{hostmatchRuleConfig(t, "service.run.app")},
	}
	g, err := newFromConfig(cfg, slog.Default(), os.ReadFile, staticBuilder(&staticSource{}))
	require.NoError(t, err)

	req := newRequest(t, "service.run.app")
	tctx := newContext()
	res, err := g.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)
	require.Equal(t, "token_endpoint_http_500", tctx.DrainAnnotations()["error"])
}

func newStubOnlyTransform(t *testing.T) *GCPIDToken {
	t.Helper()
	wantIDToken, err := fakeIDToken("https://service.run.app")
	require.NoError(t, err)
	srv, _ := fakeIDTokenServerNoAssertion(t, wantIDToken)
	path := filepath.Join(t.TempDir(), "sa.json")
	require.NoError(t, os.WriteFile(path, testKeyfileJSON(t, srv.URL, "sa@p.iam.gserviceaccount.com"), 0o600))
	cfg := config{
		KeyfilePath: path,
		Audience:    "https://service.run.app",
		Rules:       []hostmatch.RuleConfig{hostmatchRuleConfig(t, "service.run.app")},
	}
	g, err := newFromConfig(cfg, slog.Default(), os.ReadFile, staticBuilder(&staticSource{}))
	require.NoError(t, err)
	return g
}

func fakeIDTokenServerNoAssertion(t *testing.T, accessToken string) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, err := io.Copy(io.Discard, r.Body)
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id_token":   accessToken,
			"token_type": "Bearer",
			"expires_in": stubIDTokenLifetimeSeconds,
		})
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func hostmatchRuleConfig(t *testing.T, host string) hostmatch.RuleConfig {
	t.Helper()
	var rules struct {
		Rules []hostmatch.RuleConfig `yaml:"rules"`
	}
	require.NoError(t, yaml.Unmarshal([]byte("rules:\n  - host: "+host+"\n"), &rules))
	return rules.Rules[0]
}
