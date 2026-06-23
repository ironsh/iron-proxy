package gcpauth

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
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/gcpjwt"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

// staticSource implements secrets.Source with a fixed value or error.
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

// errTokenSourceBuilder fails if invoked. Used in tests that exercise the
// keyfile paths so an accidental credentials_provider entry is caught.
func errTokenSourceBuilder(context.Context, yaml.Node, []string, *slog.Logger) (oauth2.TokenSource, string, error) {
	return nil, "", fmt.Errorf("tokenSourceBuilder must not be called in this test")
}

func staticTokenSourceBuilder(ts oauth2.TokenSource, principal string) tokenSourceBuilder {
	return func(context.Context, yaml.Node, []string, *slog.Logger) (oauth2.TokenSource, string, error) {
		return ts, principal, nil
	}
}

// testKeyfileJSON generates a service-account JSON keyfile pointing token
// exchange at tokenURL.
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

// fakeTokenServer mimics Google's oauth2 token endpoint and counts requests.
func fakeTokenServer(t *testing.T, accessToken string, expiresIn int) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   expiresIn,
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func yamlFromString(t *testing.T, src string) yaml.Node {
	t.Helper()
	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(src), &node))
	return *node.Content[0]
}

func newRequest(t *testing.T, host string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, "https://"+host+"/v1/projects", nil)
	require.NoError(t, err)
	return r
}

func newContext() *transform.TransformContext {
	return &transform.TransformContext{Mode: transform.ModeMITM}
}

func TestGCPAuth_Validation(t *testing.T) {
	cases := []struct {
		name      string
		yaml      string
		wantError string
	}{
		{
			name: "missing both keyfile sources",
			yaml: `
scopes: [a]
rules:
  - host: "*.googleapis.com"
`,
			wantError: "exactly one of",
		},
		{
			name: "both keyfile sources set",
			yaml: `
keyfile_path: /tmp/k.json
keyfile:
  type: env
  var: X
scopes: [a]
rules:
  - host: "*.googleapis.com"
`,
			wantError: "exactly one of",
		},
		{
			name: "missing scopes",
			yaml: `
keyfile_path: /tmp/k.json
rules:
  - host: "*.googleapis.com"
`,
			wantError: "scopes",
		},
		{
			name: "keyfile_path and credentials_provider both set",
			yaml: `
keyfile_path: /tmp/k.json
credentials_provider:
  type: workload_identity
scopes: [a]
rules:
  - host: "*.googleapis.com"
`,
			wantError: "exactly one of",
		},
		{
			name: "subject combined with credentials_provider",
			yaml: `
credentials_provider:
  type: workload_identity
subject: user@workspace.example.com
scopes: [a]
rules:
  - host: "*.googleapis.com"
`,
			wantError: "subject",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c config
			node := yamlFromString(t, tc.yaml)
			require.NoError(t, node.Decode(&c))
			_, err := newFromConfig(c, slog.Default(), os.ReadFile, staticBuilder(&staticSource{}), errTokenSourceBuilder)
			require.ErrorContains(t, err, tc.wantError)
		})
	}
}

func TestGCPAuth_InjectsBearerFromCredentialsProvider(t *testing.T) {
	cfgYAML := `
credentials_provider:
  type: workload_identity
scopes: ["https://www.googleapis.com/auth/cloud-platform"]
rules:
  - host: "*.googleapis.com"
`
	var c config
	node := yamlFromString(t, cfgYAML)
	require.NoError(t, node.Decode(&c))

	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "wi-token", TokenType: "Bearer"})
	g, err := newFromConfig(c, slog.Default(), os.ReadFile, staticBuilder(&staticSource{}), staticTokenSourceBuilder(ts, "wi-principal@example.com"))
	require.NoError(t, err)

	req := newRequest(t, "storage.googleapis.com")
	tctx := newContext()
	res, err := g.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "Bearer wi-token", req.Header.Get("Authorization"))
	require.Equal(t, "wi-principal@example.com", tctx.DrainAnnotations()["service_account"])
}

func TestGCPAuth_InjectsBearerFromKeyfilePath(t *testing.T) {
	srv, calls := fakeTokenServer(t, "minted-token", 3600)
	dir := t.TempDir()
	path := filepath.Join(dir, "sa.json")
	require.NoError(t, os.WriteFile(path, testKeyfileJSON(t, srv.URL, "sa@p.iam.gserviceaccount.com"), 0o600))

	cfg := config{
		KeyfilePath: path,
		Scopes:      []string{"https://www.googleapis.com/auth/cloud-platform"},
	}
	g, err := newFromConfig(cfg, slog.Default(), os.ReadFile, staticBuilder(&staticSource{}), errTokenSourceBuilder)
	require.NoError(t, err)

	req := newRequest(t, "storage.googleapis.com")
	res, err := g.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "Bearer minted-token", req.Header.Get("Authorization"))
	require.Equal(t, int64(1), calls.Load())
}

func TestGCPAuth_InjectsBearerFromNestedSource(t *testing.T) {
	srv, _ := fakeTokenServer(t, "nested-token", 3600)
	keyJSON := testKeyfileJSON(t, srv.URL, "nested-sa@p.iam.gserviceaccount.com")
	nested := &staticSource{name: "op://vault/gcp-sa/credential", value: string(keyJSON)}

	cfg := config{
		Keyfile: yamlFromString(t, `
type: 1password_connect
secret_ref: "op://vault/gcp-sa/credential"
`),
		Scopes: []string{"https://www.googleapis.com/auth/cloud-platform"},
	}
	g, err := newFromConfig(cfg, slog.Default(), os.ReadFile, staticBuilder(nested), errTokenSourceBuilder)
	require.NoError(t, err)

	req := newRequest(t, "storage.googleapis.com")
	res, err := g.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "Bearer nested-token", req.Header.Get("Authorization"))
	require.Equal(t, int64(1), nested.calls.Load())
}

func TestGCPAuth_HostRulesRestrictInjection(t *testing.T) {
	srv, calls := fakeTokenServer(t, "scoped-token", 3600)
	dir := t.TempDir()
	path := filepath.Join(dir, "sa.json")
	require.NoError(t, os.WriteFile(path, testKeyfileJSON(t, srv.URL, "sa@p.iam.gserviceaccount.com"), 0o600))

	cfgYAML := `
keyfile_path: ` + path + `
scopes: ["https://www.googleapis.com/auth/cloud-platform"]
rules:
  - host: "*.googleapis.com"
`
	var c config
	node := yamlFromString(t, cfgYAML)
	require.NoError(t, node.Decode(&c))
	g, err := newFromConfig(c, slog.Default(), os.ReadFile, staticBuilder(&staticSource{}), errTokenSourceBuilder)
	require.NoError(t, err)

	// Matching host gets the header.
	req := newRequest(t, "storage.googleapis.com")
	_, err = g.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, "Bearer scoped-token", req.Header.Get("Authorization"))

	// Non-matching host is passed through untouched.
	other := newRequest(t, "api.openai.com")
	_, err = g.TransformRequest(context.Background(), newContext(), other)
	require.NoError(t, err)
	require.Empty(t, other.Header.Get("Authorization"))
	require.Equal(t, int64(1), calls.Load(), "token endpoint should only be hit for matching hosts")
}

func TestGCPAuth_CachesTokenAcrossRequests(t *testing.T) {
	srv, calls := fakeTokenServer(t, "shared-token", 3600)
	dir := t.TempDir()
	path := filepath.Join(dir, "sa.json")
	require.NoError(t, os.WriteFile(path, testKeyfileJSON(t, srv.URL, "sa@p.iam.gserviceaccount.com"), 0o600))

	cfg := config{
		KeyfilePath: path,
		Scopes:      []string{"https://www.googleapis.com/auth/cloud-platform"},
	}
	g, err := newFromConfig(cfg, slog.Default(), os.ReadFile, staticBuilder(&staticSource{}), errTokenSourceBuilder)
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		req := newRequest(t, "storage.googleapis.com")
		_, err := g.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)
		require.Equal(t, "Bearer shared-token", req.Header.Get("Authorization"))
	}
	require.Equal(t, int64(1), calls.Load())
}

func TestGCPAuth_KeyfileMissing_Rejects(t *testing.T) {
	cfg := config{
		KeyfilePath: "/does/not/exist.json",
		Scopes:      []string{"https://www.googleapis.com/auth/cloud-platform"},
	}
	g, err := newFromConfig(cfg, slog.Default(), os.ReadFile, staticBuilder(&staticSource{}), errTokenSourceBuilder)
	require.NoError(t, err)

	req := newRequest(t, "storage.googleapis.com")
	res, err := g.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)
	require.Empty(t, req.Header.Get("Authorization"))
}

func TestGCPAuth_NestedSourceBuildError(t *testing.T) {
	cfg := config{
		Keyfile: yamlFromString(t, `
type: 1password_connect
secret_ref: "op://vault/missing"
`),
		Scopes: []string{"https://www.googleapis.com/auth/cloud-platform"},
	}
	_, err := newFromConfig(cfg, slog.Default(), os.ReadFile, failingBuilder(fmt.Errorf("not configured")), errTokenSourceBuilder)
	require.ErrorContains(t, err, "building keyfile source")
	require.ErrorContains(t, err, "not configured")
}

type stubTokenResp struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func decodeStubResponse(t *testing.T, resp *http.Response) stubTokenResp {
	t.Helper()
	require.NotNil(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var out stubTokenResp
	require.NoError(t, json.Unmarshal(body, &out))
	return out
}

// TestGCPAuth_StubsOAuth2TokenEndpoint exercises the always-on stub for the
// JWT bearer grant endpoint used by service-account keyfile flows. The rules
// here target a different host on purpose: stubbing must not depend on the
// configured rules matching the token endpoint.
func TestGCPAuth_StubsOAuth2TokenEndpoint(t *testing.T) {
	srv, calls := fakeTokenServer(t, "minted-token", 3600)
	dir := t.TempDir()
	path := filepath.Join(dir, "sa.json")
	require.NoError(t, os.WriteFile(path, testKeyfileJSON(t, srv.URL, "sa@p.iam.gserviceaccount.com"), 0o600))

	cfgYAML := `
keyfile_path: ` + path + `
scopes: ["https://www.googleapis.com/auth/cloud-platform"]
rules:
  - host: "bigquery.googleapis.com"
`
	var c config
	node := yamlFromString(t, cfgYAML)
	require.NoError(t, node.Decode(&c))
	g, err := newFromConfig(c, slog.Default(), os.ReadFile, staticBuilder(&staticSource{}), errTokenSourceBuilder)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, "https://oauth2.googleapis.com/token", nil)
	require.NoError(t, err)
	tctx := newContext()
	res, err := g.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionStub, res.Action)

	decoded := decodeStubResponse(t, res.Response)
	require.Equal(t, stubAccessToken, decoded.AccessToken)
	require.Equal(t, "Bearer", decoded.TokenType)
	require.Equal(t, 3600, decoded.ExpiresIn)

	annotations := tctx.DrainAnnotations()
	require.Equal(t, "oauth2_token_endpoint", annotations["stubbed"])

	require.Empty(t, req.Header.Get("Authorization"))
	require.Equal(t, int64(0), calls.Load(), "real GCP token endpoint must not be hit when stubbing")
}

func TestGCPAuth_DoesNotStubIDTokenJWTBearer(t *testing.T) {
	srv, calls := fakeTokenServer(t, "minted-token", 3600)
	dir := t.TempDir()
	path := filepath.Join(dir, "sa.json")
	require.NoError(t, os.WriteFile(path, testKeyfileJSON(t, srv.URL, "sa@p.iam.gserviceaccount.com"), 0o600))

	cfgYAML := `
keyfile_path: ` + path + `
scopes: ["https://www.googleapis.com/auth/cloud-platform"]
rules:
  - host: "bigquery.googleapis.com"
`
	var c config
	node := yamlFromString(t, cfgYAML)
	require.NoError(t, node.Decode(&c))
	g, err := newFromConfig(c, slog.Default(), os.ReadFile, staticBuilder(&staticSource{}), errTokenSourceBuilder)
	require.NoError(t, err)

	form := url.Values{}
	form.Set("grant_type", gcpjwt.JWTBearerGrantType)
	form.Set("assertion", unsignedAssertion(t, map[string]any{
		"iss":             "stub@p.iam.gserviceaccount.com",
		"aud":             "https://oauth2.googleapis.com/token",
		"target_audience": "https://service.run.app",
	}))
	body := form.Encode()
	req, err := http.NewRequest(http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(body))
	require.NoError(t, err)
	tctx := newContext()
	res, err := g.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Empty(t, tctx.DrainAnnotations())

	restored, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	require.Equal(t, body, string(restored))
	require.Empty(t, req.Header.Get("Authorization"))
	require.Equal(t, int64(0), calls.Load(), "gcp_auth must not stub or mint for ID-token JWT bearer requests")
}

func TestGCPAuth_StubsMetadataServerToken(t *testing.T) {
	srv, _ := fakeTokenServer(t, "minted-token", 3600)
	dir := t.TempDir()
	path := filepath.Join(dir, "sa.json")
	require.NoError(t, os.WriteFile(path, testKeyfileJSON(t, srv.URL, "sa@p.iam.gserviceaccount.com"), 0o600))

	cfg := config{
		KeyfilePath: path,
		Scopes:      []string{"https://www.googleapis.com/auth/cloud-platform"},
	}
	g, err := newFromConfig(cfg, slog.Default(), os.ReadFile, staticBuilder(&staticSource{}), errTokenSourceBuilder)
	require.NoError(t, err)

	urls := []string{
		"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
		"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/sa@p.iam.gserviceaccount.com/token",
		"http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
	}
	for _, u := range urls {
		t.Run(u, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, u, nil)
			require.NoError(t, err)
			tctx := newContext()
			res, err := g.TransformRequest(context.Background(), tctx, req)
			require.NoError(t, err)
			require.Equal(t, transform.ActionStub, res.Action)

			decoded := decodeStubResponse(t, res.Response)
			require.Equal(t, stubAccessToken, decoded.AccessToken)
			require.Equal(t, "oauth2_token_endpoint", tctx.DrainAnnotations()["stubbed"])
		})
	}
}

// Paths on the same hosts that aren't the token endpoint should not be stubbed
// — they fall through to the normal injection path so the matching upstream
// keeps working.
func TestGCPAuth_DoesNotStubNonTokenPaths(t *testing.T) {
	srv, _ := fakeTokenServer(t, "minted-token", 3600)
	dir := t.TempDir()
	path := filepath.Join(dir, "sa.json")
	require.NoError(t, os.WriteFile(path, testKeyfileJSON(t, srv.URL, "sa@p.iam.gserviceaccount.com"), 0o600))

	cfg := config{
		KeyfilePath: path,
		Scopes:      []string{"https://www.googleapis.com/auth/cloud-platform"},
	}
	g, err := newFromConfig(cfg, slog.Default(), os.ReadFile, staticBuilder(&staticSource{}), errTokenSourceBuilder)
	require.NoError(t, err)

	cases := []string{
		"https://oauth2.googleapis.com/revoke",
		"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, u, nil)
			require.NoError(t, err)
			res, err := g.TransformRequest(context.Background(), newContext(), req)
			require.NoError(t, err)
			require.Equal(t, transform.ActionContinue, res.Action)
			require.Equal(t, "Bearer minted-token", req.Header.Get("Authorization"))
		})
	}
}

// End-to-end through the registered transform factory and the real secrets
// package: keyfile loaded via the env source.
func TestGCPAuth_Factory_EndToEnd(t *testing.T) {
	srv, _ := fakeTokenServer(t, "factory-token", 3600)
	keyJSON := testKeyfileJSON(t, srv.URL, "factory-sa@p.iam.gserviceaccount.com")
	t.Setenv("GCP_SA_JSON", string(keyJSON))

	cfgYAML := `
keyfile:
  type: env
  var: GCP_SA_JSON
scopes: ["https://www.googleapis.com/auth/cloud-platform"]
rules:
  - host: "*.googleapis.com"
`
	tr, err := factory(yamlFromString(t, cfgYAML), slog.Default())
	require.NoError(t, err)

	req := newRequest(t, "storage.googleapis.com")
	res, err := tr.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "Bearer factory-token", req.Header.Get("Authorization"))
}

// decodeJWTClaims base64-decodes the payload segment of a JWT.
func decodeJWTClaims(t *testing.T, assertion string) map[string]any {
	t.Helper()
	parts := strings.Split(assertion, ".")
	require.Len(t, parts, 3, "assertion is not a JWT")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(raw, &claims))
	return claims
}

func unsignedAssertion(t *testing.T, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT"})
	require.NoError(t, err)
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

// TestGCPAuth_Subject verifies that the subject field drives domain-wide
// delegation: the minted assertion's sub claim impersonates the configured
// Workspace user, and is absent when no subject is set.
func TestGCPAuth_Subject(t *testing.T) {
	cases := []struct {
		name    string
		subject string
	}{
		{name: "with subject", subject: "user@workspace.example.com"},
		{name: "without subject", subject: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var assertion atomic.Value
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.NoError(t, r.ParseForm())
				assertion.Store(r.PostForm.Get("assertion"))
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"access_token": "minted-token",
					"token_type":   "Bearer",
					"expires_in":   3600,
				})
			}))
			t.Cleanup(srv.Close)

			path := filepath.Join(t.TempDir(), "sa.json")
			require.NoError(t, os.WriteFile(path, testKeyfileJSON(t, srv.URL, "sa@p.iam.gserviceaccount.com"), 0o600))

			cfg := config{
				KeyfilePath: path,
				Subject:     tc.subject,
				Scopes:      []string{"https://www.googleapis.com/auth/cloud-platform"},
			}
			g, err := newFromConfig(cfg, slog.Default(), os.ReadFile, staticBuilder(&staticSource{}), errTokenSourceBuilder)
			require.NoError(t, err)

			req := newRequest(t, "storage.googleapis.com")
			res, err := g.TransformRequest(context.Background(), newContext(), req)
			require.NoError(t, err)
			require.Equal(t, transform.ActionContinue, res.Action)
			require.Equal(t, "Bearer minted-token", req.Header.Get("Authorization"))

			claims := decodeJWTClaims(t, assertion.Load().(string))
			require.Equal(t, "sa@p.iam.gserviceaccount.com", claims["iss"])
			if tc.subject == "" {
				require.NotContains(t, claims, "sub", "no subject: the assertion must not impersonate")
			} else {
				require.Equal(t, tc.subject, claims["sub"], "subject must impersonate the configured user")
			}
		})
	}
}
