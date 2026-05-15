package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

// --- test doubles ---

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

// tokenServer is a fake OAuth2 token endpoint. It counts requests and records
// each request's form so tests can assert on the exchange.
type tokenServer struct {
	*httptest.Server
	mu    sync.Mutex
	calls int
	forms []url.Values
}

func (ts *tokenServer) Calls() int {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.calls
}

func (ts *tokenServer) LastForm() url.Values {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.forms[len(ts.forms)-1]
}

// newTokenServer serves the OAuth2 token endpoint. respond decides the HTTP
// status and JSON body per request; pass nil for the default success
// response that mints "minted-token".
func newTokenServer(t *testing.T, respond func(form url.Values) (int, map[string]any)) *tokenServer {
	t.Helper()
	if respond == nil {
		respond = func(url.Values) (int, map[string]any) {
			return http.StatusOK, map[string]any{
				"access_token": "minted-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			}
		}
	}
	ts := &tokenServer{}
	ts.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		ts.mu.Lock()
		ts.calls++
		ts.forms = append(ts.forms, r.PostForm)
		ts.mu.Unlock()
		status, body := respond(r.PostForm)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(ts.Close)
	return ts
}

// --- credential blob builders ---

// keyfileJSON generates a GCP service-account keyfile whose JWT-bearer
// exchange targets tokenURL.
func keyfileJSON(t *testing.T, tokenURL string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	data, err := json.Marshal(map[string]string{
		"type":           "service_account",
		"project_id":     "test-project",
		"private_key_id": "test-key-id",
		"private_key":    string(pemBytes),
		"client_email":   "sa@test-project.iam.gserviceaccount.com",
		"token_uri":      tokenURL,
	})
	require.NoError(t, err)
	return data
}

func refreshTokenJSON(t *testing.T, tokenURI string) []byte {
	t.Helper()
	blob := map[string]any{
		"refresh_token": "test-refresh-token",
		"client_id":     "test-client-id",
		"client_secret": "test-client-secret",
	}
	if tokenURI != "" {
		blob["token_uri"] = tokenURI
	}
	data, err := json.Marshal(blob)
	require.NoError(t, err)
	return data
}

func clientCredentialsJSON(t *testing.T) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]string{
		"client_id":     "test-client-id",
		"client_secret": "test-client-secret",
	})
	require.NoError(t, err)
	return data
}

// --- generic helpers ---

func yamlFromString(t *testing.T, src string) yaml.Node {
	t.Helper()
	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(src), &node))
	return *node.Content[0]
}

func newRequest(t *testing.T, method, rawURL string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(method, rawURL, nil)
	require.NoError(t, err)
	return r
}

func newContext() *transform.TransformContext {
	return &transform.TransformContext{Mode: transform.ModeMITM}
}

// buildTransform decodes cfgYAML and builds the transform with a static
// credential source, so tests never reach a real secret backend.
func buildTransform(t *testing.T, cfgYAML string, src secrets.Source) *OAuth {
	t.Helper()
	var c config
	node := yamlFromString(t, cfgYAML)
	require.NoError(t, node.Decode(&c))
	o, err := newFromConfig(c, slog.Default(), staticBuilder(src))
	require.NoError(t, err)
	return o
}

type tokenJSON struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func decodeBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	require.NotNil(t, resp)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return body
}

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

// --- validation ---

func TestValidation(t *testing.T) {
	cases := []struct {
		name      string
		yaml      string
		wantError string
	}{
		{
			name:      "empty tokens",
			yaml:      `tokens: []`,
			wantError: "at least one entry in \"tokens\"",
		},
		{
			name: "unknown grant",
			yaml: `
tokens:
  - grant: password
    credential: {type: env, var: X}
    rules:
      - host: "example.com"
`,
			wantError: "\"grant\" must be one of",
		},
		{
			name: "missing credential",
			yaml: `
tokens:
  - grant: jwt_bearer
    rules:
      - host: "example.com"
`,
			wantError: "\"credential\" is required",
		},
		{
			name: "subject on non-jwt grant",
			yaml: `
tokens:
  - grant: refresh_token
    credential: {type: env, var: X}
    subject: user@example.com
    rules:
      - host: "example.com"
`,
			wantError: "\"subject\" is only valid for the jwt_bearer grant",
		},
		{
			name: "client_credentials without token_endpoint",
			yaml: `
tokens:
  - grant: client_credentials
    credential: {type: env, var: X}
    rules:
      - host: "example.com"
`,
			wantError: "client_credentials grant requires \"token_endpoint\"",
		},
		{
			name: "missing rules",
			yaml: `
tokens:
  - grant: jwt_bearer
    credential: {type: env, var: X}
`,
			wantError: "at least one entry in \"rules\"",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c config
			node := yamlFromString(t, tc.yaml)
			require.NoError(t, node.Decode(&c))
			_, err := newFromConfig(c, slog.Default(), staticBuilder(&staticSource{}))
			require.ErrorContains(t, err, tc.wantError)
		})
	}
}

// --- refresh_token grant ---

func TestRefreshTokenGrant_InjectsBearer(t *testing.T) {
	srv := newTokenServer(t, nil)
	tokenURL := srv.URL + "/token"
	src := &staticSource{name: "op://ai-agents/GSUITE", value: string(refreshTokenJSON(t, tokenURL))}

	o := buildTransform(t, `
tokens:
  - grant: refresh_token
    credential: {type: env, var: X}
    scopes: ["https://www.googleapis.com/auth/gmail.readonly"]
    rules:
      - host: "gmail.googleapis.com"
`, src)

	req := newRequest(t, http.MethodGet, "https://gmail.googleapis.com/gmail/v1/users/me/messages")
	res, err := o.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "Bearer minted-token", req.Header.Get("Authorization"))

	form := srv.LastForm()
	require.Equal(t, "refresh_token", form.Get("grant_type"))
	require.Equal(t, "test-refresh-token", form.Get("refresh_token"))
	require.Equal(t, "test-client-id", form.Get("client_id"))
	require.Equal(t, "test-client-secret", form.Get("client_secret"), "client auth must be in the form body")
}

// The token endpoint comes from the credential blob's token_uri when no
// token_endpoint is configured.
func TestRefreshTokenGrant_TokenURIFromBlobOnly(t *testing.T) {
	srv := newTokenServer(t, nil)
	src := &staticSource{name: "blob", value: string(refreshTokenJSON(t, srv.URL+"/token"))}

	o := buildTransform(t, `
tokens:
  - grant: refresh_token
    credential: {type: env, var: X}
    rules:
      - host: "gmail.googleapis.com"
`, src)

	req := newRequest(t, http.MethodGet, "https://gmail.googleapis.com/v1/x")
	res, err := o.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "Bearer minted-token", req.Header.Get("Authorization"))
	require.Equal(t, 1, srv.Calls())
}

// --- jwt_bearer grant ---

func TestJWTBearerGrant_WithoutSubject(t *testing.T) {
	srv := newTokenServer(t, nil)
	src := &staticSource{name: "keyfile", value: string(keyfileJSON(t, srv.URL+"/token"))}

	o := buildTransform(t, `
tokens:
  - grant: jwt_bearer
    credential: {type: env, var: X}
    scopes: ["https://www.googleapis.com/auth/bigquery.readonly"]
    rules:
      - host: "bigquery.googleapis.com"
`, src)

	req := newRequest(t, http.MethodGet, "https://bigquery.googleapis.com/bigquery/v2/projects/p/queries")
	res, err := o.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "Bearer minted-token", req.Header.Get("Authorization"))

	form := srv.LastForm()
	require.Equal(t, "urn:ietf:params:oauth:grant-type:jwt-bearer", form.Get("grant_type"))
	claims := decodeJWTClaims(t, form.Get("assertion"))
	require.Equal(t, "sa@test-project.iam.gserviceaccount.com", claims["iss"])
	require.NotContains(t, claims, "sub", "no subject configured: assertion must not impersonate")
}

func TestJWTBearerGrant_WithSubject(t *testing.T) {
	srv := newTokenServer(t, nil)
	src := &staticSource{name: "keyfile", value: string(keyfileJSON(t, srv.URL+"/token"))}

	o := buildTransform(t, `
tokens:
  - grant: jwt_bearer
    credential: {type: env, var: X}
    scopes: ["https://www.googleapis.com/auth/gmail.readonly"]
    subject: "user@workspace.example.com"
    rules:
      - host: "gmail.googleapis.com"
`, src)

	req := newRequest(t, http.MethodGet, "https://gmail.googleapis.com/v1/x")
	tctx := newContext()
	res, err := o.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)

	claims := decodeJWTClaims(t, srv.LastForm().Get("assertion"))
	require.Equal(t, "user@workspace.example.com", claims["sub"], "subject must impersonate the configured user")
	require.Equal(t, "user@workspace.example.com", tctx.DrainAnnotations()["subject"])
}

// --- client_credentials grant ---

func TestClientCredentialsGrant_InjectsBearer(t *testing.T) {
	srv := newTokenServer(t, nil)
	src := &staticSource{name: "creds", value: string(clientCredentialsJSON(t))}

	o := buildTransform(t, `
tokens:
  - grant: client_credentials
    credential: {type: env, var: X}
    token_endpoint: "`+srv.URL+`/token"
    scopes: ["api.read"]
    rules:
      - host: "api.example.com"
`, src)

	req := newRequest(t, http.MethodGet, "https://api.example.com/v1/things")
	res, err := o.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "Bearer minted-token", req.Header.Get("Authorization"))

	form := srv.LastForm()
	require.Equal(t, "client_credentials", form.Get("grant_type"))
	require.Equal(t, "test-client-id", form.Get("client_id"))
	require.Equal(t, "test-client-secret", form.Get("client_secret"))
	require.Equal(t, "api.read", form.Get("scope"))
}

// --- caching, matching, injection behavior ---

func TestCachesTokenAcrossRequests(t *testing.T) {
	srv := newTokenServer(t, nil)
	src := &staticSource{name: "creds", value: string(clientCredentialsJSON(t))}

	o := buildTransform(t, `
tokens:
  - grant: client_credentials
    credential: {type: env, var: X}
    token_endpoint: "`+srv.URL+`/token"
    rules:
      - host: "api.example.com"
`, src)

	for i := 0; i < 5; i++ {
		req := newRequest(t, http.MethodGet, "https://api.example.com/v1/x")
		_, err := o.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)
		require.Equal(t, "Bearer minted-token", req.Header.Get("Authorization"))
	}
	require.Equal(t, 1, srv.Calls(), "token should be minted once and cached")
}

func TestConcurrentRequestsTriggerSingleRefresh(t *testing.T) {
	srv := newTokenServer(t, nil)
	src := &staticSource{name: "creds", value: string(clientCredentialsJSON(t))}

	o := buildTransform(t, `
tokens:
  - grant: client_credentials
    credential: {type: env, var: X}
    token_endpoint: "`+srv.URL+`/token"
    rules:
      - host: "api.example.com"
`, src)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := newRequest(t, http.MethodGet, "https://api.example.com/v1/x")
			_, err := o.TransformRequest(context.Background(), newContext(), req)
			require.NoError(t, err)
		}()
	}
	wg.Wait()
	require.Equal(t, 1, srv.Calls(), "concurrent requests must single-flight the exchange")
}

func TestNoMatchingEntryPassesThrough(t *testing.T) {
	srv := newTokenServer(t, nil)
	src := &staticSource{name: "creds", value: string(clientCredentialsJSON(t))}

	o := buildTransform(t, `
tokens:
  - grant: client_credentials
    credential: {type: env, var: X}
    token_endpoint: "`+srv.URL+`/token"
    rules:
      - host: "api.example.com"
`, src)

	req := newRequest(t, http.MethodGet, "https://other.example.org/v1/x")
	res, err := o.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Empty(t, req.Header.Get("Authorization"))
	require.Equal(t, 0, srv.Calls())
}

func TestOverwritesExistingAuthorizationHeader(t *testing.T) {
	srv := newTokenServer(t, nil)
	src := &staticSource{name: "creds", value: string(clientCredentialsJSON(t))}

	o := buildTransform(t, `
tokens:
  - grant: client_credentials
    credential: {type: env, var: X}
    token_endpoint: "`+srv.URL+`/token"
    rules:
      - host: "api.example.com"
`, src)

	req := newRequest(t, http.MethodGet, "https://api.example.com/v1/x")
	req.Header.Set("Authorization", "Bearer client-supplied-token")
	_, err := o.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, "Bearer minted-token", req.Header.Get("Authorization"))
}

// The first entry whose rules match wins, in config order.
func TestFirstMatchingEntryWins(t *testing.T) {
	srv := newTokenServer(t, func(form url.Values) (int, map[string]any) {
		return http.StatusOK, map[string]any{
			"access_token": "token-for-" + form.Get("scope"),
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
	})
	src := &staticSource{name: "creds", value: string(clientCredentialsJSON(t))}

	o := buildTransform(t, `
tokens:
  - grant: client_credentials
    credential: {type: env, var: X}
    token_endpoint: "`+srv.URL+`/token"
    scopes: ["first"]
    rules:
      - host: "*.example.com"
  - grant: client_credentials
    credential: {type: env, var: X}
    token_endpoint: "`+srv.URL+`/token"
    scopes: ["second"]
    rules:
      - host: "api.example.com"
`, src)

	req := newRequest(t, http.MethodGet, "https://api.example.com/v1/x")
	_, err := o.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, "Bearer token-for-first", req.Header.Get("Authorization"))
}

// --- token endpoint stubbing ---

func TestStubsConfiguredTokenEndpoint(t *testing.T) {
	srv := newTokenServer(t, nil)
	tokenURL := srv.URL + "/token"
	src := &staticSource{name: "keyfile", value: string(keyfileJSON(t, tokenURL))}

	// rules target the API host on purpose: stubbing must not depend on the
	// rules matching the token endpoint.
	o := buildTransform(t, `
tokens:
  - grant: jwt_bearer
    credential: {type: env, var: X}
    token_endpoint: "`+tokenURL+`"
    scopes: ["https://www.googleapis.com/auth/bigquery"]
    rules:
      - host: "bigquery.googleapis.com"
`, src)

	req := newRequest(t, http.MethodPost, tokenURL)
	tctx := newContext()
	res, err := o.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionStub, res.Action)

	var decoded tokenJSON
	require.NoError(t, json.Unmarshal(decodeBody(t, res.Response), &decoded))
	require.Equal(t, stubAccessToken, decoded.AccessToken)
	require.Equal(t, "Bearer", decoded.TokenType)
	require.Equal(t, 3600, decoded.ExpiresIn)
	require.Equal(t, "oauth2_token_endpoint", tctx.DrainAnnotations()["stubbed"])
	require.Equal(t, 0, srv.Calls(), "the real token endpoint must not be hit when stubbing")
}

// A non-token path on the token endpoint host is not stubbed.
func TestDoesNotStubOtherPaths(t *testing.T) {
	srv := newTokenServer(t, nil)
	src := &staticSource{name: "keyfile", value: string(keyfileJSON(t, srv.URL+"/token"))}

	o := buildTransform(t, `
tokens:
  - grant: jwt_bearer
    credential: {type: env, var: X}
    token_endpoint: "`+srv.URL+`/token"
    scopes: ["s"]
    rules:
      - host: "bigquery.googleapis.com"
`, src)

	req := newRequest(t, http.MethodGet, srv.URL+"/revoke")
	res, err := o.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action, "non-token path falls through")
}

// --- failure handling ---

func TestInvalidGrantFails502(t *testing.T) {
	srv := newTokenServer(t, func(url.Values) (int, map[string]any) {
		return http.StatusBadRequest, map[string]any{
			"error":             "invalid_grant",
			"error_description": "Token has been expired or revoked.",
		}
	})
	src := &staticSource{name: "blob", value: string(refreshTokenJSON(t, srv.URL+"/token"))}

	o := buildTransform(t, `
tokens:
  - grant: refresh_token
    credential: {type: env, var: X}
    rules:
      - host: "gmail.googleapis.com"
`, src)

	req := newRequest(t, http.MethodGet, "https://gmail.googleapis.com/v1/x")
	tctx := newContext()
	res, err := o.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)
	require.Equal(t, http.StatusBadGateway, res.Response.StatusCode)
	require.Empty(t, req.Header.Get("Authorization"), "an unauthenticated request must not be forwarded")

	body := decodeBody(t, res.Response)
	require.Contains(t, string(body), "oauth_token failed to mint")

	annotations := tctx.DrainAnnotations()
	require.Equal(t, "invalid_grant", annotations["error"])
	require.Equal(t, "token_unavailable", annotations["rejected"])
}

func TestCredentialUnavailableFails502(t *testing.T) {
	src := &staticSource{name: "blob", err: io.ErrUnexpectedEOF}

	o := buildTransform(t, `
tokens:
  - grant: refresh_token
    credential: {type: env, var: X}
    token_endpoint: "https://oauth2.example.com/token"
    rules:
      - host: "gmail.googleapis.com"
`, src)

	req := newRequest(t, http.MethodGet, "https://gmail.googleapis.com/v1/x")
	res, err := o.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)
	require.Equal(t, http.StatusBadGateway, res.Response.StatusCode)
}

// --- factory end-to-end through the real secrets package ---

func TestFactory_EndToEnd(t *testing.T) {
	srv := newTokenServer(t, nil)
	t.Setenv("OAUTH_CREDENTIAL", string(clientCredentialsJSON(t)))

	tr, err := factory(yamlFromString(t, `
tokens:
  - grant: client_credentials
    credential:
      type: env
      var: OAUTH_CREDENTIAL
    token_endpoint: "`+srv.URL+`/token"
    rules:
      - host: "api.example.com"
`), slog.Default())
	require.NoError(t, err)

	req := newRequest(t, http.MethodGet, "https://api.example.com/v1/x")
	res, err := tr.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "Bearer minted-token", req.Header.Get("Authorization"))
}
