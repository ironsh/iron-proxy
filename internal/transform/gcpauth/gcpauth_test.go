package gcpauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform"
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

func TestGCPAuth_InjectsBearerFromKeyfilePath(t *testing.T) {
	srv, calls := fakeTokenServer(t, "minted-token", 3600)
	dir := t.TempDir()
	path := filepath.Join(dir, "sa.json")
	require.NoError(t, os.WriteFile(path, testKeyfileJSON(t, srv.URL, "sa@p.iam.gserviceaccount.com"), 0o600))

	cfg := config{
		KeyfilePath: path,
		Scopes:      []string{"https://www.googleapis.com/auth/cloud-platform"},
	}
	g, err := newFromConfig(cfg, slog.Default(), os.ReadFile, staticBuilder(&staticSource{}))
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
	g, err := newFromConfig(cfg, slog.Default(), os.ReadFile, staticBuilder(nested))
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
	g, err := newFromConfig(c, slog.Default(), os.ReadFile, staticBuilder(&staticSource{}))
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
	g, err := newFromConfig(cfg, slog.Default(), os.ReadFile, staticBuilder(&staticSource{}))
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
	g, err := newFromConfig(cfg, slog.Default(), os.ReadFile, staticBuilder(&staticSource{}))
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
	_, err := newFromConfig(cfg, slog.Default(), os.ReadFile, failingBuilder(fmt.Errorf("not configured")))
	require.ErrorContains(t, err, "building keyfile source")
	require.ErrorContains(t, err, "not configured")
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
