package secretbroker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"

	// Registers the annotate transform, which the audit test composes with
	// secretbroker to prove header captures see the placeholder.
	_ "github.com/ironsh/iron-proxy/internal/transform/annotate"
)

const (
	placeholder = "IRON_PLACEHOLDER_GITHUB_TOKEN"
	realSecret  = "ghp_realcredential000000000000000000"
)

// --- helpers ---

// writeSecretsFile writes a secrets file and returns its path.
func writeSecretsFile(t *testing.T, values map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secrets.json")
	data, err := json.Marshal(values)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func yamlFromString(t *testing.T, src string) yaml.Node {
	t.Helper()
	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(src), &node))
	return *node.Content[0]
}

// newBroker builds a transform from YAML config, failing the test on error.
func newBroker(t *testing.T, cfg string, logger *slog.Logger) *SecretBroker {
	t.Helper()
	b, err := newFromConfig(decodeConfig(t, cfg), logger, secrets.BuildSource)
	require.NoError(t, err)
	return b
}

func decodeConfig(t *testing.T, src string) config {
	t.Helper()
	var c config
	node := yamlFromString(t, src)
	require.NoError(t, node.Decode(&c))
	return c
}

// staticSource implements secrets.Source with a fixed value.
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

// newRequest builds a MITM-shaped request with a buffered body, the way the
// proxy hands one to the pipeline.
func newRequest(t *testing.T, method, url, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, url, nil)
	req.Body = transform.NewBufferedBody(io.NopCloser(strings.NewReader(body)), 1<<20)
	return req
}

// newResponse builds a response with a buffered body, the way the proxy hands
// one to the response pipeline.
func newResponse(body string, header http.Header) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{
		StatusCode:    http.StatusOK,
		Header:        header,
		Body:          transform.NewBufferedBody(io.NopCloser(strings.NewReader(body)), 1<<20),
		ContentLength: int64(len(body)),
	}
}

func newContext() *transform.TransformContext {
	return &transform.TransformContext{Mode: transform.ModeMITM}
}

// readBody drains a pipeline body and rewinds it, as the pipeline does between
// transforms.
func readBody(t *testing.T, body io.ReadCloser) string {
	t.Helper()
	buf := transform.RequireBufferedBody(body)
	data, err := io.ReadAll(buf)
	require.NoError(t, err)
	buf.Reset()
	return string(data)
}

// capturingLogger returns a logger and the buffer holding its JSON output.
func capturingLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), &buf
}

// githubEntry is the common single-entry config used across tests.
func githubEntry(secretsFile string, extra string) string {
	return `
secrets_file: ` + secretsFile + `
entries:
  - placeholder: "` + placeholder + `"
    secret_ref: github_token
    hosts: ["api.github.com"]` + extra
}

// --- header substitution ---

func TestTransformRequest_SubstitutesAuthorizationHeader(t *testing.T) {
	file := writeSecretsFile(t, map[string]string{"github_token": realSecret})
	b := newBroker(t, githubEntry(file, ""), slog.Default())

	req := newRequest(t, http.MethodGet, "https://api.github.com/user", "")
	req.Header.Set("Authorization", "Bearer "+placeholder)

	tctx := newContext()
	res, err := b.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)

	require.Equal(t, "Bearer "+realSecret, req.Header.Get("Authorization"))

	ann := tctx.DrainAnnotations()
	subs := ann["substituted"].([]substitution)
	require.Len(t, subs, 1)
	require.Equal(t, placeholder, subs[0].Placeholder)
	require.Equal(t, "github_token", subs[0].SecretRef)
	require.Equal(t, []string{"header:Authorization"}, subs[0].Locations)
}

func TestTransformRequest_SubstitutesListedHeaderOnly(t *testing.T) {
	file := writeSecretsFile(t, map[string]string{"github_token": realSecret})
	b := newBroker(t, githubEntry(file, `
    headers: ["X-Api-Key"]`), slog.Default())

	req := newRequest(t, http.MethodGet, "https://api.github.com/user", "")
	req.Header.Set("X-Api-Key", placeholder)
	// Not in the allowlist and not Authorization: must be left alone, so a
	// workload cannot smuggle the credential into an arbitrary header.
	req.Header.Set("X-Debug-Echo", placeholder)

	tctx := newContext()
	_, err := b.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)

	require.Equal(t, realSecret, req.Header.Get("X-Api-Key"))
	require.Equal(t, placeholder, req.Header.Get("X-Debug-Echo"))
}

func TestTransformRequest_AuthorizationAlwaysScannedAlongsideAllowlist(t *testing.T) {
	file := writeSecretsFile(t, map[string]string{"github_token": realSecret})
	b := newBroker(t, githubEntry(file, `
    headers: ["X-Api-Key"]`), slog.Default())

	req := newRequest(t, http.MethodGet, "https://api.github.com/user", "")
	req.Header.Set("Authorization", "token "+placeholder)

	tctx := newContext()
	_, err := b.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, "token "+realSecret, req.Header.Get("Authorization"))
}

func TestTransformRequest_SubstitutesInsideBasicAuth(t *testing.T) {
	// git-over-HTTPS sends the credential as base64(user:token), so an exact
	// scan of the raw header value would miss it entirely.
	file := writeSecretsFile(t, map[string]string{"github_token": realSecret})
	b := newBroker(t, githubEntry(file, ""), slog.Default())

	req := newRequest(t, http.MethodGet, "https://api.github.com/user", "")
	encoded := base64.StdEncoding.EncodeToString([]byte("git:" + placeholder))
	req.Header.Set("Authorization", "Basic "+encoded)

	tctx := newContext()
	_, err := b.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)

	after, ok := strings.CutPrefix(req.Header.Get("Authorization"), "Basic ")
	require.True(t, ok)
	decoded, err := base64.StdEncoding.DecodeString(after)
	require.NoError(t, err)
	require.Equal(t, "git:"+realSecret, string(decoded))
}

func TestTransformRequest_LeavesRequestsWithoutPlaceholderUntouched(t *testing.T) {
	file := writeSecretsFile(t, map[string]string{"github_token": realSecret})
	b := newBroker(t, githubEntry(file, ""), slog.Default())

	req := newRequest(t, http.MethodGet, "https://api.github.com/user", "")
	req.Header.Set("Authorization", "Bearer some-other-token")

	tctx := newContext()
	_, err := b.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)

	require.Equal(t, "Bearer some-other-token", req.Header.Get("Authorization"))
	require.Empty(t, tctx.DrainAnnotations())
}

// --- body substitution on and off ---

func TestTransformRequest_SubstitutesBodyWhenEnabled(t *testing.T) {
	file := writeSecretsFile(t, map[string]string{"github_token": realSecret})
	b := newBroker(t, githubEntry(file, `
    match_body: true`), slog.Default())

	body := `{"token":"` + placeholder + `"}`
	req := newRequest(t, http.MethodPost, "https://api.github.com/graphql", body)

	tctx := newContext()
	_, err := b.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)

	require.Equal(t, `{"token":"`+realSecret+`"}`, readBody(t, req.Body))
	require.EqualValues(t, len(`{"token":"`+realSecret+`"}`), req.ContentLength)

	subs := tctx.DrainAnnotations()["substituted"].([]substitution)
	require.Equal(t, []string{"body"}, subs[0].Locations)
}

func TestTransformRequest_LeavesBodyAloneWhenDisabled(t *testing.T) {
	file := writeSecretsFile(t, map[string]string{"github_token": realSecret})
	// match_body defaults to false.
	b := newBroker(t, githubEntry(file, ""), slog.Default())

	body := `{"token":"` + placeholder + `"}`
	req := newRequest(t, http.MethodPost, "https://api.github.com/graphql", body)

	tctx := newContext()
	_, err := b.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)

	require.Equal(t, body, readBody(t, req.Body))
	require.Empty(t, tctx.DrainAnnotations())
}

func TestTransformRequest_SubstitutesHeaderAndBodyTogether(t *testing.T) {
	file := writeSecretsFile(t, map[string]string{"github_token": realSecret})
	b := newBroker(t, githubEntry(file, `
    match_body: true`), slog.Default())

	req := newRequest(t, http.MethodPost, "https://api.github.com/graphql", "token="+placeholder)
	req.Header.Set("Authorization", "Bearer "+placeholder)

	tctx := newContext()
	_, err := b.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)

	require.Equal(t, "Bearer "+realSecret, req.Header.Get("Authorization"))
	require.Equal(t, "token="+realSecret, readBody(t, req.Body))

	subs := tctx.DrainAnnotations()["substituted"].([]substitution)
	require.Equal(t, []string{"header:Authorization", "body"}, subs[0].Locations)
}

func TestTransformRequest_SecondEntryStillSeesBodyAfterFirstReadsIt(t *testing.T) {
	// The pipeline rewinds the body between transforms but not between
	// entries within one pass. The first entry here reads the body and finds
	// nothing to rewrite; the second must still see the whole body.
	file := writeSecretsFile(t, map[string]string{
		"unused_token": "unused-credential",
		"github_token": realSecret,
	})
	b := newBroker(t, `
secrets_file: `+file+`
entries:
  - placeholder: "PH_NOT_IN_THIS_BODY"
    secret_ref: unused_token
    hosts: ["api.github.com"]
    match_body: true
  - placeholder: "`+placeholder+`"
    secret_ref: github_token
    hosts: ["api.github.com"]
    match_body: true
`, slog.Default())

	body := `{"token":"` + placeholder + `"}`
	req := newRequest(t, http.MethodPost, "https://api.github.com/graphql", body)

	tctx := newContext()
	_, err := b.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)

	require.Equal(t, `{"token":"`+realSecret+`"}`, readBody(t, req.Body))
}

func TestTransformResponse_SecondEntryStillSeesBodyAfterFirstReadsIt(t *testing.T) {
	file := writeSecretsFile(t, map[string]string{
		"unused_token": "unused-credential",
		"github_token": realSecret,
	})
	b := newBroker(t, `
secrets_file: `+file+`
entries:
  - placeholder: "PH_NOT_IN_THIS_BODY"
    secret_ref: unused_token
    hosts: ["api.github.com"]
  - placeholder: "`+placeholder+`"
    secret_ref: github_token
    hosts: ["api.github.com"]
`, slog.Default())

	req := newRequest(t, http.MethodGet, "https://api.github.com/echo", "")
	resp := newResponse(`{"echo":"`+realSecret+`"}`, nil)

	tctx := newContext()
	_, err := b.TransformResponse(context.Background(), tctx, req, resp)
	require.NoError(t, err)

	got := readBody(t, resp.Body)
	require.NotContains(t, got, realSecret)
	require.Equal(t, `{"echo":"`+placeholder+`"}`, got)
}

// --- host not allowed ---

func TestTransformRequest_NeverSubstitutesOnDisallowedHost(t *testing.T) {
	file := writeSecretsFile(t, map[string]string{"github_token": realSecret})
	b := newBroker(t, githubEntry(file, `
    match_body: true`), slog.Default())

	body := `{"token":"` + placeholder + `"}`
	req := newRequest(t, http.MethodPost, "https://evil.example.com/collect", body)
	req.Header.Set("Authorization", "Bearer "+placeholder)

	tctx := newContext()
	res, err := b.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)

	require.Equal(t, "Bearer "+placeholder, req.Header.Get("Authorization"))
	require.Equal(t, body, readBody(t, req.Body))
	require.Empty(t, tctx.DrainAnnotations())
}

func TestTransformRequest_HostRulesAreScopedPerEntry(t *testing.T) {
	// Two credentials, two hosts. Neither may cross to the other's host.
	file := writeSecretsFile(t, map[string]string{
		"github_token": realSecret,
		"stripe_key":   "sk_live_realstripekey0000",
	})
	b := newBroker(t, `
secrets_file: `+file+`
entries:
  - placeholder: "PH_GITHUB"
    secret_ref: github_token
    hosts: ["api.github.com"]
  - placeholder: "PH_STRIPE"
    secret_ref: stripe_key
    hosts: ["api.stripe.com"]
`, slog.Default())

	req := newRequest(t, http.MethodGet, "https://api.github.com/user", "")
	req.Header.Set("Authorization", "Bearer PH_GITHUB")
	req.Header.Add("Authorization", "Bearer PH_STRIPE")

	tctx := newContext()
	_, err := b.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)

	vals := req.Header.Values("Authorization")
	require.Equal(t, []string{"Bearer " + realSecret, "Bearer PH_STRIPE"}, vals)
}

func TestTransformRequest_RespectsMethodAndPathRules(t *testing.T) {
	file := writeSecretsFile(t, map[string]string{"github_token": realSecret})
	b := newBroker(t, `
secrets_file: `+file+`
entries:
  - placeholder: "`+placeholder+`"
    secret_ref: github_token
    rules:
      - host: "api.github.com"
        methods: ["POST"]
        paths: ["/repos/*"]
`, slog.Default())

	cases := []struct {
		name, method, url string
		wantSubstituted   bool
	}{
		{"matching method and path", http.MethodPost, "https://api.github.com/repos/o/r/issues", true},
		{"wrong method", http.MethodGet, "https://api.github.com/repos/o/r/issues", false},
		{"wrong path", http.MethodPost, "https://api.github.com/user", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := newRequest(t, tc.method, tc.url, "")
			req.Header.Set("Authorization", "Bearer "+placeholder)
			_, err := b.TransformRequest(context.Background(), newContext(), req)
			require.NoError(t, err)

			want := "Bearer " + placeholder
			if tc.wantSubstituted {
				want = "Bearer " + realSecret
			}
			require.Equal(t, want, req.Header.Get("Authorization"))
		})
	}
}

func TestTransformRequest_NoOpInSNIOnlyMode(t *testing.T) {
	file := writeSecretsFile(t, map[string]string{"github_token": realSecret})
	b := newBroker(t, githubEntry(file, ""), slog.Default())

	req := newRequest(t, http.MethodGet, "https://api.github.com/user", "")
	req.Header.Set("Authorization", "Bearer "+placeholder)

	tctx := &transform.TransformContext{Mode: transform.ModeSNIOnly}
	_, err := b.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, "Bearer "+placeholder, req.Header.Get("Authorization"))
}

// --- missing secrets file ---

func TestTransformRequest_MissingSecretsFileFailsClosed(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.json")
	logger, logs := capturingLogger()
	b := newBroker(t, githubEntry(missing, `
    match_body: true`), logger)

	body := `{"token":"` + placeholder + `"}`
	req := newRequest(t, http.MethodPost, "https://api.github.com/graphql", body)
	req.Header.Set("Authorization", "Bearer "+placeholder)

	tctx := newContext()
	res, err := b.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)

	// Fail closed: nothing substituted, the placeholder goes upstream.
	require.Equal(t, "Bearer "+placeholder, req.Header.Get("Authorization"))
	require.Equal(t, body, readBody(t, req.Body))

	ann := tctx.DrainAnnotations()
	require.Nil(t, ann["substituted"])
	require.Equal(t, []string{"github_token"}, ann["secret_unavailable"])

	// Exactly one warning, naming the path.
	require.Equal(t, 1, strings.Count(logs.String(), `"level":"WARN"`))
	require.Contains(t, logs.String(), missing)
}

func TestMissingSecretsFile_WarnsOncePerFailureNotPerRequest(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.json")
	logger, logs := capturingLogger()
	b := newBroker(t, githubEntry(missing, ""), logger)

	for range 5 {
		req := newRequest(t, http.MethodGet, "https://api.github.com/user", "")
		req.Header.Set("Authorization", "Bearer "+placeholder)
		_, err := b.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)
	}

	require.Equal(t, 1, strings.Count(logs.String(), `"level":"WARN"`))
}

func TestMissingSecretsFile_NeverLogsCredentials(t *testing.T) {
	// A malformed file must not have its contents echoed into the warning:
	// a JSON error message can quote the offending bytes.
	path := filepath.Join(t.TempDir(), "secrets.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"github_token": "`+realSecret+`"`), 0o600))

	logger, logs := capturingLogger()
	b := newBroker(t, githubEntry(path, ""), logger)

	req := newRequest(t, http.MethodGet, "https://api.github.com/user", "")
	req.Header.Set("Authorization", "Bearer "+placeholder)
	_, err := b.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)

	require.Equal(t, "Bearer "+placeholder, req.Header.Get("Authorization"))
	require.Contains(t, logs.String(), path)
	require.NotContains(t, logs.String(), realSecret)
}

func TestSecretsFile_RefNotPresentFailsClosed(t *testing.T) {
	file := writeSecretsFile(t, map[string]string{"other_token": realSecret})
	b := newBroker(t, githubEntry(file, ""), slog.Default())

	req := newRequest(t, http.MethodGet, "https://api.github.com/user", "")
	req.Header.Set("Authorization", "Bearer "+placeholder)

	tctx := newContext()
	_, err := b.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)

	require.Equal(t, "Bearer "+placeholder, req.Header.Get("Authorization"))
	require.Equal(t, []string{"github_token"}, tctx.DrainAnnotations()["secret_unavailable"])
}

func TestSecretsFile_RereadOnFileChange(t *testing.T) {
	file := writeSecretsFile(t, map[string]string{"github_token": realSecret})
	b := newBroker(t, githubEntry(file, ""), slog.Default())

	substitute := func() string {
		req := newRequest(t, http.MethodGet, "https://api.github.com/user", "")
		req.Header.Set("Authorization", "Bearer "+placeholder)
		_, err := b.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)
		return req.Header.Get("Authorization")
	}

	require.Equal(t, "Bearer "+realSecret, substitute())

	// Rotate the credential in place. The mtime is bumped explicitly so the
	// change is visible regardless of filesystem timestamp granularity.
	rotated := "ghp_rotatedcredential11111111111111"
	data, err := json.Marshal(map[string]string{"github_token": rotated})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(file, data, 0o600))
	future := time.Now().Add(2 * time.Second)
	require.NoError(t, os.Chtimes(file, future, future))

	require.Equal(t, "Bearer "+rotated, substitute())
}

func TestSecretsFile_RecoversAfterFileAppears(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.json")
	logger, logs := capturingLogger()
	b := newBroker(t, githubEntry(path, ""), logger)

	req := newRequest(t, http.MethodGet, "https://api.github.com/user", "")
	req.Header.Set("Authorization", "Bearer "+placeholder)
	_, err := b.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, "Bearer "+placeholder, req.Header.Get("Authorization"))

	data, err := json.Marshal(map[string]string{"github_token": realSecret})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))

	req = newRequest(t, http.MethodGet, "https://api.github.com/user", "")
	req.Header.Set("Authorization", "Bearer "+placeholder)
	_, err = b.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, "Bearer "+realSecret, req.Header.Get("Authorization"))

	require.Equal(t, 1, strings.Count(logs.String(), `"level":"WARN"`))
}

func TestSourceEntry_UnavailableSecretFailsClosed(t *testing.T) {
	src := &staticSource{name: "GITHUB_TOKEN", err: io.ErrUnexpectedEOF}
	b, err := newFromConfig(decodeConfig(t, `
entries:
  - placeholder: "`+placeholder+`"
    source:
      type: env
      var: GITHUB_TOKEN
    hosts: ["api.github.com"]
`), slog.Default(), staticBuilder(src))
	require.NoError(t, err)

	req := newRequest(t, http.MethodGet, "https://api.github.com/user", "")
	req.Header.Set("Authorization", "Bearer "+placeholder)

	tctx := newContext()
	_, err = b.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)

	require.Equal(t, "Bearer "+placeholder, req.Header.Get("Authorization"))
	require.Equal(t, []string{"GITHUB_TOKEN"}, tctx.DrainAnnotations()["secret_unavailable"])
}

func TestSourceEntry_SubstitutesFromSecretsSource(t *testing.T) {
	src := &staticSource{name: "GITHUB_TOKEN", value: realSecret}
	b, err := newFromConfig(decodeConfig(t, `
entries:
  - placeholder: "`+placeholder+`"
    source:
      type: env
      var: GITHUB_TOKEN
    hosts: ["api.github.com"]
`), slog.Default(), staticBuilder(src))
	require.NoError(t, err)

	req := newRequest(t, http.MethodGet, "https://api.github.com/user", "")
	req.Header.Set("Authorization", "Bearer "+placeholder)

	_, err = b.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, "Bearer "+realSecret, req.Header.Get("Authorization"))
}

// --- response scrubbing ---

func TestTransformResponse_ScrubsCredentialFromBody(t *testing.T) {
	file := writeSecretsFile(t, map[string]string{"github_token": realSecret})
	b := newBroker(t, githubEntry(file, ""), slog.Default())

	// A debugging workload bounces its request off an echo endpoint.
	echoed := `{"headers":{"authorization":"Bearer ` + realSecret + `"}}`
	req := newRequest(t, http.MethodGet, "https://api.github.com/echo", "")
	resp := newResponse(echoed, nil)

	tctx := newContext()
	res, err := b.TransformResponse(context.Background(), tctx, req, resp)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)

	got := readBody(t, resp.Body)
	require.NotContains(t, got, realSecret)
	require.Equal(t, `{"headers":{"authorization":"Bearer `+placeholder+`"}}`, got)
	require.EqualValues(t, len(got), resp.ContentLength)

	scrubbed := tctx.DrainAnnotations()["scrubbed"].([]substitution)
	require.Equal(t, placeholder, scrubbed[0].Placeholder)
	require.Equal(t, []string{"body"}, scrubbed[0].Locations)
}

func TestTransformResponse_ScrubsCredentialFromAnyHeader(t *testing.T) {
	file := writeSecretsFile(t, map[string]string{"github_token": realSecret})
	b := newBroker(t, githubEntry(file, ""), slog.Default())

	req := newRequest(t, http.MethodGet, "https://api.github.com/echo", "")
	// Not Authorization and not in the request header allowlist: the
	// allowlist bounds where the proxy writes, never where it scrubs.
	resp := newResponse("", http.Header{"X-Echoed-Token": {realSecret}})

	tctx := newContext()
	_, err := b.TransformResponse(context.Background(), tctx, req, resp)
	require.NoError(t, err)

	require.Equal(t, placeholder, resp.Header.Get("X-Echoed-Token"))
	scrubbed := tctx.DrainAnnotations()["scrubbed"].([]substitution)
	require.Equal(t, []string{"header:X-Echoed-Token"}, scrubbed[0].Locations)
}

func TestTransformResponse_SkipsWhenScrubDisabled(t *testing.T) {
	file := writeSecretsFile(t, map[string]string{"github_token": realSecret})
	b := newBroker(t, githubEntry(file, `
    scrub_response: false`), slog.Default())

	req := newRequest(t, http.MethodGet, "https://api.github.com/echo", "")
	resp := newResponse(realSecret, nil)

	tctx := newContext()
	_, err := b.TransformResponse(context.Background(), tctx, req, resp)
	require.NoError(t, err)

	require.Equal(t, realSecret, readBody(t, resp.Body))
	require.Empty(t, tctx.DrainAnnotations())
}

func TestTransformResponse_SkipsDisallowedHost(t *testing.T) {
	file := writeSecretsFile(t, map[string]string{"github_token": realSecret})
	b := newBroker(t, githubEntry(file, ""), slog.Default())

	req := newRequest(t, http.MethodGet, "https://evil.example.com/echo", "")
	resp := newResponse(realSecret, nil)

	tctx := newContext()
	_, err := b.TransformResponse(context.Background(), tctx, req, resp)
	require.NoError(t, err)

	require.Equal(t, realSecret, readBody(t, resp.Body))
	require.Empty(t, tctx.DrainAnnotations())
}

func TestTransformResponse_LeavesSSEBodyStreaming(t *testing.T) {
	file := writeSecretsFile(t, map[string]string{"github_token": realSecret})
	b := newBroker(t, githubEntry(file, ""), slog.Default())

	req := newRequest(t, http.MethodGet, "https://api.github.com/events", "")
	resp := newResponse("data: hello\n\n", http.Header{
		"Content-Type":   {"text/event-stream"},
		"X-Echoed-Token": {realSecret},
	})

	tctx := newContext()
	_, err := b.TransformResponse(context.Background(), tctx, req, resp)
	require.NoError(t, err)

	// Headers are still scrubbed; the body is left unbuffered so the proxy's
	// per-chunk streaming path keeps working.
	require.Equal(t, placeholder, resp.Header.Get("X-Echoed-Token"))
	require.Equal(t, -1, transform.RequireBufferedBody(resp.Body).Len())
	require.Equal(t, "sse_body", tctx.DrainAnnotations()["scrub_skipped"])
}

func TestTransformResponse_MissingSecretsFileIsNotAnError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.json")
	b := newBroker(t, githubEntry(missing, ""), slog.Default())

	req := newRequest(t, http.MethodGet, "https://api.github.com/echo", "")
	resp := newResponse("nothing to scrub", nil)

	tctx := newContext()
	res, err := b.TransformResponse(context.Background(), tctx, req, resp)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "nothing to scrub", readBody(t, resp.Body))
}

// --- audit records carry the placeholder only ---

func TestAudit_CarriesPlaceholderNeverCredential(t *testing.T) {
	file := writeSecretsFile(t, map[string]string{"github_token": realSecret})

	// annotate captures the Authorization header into the audit stream and
	// runs before secretbroker, the documented pipeline order.
	annotateT, err := transform.Lookup("annotate")
	require.NoError(t, err)
	capture, err := annotateT(yamlFromString(t, `
annotations:
  - rules:
      - host: "api.github.com"
    headers: ["Authorization"]
`), slog.Default())
	require.NoError(t, err)

	broker := newBroker(t, githubEntry(file, `
    match_body: true`), slog.Default())

	pl := transform.NewPipeline([]transform.Transformer{capture, broker}, transform.BodyLimits{}, slog.Default())

	logger, logs := capturingLogger()
	pl.SetAuditFunc(transform.NewAuditLogger(logger))

	req := newRequest(t, http.MethodPost, "https://api.github.com/graphql", `{"t":"`+placeholder+`"}`)
	req.Header.Set("Authorization", "Bearer "+placeholder)

	result := &transform.PipelineResult{Host: "api.github.com", Method: http.MethodPost, Path: "/graphql"}
	tctx := newContext()
	short, err := pl.ProcessRequest(context.Background(), tctx, req, &result.RequestTransforms)
	require.NoError(t, err)
	require.Nil(t, short)

	// The credential did reach the wire: this is a real substitution, not a
	// no-op that would make the assertion below vacuous.
	require.Equal(t, "Bearer "+realSecret, req.Header.Get("Authorization"))

	// An upstream that echoes the credential back.
	resp := newResponse(`{"echo":"`+realSecret+`"}`, http.Header{"X-Echoed-Token": {realSecret}})
	_, err = pl.ProcessResponse(context.Background(), tctx, req, resp, &result.ResponseTransforms)
	require.NoError(t, err)

	pl.EmitAudit(result)

	require.NotContains(t, logs.String(), realSecret)
	require.Contains(t, logs.String(), placeholder)

	// And specifically: the header annotate captured is the placeholder.
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(logs.Bytes(), &parsed))
	traces := parsed["request_transforms"].([]any)
	annotations := traces[0].(map[string]any)["annotations"].(map[string]any)
	require.Equal(t, "Bearer "+placeholder, annotations["header:Authorization"])
}

func TestAudit_SecretUnavailableRecordsRefNotValue(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.json")
	b := newBroker(t, githubEntry(missing, ""), slog.Default())

	req := newRequest(t, http.MethodGet, "https://api.github.com/user", "")
	req.Header.Set("Authorization", "Bearer "+placeholder)

	tctx := newContext()
	_, err := b.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)

	result := &transform.PipelineResult{
		Host: "api.github.com",
		RequestTransforms: []transform.TransformTrace{
			{Name: transformName, Annotations: tctx.DrainAnnotations()},
		},
	}
	logger, logs := capturingLogger()
	transform.NewAuditLogger(logger)(result)

	require.Contains(t, logs.String(), "github_token")
	require.NotContains(t, logs.String(), realSecret)
}

// --- config validation ---

func TestNewFromConfig_Validation(t *testing.T) {
	cases := []struct {
		name      string
		yaml      string
		wantError string
	}{
		{
			name:      "no entries",
			yaml:      "entries: []",
			wantError: "at least one entry is required",
		},
		{
			name: "missing placeholder",
			yaml: `
secrets_file: /etc/secrets.json
entries:
  - secret_ref: github_token
    hosts: ["api.github.com"]
`,
			wantError: "placeholder is required",
		},
		{
			name: "neither secret_ref nor source",
			yaml: `
entries:
  - placeholder: PH
    hosts: ["api.github.com"]
`,
			wantError: "exactly one of",
		},
		{
			name: "both secret_ref and source",
			yaml: `
secrets_file: /etc/secrets.json
entries:
  - placeholder: PH
    secret_ref: github_token
    source:
      type: env
      var: X
    hosts: ["api.github.com"]
`,
			wantError: "exactly one of",
		},
		{
			name: "secret_ref without secrets_file",
			yaml: `
entries:
  - placeholder: PH
    secret_ref: github_token
    hosts: ["api.github.com"]
`,
			wantError: `requires "secrets_file"`,
		},
		{
			name: "no hosts or rules",
			yaml: `
secrets_file: /etc/secrets.json
entries:
  - placeholder: PH
    secret_ref: github_token
`,
			wantError: `at least one entry in "hosts" or "rules"`,
		},
		{
			name: "wildcard host in hosts",
			yaml: `
secrets_file: /etc/secrets.json
entries:
  - placeholder: PH
    secret_ref: github_token
    hosts: ["*"]
`,
			wantError: `host "*" is not allowed`,
		},
		{
			name: "wildcard host in rules",
			yaml: `
secrets_file: /etc/secrets.json
entries:
  - placeholder: PH
    secret_ref: github_token
    rules:
      - host: "*"
`,
			wantError: `host "*" is not allowed`,
		},
		{
			name: "duplicate placeholder",
			yaml: `
secrets_file: /etc/secrets.json
entries:
  - placeholder: PH
    secret_ref: a
    hosts: ["api.github.com"]
  - placeholder: PH
    secret_ref: b
    hosts: ["api.stripe.com"]
`,
			wantError: "already used by entries[0]",
		},
		{
			name: "overlapping placeholder",
			yaml: `
secrets_file: /etc/secrets.json
entries:
  - placeholder: PH_TOKEN
    secret_ref: a
    hosts: ["api.github.com"]
  - placeholder: PH_TOKEN_LONG
    secret_ref: b
    hosts: ["api.stripe.com"]
`,
			wantError: `overlaps placeholder "PH_TOKEN" from entries[0]`,
		},
		{
			name: "invalid rule path",
			yaml: `
secrets_file: /etc/secrets.json
entries:
  - placeholder: PH
    secret_ref: github_token
    rules:
      - host: "api.github.com"
        paths: ["repos"]
`,
			wantError: "must start with /",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A logger writing nowhere: the missing-file warning that a
			// startup load emits is not what these cases assert on.
			logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
			_, err := newFromConfig(decodeConfig(t, tc.yaml), logger, secrets.BuildSource)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantError)
		})
	}
}

func TestFactory_RegisteredUnderName(t *testing.T) {
	f, err := transform.Lookup(transformName)
	require.NoError(t, err)

	file := writeSecretsFile(t, map[string]string{"github_token": realSecret})
	tr, err := f(yamlFromString(t, githubEntry(file, "")), slog.Default())
	require.NoError(t, err)
	require.Equal(t, transformName, tr.Name())
}

func TestCompileHeaders_AlwaysIncludesAuthorizationWithoutDuplicating(t *testing.T) {
	require.Equal(t, []string{"Authorization"}, compileHeaders(nil))
	require.Equal(t, []string{"Authorization"}, compileHeaders([]string{"authorization"}))
	require.Equal(t,
		[]string{"Authorization", "X-Api-Key", "X-Token"},
		compileHeaders([]string{"x-api-key", "X-Token", "x-api-key"}),
	)
}
