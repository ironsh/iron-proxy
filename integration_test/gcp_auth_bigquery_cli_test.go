package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestGCPAuthBigQueryGcloudCLI drives the real bq CLI (shipped with the Google
// Cloud SDK) through the proxy to prove the gcp_auth OAuth2 stub works against
// an off-the-shelf client.
//
// The CLI is activated with a *dummy* service account keyfile: the private key
// is freshly generated and corresponds to no real Google identity. When bq
// mints a token it signs a JWT with that dummy key and POSTs it to
// oauth2.googleapis.com/token — the proxy intercepts that request and returns a
// stubbed access token, so the bogus signature is never seen by Google. bq then
// calls bigquery.googleapis.com with the stub bearer, and gcp_auth swaps in a
// real token minted from the genuine keyfile the proxy holds
// (GCP_BIGQUERY_SERVICE_ACCOUNT_KEY_FILE).
//
// The query succeeding therefore depends on both halves of the feature: the
// token endpoint being stubbed and the real token being injected.
//
// Requires the gcloud SDK (gcloud + bq) on PATH and a BigQuery table at
// test_dataset.test_table with a test_field column readable by the configured
// service account.
func TestGCPAuthBigQueryGcloudCLI(t *testing.T) {
	keyfilePath := requireEnv(t, "GCP_BIGQUERY_SERVICE_ACCOUNT_KEY_FILE")
	gcloudBin, err := exec.LookPath("gcloud")
	if err != nil {
		t.Skip("gcloud CLI not found on PATH")
	}
	bqBin, err := exec.LookPath("bq")
	if err != nil {
		t.Skip("bq CLI not found on PATH")
	}

	keyJSON, err := os.ReadFile(keyfilePath)
	require.NoError(t, err, "reading GCP_BIGQUERY_SERVICE_ACCOUNT_KEY_FILE")
	var meta struct {
		ProjectID string `json:"project_id"`
	}
	require.NoError(t, json.Unmarshal(keyJSON, &meta))
	require.NotEmpty(t, meta.ProjectID, "service account JSON missing project_id")

	tmpDir := t.TempDir()
	binary := proxyBinary(t)
	cfgPath := renderConfig(t, tmpDir, "gcp_auth_bigquery_cli.yaml", struct {
		KeyfilePath string
	}{KeyfilePath: keyfilePath})

	proxy := startProxy(t, binary, cfgPath, nil)
	// CONNECT requests for HTTPS upstreams go to the tunnel listener.
	tunnelAddr := proxy.AddrFor(t, "tunnel proxy starting")

	caPath := filepath.Join(repoRoot(t), "tmp", "ca.crt")
	_, err = os.Stat(caPath)
	require.NoError(t, err, "expected proxy CA at %s — generate it with: ./iron-proxy generate-ca -outdir tmp -alg ed25519", caPath)

	dummyKey := writeDummyServiceAccountKeyfile(t, tmpDir)

	// Point gcloud/bq at this test's proxy and CA, fully overriding any
	// ambient proxy configuration the CI runner may have set. CLOUDSDK_CONFIG
	// and BIGQUERYRC keep the CLI state inside the temp dir so the test is
	// hermetic.
	cliEnv := envWith(map[string]string{
		"CLOUDSDK_CONFIG":                    filepath.Join(tmpDir, "cloudsdk"),
		"BIGQUERYRC":                         filepath.Join(tmpDir, "bigqueryrc"),
		"CLOUDSDK_CORE_DISABLE_PROMPTS":      "1",
		"HTTP_PROXY":                         "http://" + tunnelAddr,
		"HTTPS_PROXY":                        "http://" + tunnelAddr,
		"http_proxy":                         "http://" + tunnelAddr,
		"https_proxy":                        "http://" + tunnelAddr,
		"NO_PROXY":                           "",
		"no_proxy":                           "",
		"CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE": caPath,
		"REQUESTS_CA_BUNDLE":                 caPath,
		"SSL_CERT_FILE":                      caPath,
	})

	// activate-service-account is offline: gcloud just stores the keyfile. The
	// dummy key is never validated against Google.
	runCLI(t, cliEnv, 30*time.Second, gcloudBin,
		"auth", "activate-service-account", "--key-file="+dummyKey)

	out := runCLI(t, cliEnv, 90*time.Second, bqBin, "query",
		"--project_id="+meta.ProjectID,
		"--headless",
		"--quiet",
		"--format=json",
		"--use_legacy_sql=false",
		"SELECT test_field FROM test_dataset.test_table LIMIT 1",
	)

	// bq --format=json emits a JSON array of row objects keyed by column name.
	var rows []map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &rows), "parsing bq output: %s", out)
	require.NotEmpty(t, rows, "no rows returned from test_dataset.test_table")
	require.Equal(t, "foo", rows[0]["test_field"], "test_dataset.test_table.test_field first value")
}

// writeDummyServiceAccountKeyfile generates a syntactically valid service
// account JSON keyfile with a freshly minted RSA private key. It is accepted by
// gcloud auth activate-service-account but corresponds to no real identity.
func writeDummyServiceAccountKeyfile(t *testing.T, dir string) string {
	t.Helper()
	keyfile := map[string]string{
		"type":                        "service_account",
		"project_id":                  "iron-proxy-stub",
		"private_key_id":              "stub-private-key-id",
		"private_key":                 generateServiceAccountKeyPEM(t),
		"client_email":                "stub@iron-proxy-stub.iam.gserviceaccount.com",
		"client_id":                   "000000000000000000000",
		"auth_uri":                    "https://accounts.google.com/o/oauth2/auth",
		"token_uri":                   "https://oauth2.googleapis.com/token",
		"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
		"client_x509_cert_url":        "https://www.googleapis.com/robot/v1/metadata/x509/stub%40iron-proxy-stub.iam.gserviceaccount.com",
	}
	data, err := json.MarshalIndent(keyfile, "", "  ")
	require.NoError(t, err)

	path := filepath.Join(dir, "dummy-sa.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

// runCLI runs an external command with the given environment and timeout,
// failing the test with full stdout/stderr if it exits non-zero.
func runCLI(t *testing.T, env []string, timeout time.Duration, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	require.NoError(t, err, "%s %s failed\nstdout:\n%s\nstderr:\n%s",
		name, strings.Join(args, " "), stdout.String(), stderr.String())
	return stdout.String()
}

// envWith returns os.Environ() with the given keys overridden. Existing entries
// for an overridden key are dropped so the new value is the only one the child
// process sees (libc getenv returns the first match).
func envWith(overrides map[string]string) []string {
	out := make([]string, 0, len(os.Environ())+len(overrides))
	for _, kv := range os.Environ() {
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			continue
		}
		if _, ok := overrides[kv[:eq]]; ok {
			continue
		}
		out = append(out, kv)
	}
	for k, v := range overrides {
		out = append(out, k+"="+v)
	}
	return out
}
