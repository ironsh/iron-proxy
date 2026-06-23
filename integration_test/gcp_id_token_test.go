package integration_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestGCPIDToken drives the gcp_id_token transform end-to-end without real GCP
// infra by steering the service-account token_uri at a local httptest server.
func TestGCPIDToken(t *testing.T) {
	tmpDir := t.TempDir()
	binary := proxyBinary(t)

	const audience = "https://private-service.run.app"
	var (
		tokenCalls atomic.Int64
		gotAud     atomic.Value
	)
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenCalls.Add(1)
		require.NoError(t, r.ParseForm())
		assertion := r.PostForm.Get("assertion")
		claims := decodeJWTClaims(t, assertion)
		targetAudience, ok := claims["target_audience"].(string)
		require.True(t, ok, "service account assertion must include target_audience")
		gotAud.Store(targetAudience)
		idToken := fakeGoogleIDToken(t, targetAudience)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id_token":   idToken,
			"token_type": "Bearer",
			"expires_in": 3600,
		})
	}))
	defer tokenSrv.Close()

	var (
		mu      sync.Mutex
		gotAuth string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	keyfile := writeIDTokenKeyfile(t, tmpDir, tokenSrv.URL)
	cfgPath := renderConfig(t, tmpDir, "gcp_id_token.yaml", struct {
		KeyfilePath string
		Audience    string
	}{
		KeyfilePath: keyfile,
		Audience:    audience,
	})
	proxy := startProxy(t, binary, cfgPath, nil)
	upstreamHost := upstream.Listener.Addr().String()

	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/private", proxy.HTTPAddr), nil)
	require.NoError(t, err)
	req.Host = upstreamHost
	req.Header.Set("Authorization", "Bearer agent-placeholder")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, gotAuth)
	require.NotContains(t, gotAuth, "agent-placeholder", "agent placeholder bearer must be replaced")
	require.True(t, strings.HasPrefix(gotAuth, "Bearer "), "ID token must be injected as a bearer")
	claims := decodeJWTClaims(t, strings.TrimPrefix(gotAuth, "Bearer "))
	require.Equal(t, audience, claims["aud"])
	require.Equal(t, audience, gotAud.Load())
	require.Equal(t, int64(1), tokenCalls.Load(), "token endpoint should be hit exactly once and then cached")
}

func writeIDTokenKeyfile(t *testing.T, dir, tokenURI string) string {
	t.Helper()
	keyfile := map[string]string{
		"type":         "service_account",
		"project_id":   "iron-proxy-id-token-test",
		"private_key":  generateServiceAccountKeyPEM(t),
		"client_email": "cloud-run-caller@iron-proxy-test.iam.gserviceaccount.com",
		"token_uri":    tokenURI,
	}
	data, err := json.MarshalIndent(keyfile, "", "  ")
	require.NoError(t, err)

	path := filepath.Join(dir, "cloud-run-sa.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func fakeGoogleIDToken(t *testing.T, audience string) string {
	t.Helper()
	now := time.Now()
	header := map[string]any{
		"alg": "RS256",
		"typ": "JWT",
	}
	claims := map[string]any{
		"iss":            "https://accounts.google.com",
		"aud":            audience,
		"azp":            "112010400000000710080",
		"sub":            "112010400000000710080",
		"email":          "cloud-run-caller@iron-proxy-test.iam.gserviceaccount.com",
		"email_verified": true,
		"iat":            now.Unix(),
		"exp":            now.Add(time.Hour).Unix(),
	}
	return encodeJWTPart(t, header) + "." + encodeJWTPart(t, claims) + "." + encodeJWTPart(t, "signature")
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

func encodeJWTPart(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(b)
}
