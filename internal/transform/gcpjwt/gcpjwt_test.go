package gcpjwt

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJWTBearerTargetAudience(t *testing.T) {
	form := url.Values{}
	form.Set("grant_type", JWTBearerGrantType)
	form.Set("assertion", unsignedAssertion(t, map[string]any{
		"target_audience": "https://service.run.app",
	}))
	body := form.Encode()
	req, err := http.NewRequest(http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(body))
	require.NoError(t, err)

	audience, ok := JWTBearerTargetAudience(req)
	require.True(t, ok)
	require.Equal(t, "https://service.run.app", audience)

	restored, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	require.Equal(t, body, string(restored))
}

func TestJWTBearerTargetAudienceRestoresOversizedBody(t *testing.T) {
	body := strings.Repeat("x", MaxTokenRequestBodyBytes+1)
	req, err := http.NewRequest(http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(body))
	require.NoError(t, err)

	audience, ok := JWTBearerTargetAudience(req)
	require.False(t, ok)
	require.Empty(t, audience)

	restored, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	require.Equal(t, body, string(restored))
}

func TestTargetAudienceFromAssertionRejectsMissingAudience(t *testing.T) {
	audience, ok := TargetAudienceFromAssertion(unsignedAssertion(t, map[string]any{
		"scope": "https://www.googleapis.com/auth/cloud-platform",
	}))
	require.False(t, ok)
	require.Empty(t, audience)
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
