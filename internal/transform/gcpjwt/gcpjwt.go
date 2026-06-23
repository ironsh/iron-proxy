// Package gcpjwt contains small helpers shared by GCP auth transforms for
// recognizing Google JWT-bearer token exchange requests.
package gcpjwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	// JWTBearerGrantType is the OAuth2 grant type used by Google service
	// account keyfiles when exchanging a signed JWT assertion.
	JWTBearerGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"

	// MaxTokenRequestBodyBytes caps token endpoint body inspection. Requests
	// above this size are left for the normal request path.
	MaxTokenRequestBodyBytes = 1 << 20
)

// JWTBearerTargetAudience returns the target_audience claim from a JWT-bearer
// token request body. The request body is restored before returning.
func JWTBearerTargetAudience(req *http.Request) (string, bool) {
	body, ok := tokenRequestBody(req)
	if !ok {
		return "", false
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return "", false
	}
	if values.Get("grant_type") != JWTBearerGrantType {
		return "", false
	}
	return TargetAudienceFromAssertion(values.Get("assertion"))
}

// TargetAudienceFromAssertion extracts the target_audience private claim from
// an unsigned inspection of a JWT assertion.
func TargetAudienceFromAssertion(assertion string) (string, bool) {
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	var claims struct {
		TargetAudience string `json:"target_audience"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return "", false
	}
	return claims.TargetAudience, claims.TargetAudience != ""
}

func tokenRequestBody(req *http.Request) ([]byte, bool) {
	if req.Body == nil {
		return nil, false
	}
	if req.ContentLength < 0 || req.ContentLength > MaxTokenRequestBodyBytes {
		return nil, false
	}

	body, err := io.ReadAll(io.LimitReader(req.Body, MaxTokenRequestBodyBytes+1))
	if err != nil || len(body) > MaxTokenRequestBodyBytes {
		req.Body = &replayReadCloser{
			Reader: io.MultiReader(bytes.NewReader(body), req.Body),
			closer: req.Body,
		}
		return nil, false
	}
	closeErr := req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(body))
	if closeErr != nil {
		return nil, false
	}
	return body, true
}

type replayReadCloser struct {
	io.Reader
	closer io.Closer
}

func (r *replayReadCloser) Close() error {
	return r.closer.Close()
}
