package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/oauth2/google"
)

// mint returns a cached or freshly minted access token for the entry.
func (e *tokenEntry) mint(ctx context.Context) (string, error) {
	ts, err := e.tokenSourceFor(ctx)
	if err != nil {
		return "", err
	}
	tok, err := ts.Token()
	if err != nil {
		return "", fmt.Errorf("minting %s access token: %w", e.grant, err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("%s token endpoint returned an empty access_token", e.grant)
	}
	return tok.AccessToken, nil
}

// tokenSourceFor returns the entry's oauth2.TokenSource, rebuilding it when the
// credential blob has changed since it was last built. The returned source
// caches the access token and single-flights concurrent refreshes.
func (e *tokenEntry) tokenSourceFor(ctx context.Context) (oauth2.TokenSource, error) {
	// Get is read outside the lock: the secrets source has its own ttl cache,
	// so this is cheap and returns a stable value within the ttl window.
	blob, err := e.credential.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading credential from %q: %w", e.credential.Name(), err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.tokenSource != nil && blob == e.blob {
		return e.tokenSource, nil
	}
	ts, err := buildTokenSource(ctx, e.grant, blob, e.scopes, e.subject, e.cfgEndpoint)
	if err != nil {
		return nil, err
	}
	e.tokenSource = ts
	e.blob = blob
	return ts, nil
}

// buildTokenSource constructs an oauth2.TokenSource for one grant from its
// credential blob. It performs no I/O: the token is exchanged lazily on the
// first Token() call.
func buildTokenSource(ctx context.Context, grant, blob string, scopes []string, subject, cfgEndpoint string) (oauth2.TokenSource, error) {
	switch grant {
	case grantJWTBearer:
		return jwtBearerTokenSource(ctx, blob, scopes, subject)
	case grantRefreshToken:
		return refreshTokenTokenSource(ctx, blob, scopes, cfgEndpoint)
	case grantClientCredentials:
		return clientCredentialsTokenSource(ctx, blob, scopes, cfgEndpoint)
	default:
		return nil, fmt.Errorf("unknown grant %q", grant)
	}
}

// jwtBearerTokenSource builds a token source for the RFC 7523 JWT-bearer grant
// from a GCP service-account keyfile. A non-empty subject impersonates that
// Workspace user via domain-wide delegation.
func jwtBearerTokenSource(ctx context.Context, blob string, scopes []string, subject string) (oauth2.TokenSource, error) {
	// JWTConfigFromJSON only accepts service-account keyfiles and validates
	// that client_email, private_key, and token_uri are present.
	cfg, err := google.JWTConfigFromJSON([]byte(blob), scopes...)
	if err != nil {
		return nil, fmt.Errorf("parsing jwt_bearer service account keyfile: %w", err)
	}
	cfg.Subject = subject
	return cfg.TokenSource(ctx), nil
}

// authorizedUser is the refresh_token credential blob. Google's
// Credentials.to_json() authorized-user output satisfies it directly.
type authorizedUser struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	TokenURI     string `json:"token_uri"`
	Expiry       string `json:"expiry"`
}

// refreshTokenTokenSource builds a token source for the RFC 6749 refresh_token
// grant. The token endpoint is the blob's token_uri when present, otherwise
// the configured token_endpoint.
func refreshTokenTokenSource(ctx context.Context, blob string, scopes []string, cfgEndpoint string) (oauth2.TokenSource, error) {
	var au authorizedUser
	if err := json.Unmarshal([]byte(blob), &au); err != nil {
		return nil, fmt.Errorf("parsing refresh_token credential: %w", err)
	}
	if au.RefreshToken == "" {
		return nil, fmt.Errorf("refresh_token credential is missing \"refresh_token\"")
	}
	if au.ClientID == "" {
		return nil, fmt.Errorf("refresh_token credential is missing \"client_id\"")
	}
	tokenURL := au.TokenURI
	if tokenURL == "" {
		tokenURL = cfgEndpoint
	}
	if tokenURL == "" {
		return nil, fmt.Errorf("refresh_token grant needs a token endpoint: set \"token_endpoint\" or include \"token_uri\" in the credential")
	}

	cfg := &oauth2.Config{
		ClientID:     au.ClientID,
		ClientSecret: au.ClientSecret,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			TokenURL: tokenURL,
			// Send client_id/client_secret in the form body, never as HTTP
			// Basic. Every provider in scope accepts body auth.
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}

	// Seed the cache from the blob's token/expiry to skip the first refresh.
	// The expiry format is provider-specific; if it does not parse, the seed
	// is dropped and the token source refreshes on first use.
	seed := &oauth2.Token{RefreshToken: au.RefreshToken}
	if au.Token != "" && au.Expiry != "" {
		if exp, err := time.Parse(time.RFC3339, au.Expiry); err == nil && exp.After(time.Now()) {
			seed.AccessToken = au.Token
			seed.Expiry = exp
		}
	}
	return cfg.TokenSource(ctx, seed), nil
}

// clientCredentials is the client_credentials credential blob.
type clientCredentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// clientCredentialsTokenSource builds a token source for the RFC 6749 4.4
// client_credentials grant.
func clientCredentialsTokenSource(ctx context.Context, blob string, scopes []string, tokenURL string) (oauth2.TokenSource, error) {
	var cc clientCredentials
	if err := json.Unmarshal([]byte(blob), &cc); err != nil {
		return nil, fmt.Errorf("parsing client_credentials credential: %w", err)
	}
	if cc.ClientID == "" || cc.ClientSecret == "" {
		return nil, fmt.Errorf("client_credentials credential needs \"client_id\" and \"client_secret\"")
	}
	cfg := &clientcredentials.Config{
		ClientID:     cc.ClientID,
		ClientSecret: cc.ClientSecret,
		TokenURL:     tokenURL,
		Scopes:       scopes,
		AuthStyle:    oauth2.AuthStyleInParams,
	}
	return cfg.TokenSource(ctx), nil
}

// logMintFailure classifies and logs a mint error and returns a short reason
// string for the audit annotation. An invalid_grant (revoked or expired
// refresh token) is unrecoverable and needs a human, so it logs at error
// level; everything else is potentially transient and logs at warn.
func (e *tokenEntry) logMintFailure(err error) string {
	reason, unrecoverable := classifyMintError(err)
	level := slog.LevelWarn
	if unrecoverable {
		level = slog.LevelError
	}
	if e.logger != nil {
		// err may carry the token endpoint's error response, which is the
		// standard OAuth2 error JSON and contains no credential material.
		e.logger.Log(context.Background(), level, "oauth_token mint failed",
			"grant", e.grant, "reason", reason, "error", err)
	}
	return reason
}

func classifyMintError(err error) (reason string, unrecoverable bool) {
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		switch {
		case re.ErrorCode == "invalid_grant":
			return "invalid_grant", true
		case re.ErrorCode != "":
			return re.ErrorCode, false
		case re.Response != nil:
			return fmt.Sprintf("token_endpoint_http_%d", re.Response.StatusCode), false
		default:
			return "token_endpoint_error", false
		}
	}
	return "mint_failed", false
}
