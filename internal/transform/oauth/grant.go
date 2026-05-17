package oauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
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

// tokenSourceFor returns the entry's oauth2.TokenSource, rebuilding it when any
// credential value has changed since it was last built. The returned source
// caches the access token and single-flights concurrent refreshes.
func (e *tokenEntry) tokenSourceFor(ctx context.Context) (oauth2.TokenSource, error) {
	// Sources are read outside the lock: each has its own ttl cache, so this is
	// cheap and returns stable values within the ttl window.
	vals, fingerprint, err := e.resolveCredentials(ctx)
	if err != nil {
		return nil, err
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.tokenSource != nil && fingerprint == e.fingerprint {
		return e.tokenSource, nil
	}
	ts, err := buildTokenSource(ctx, e.grant, vals, e.scopes, e.cfgEndpoint)
	if err != nil {
		return nil, err
	}
	e.tokenSource = ts
	e.fingerprint = fingerprint
	return ts, nil
}

// resolveCredentials fetches every credential source for the entry and returns
// the resolved values keyed by field, plus a fingerprint that changes whenever
// any value does.
func (e *tokenEntry) resolveCredentials(ctx context.Context) (map[string]string, string, error) {
	keys := make([]string, 0, len(e.sources))
	for k := range e.sources {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	vals := make(map[string]string, len(e.sources))
	var fp strings.Builder
	for _, k := range keys {
		v, err := e.sources[k].Get(ctx)
		if err != nil {
			return nil, "", fmt.Errorf("loading %s from %q: %w", k, e.sources[k].Name(), err)
		}
		vals[k] = v
		fp.WriteString(k)
		fp.WriteByte('=')
		fp.WriteString(v)
		fp.WriteByte(0)
	}
	return vals, fp.String(), nil
}

// buildTokenSource constructs an oauth2.TokenSource for one grant from its
// resolved credential values. It performs no I/O: the token is exchanged
// lazily on the first Token() call.
func buildTokenSource(ctx context.Context, grant string, vals map[string]string, scopes []string, cfgEndpoint string) (oauth2.TokenSource, error) {
	switch grant {
	case grantRefreshToken:
		return refreshTokenTokenSource(ctx, vals, scopes, cfgEndpoint)
	case grantClientCredentials:
		return clientCredentialsTokenSource(ctx, vals, scopes, cfgEndpoint)
	default:
		return nil, fmt.Errorf("unknown grant %q", grant)
	}
}

// refreshTokenTokenSource builds a token source for the RFC 6749 refresh_token
// grant from discrete sources: a refresh token, a client id, and an optional
// client secret (public clients have none). The token endpoint comes from the
// configured token_endpoint.
func refreshTokenTokenSource(ctx context.Context, vals map[string]string, scopes []string, cfgEndpoint string) (oauth2.TokenSource, error) {
	refreshToken := vals[fieldRefreshToken]
	clientID := vals[fieldClientID]
	clientSecret := vals[fieldClientSecret] // empty for public clients
	if refreshToken == "" {
		return nil, fmt.Errorf("refresh_token grant is missing the refresh token")
	}
	if clientID == "" {
		return nil, fmt.Errorf("refresh_token grant is missing the client id")
	}
	if cfgEndpoint == "" {
		return nil, fmt.Errorf("refresh_token grant needs a token endpoint: set \"token_endpoint\"")
	}

	cfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			TokenURL: cfgEndpoint,
			// Send client_id/client_secret in the form body, never as HTTP
			// Basic. Every provider in scope accepts body auth.
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
	// No access-token seed: the source exchanges the refresh token on first
	// use. One extra exchange at startup is cheaper than carrying a
	// provider-specific expiry format.
	return cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}), nil
}

// clientCredentialsTokenSource builds a token source for the RFC 6749 4.4
// client_credentials grant from discrete client_id and client_secret sources.
func clientCredentialsTokenSource(ctx context.Context, vals map[string]string, scopes []string, tokenURL string) (oauth2.TokenSource, error) {
	clientID := vals[fieldClientID]
	clientSecret := vals[fieldClientSecret]
	if clientID == "" || clientSecret == "" {
		return nil, fmt.Errorf("client_credentials grant needs a client id and client secret")
	}
	cfg := &clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
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
