package oauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
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
	headers, headerFingerprint, err := e.resolveEndpointHeaders(ctx)
	if err != nil {
		return nil, err
	}
	fingerprint += headerFingerprint

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.tokenSource != nil && fingerprint == e.fingerprint {
		return e.tokenSource, nil
	}
	tsCtx := ctx
	if len(headers) > 0 {
		tsCtx = context.WithValue(ctx, oauth2.HTTPClient, newHeaderInjectingClient(headers))
	}
	ts, err := buildTokenSource(tsCtx, e.grant, vals, e.scopes, e.cfgEndpoint)
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

// resolveEndpointHeaders mirrors resolveCredentials for the token-endpoint
// header sources. The returned fingerprint slot is namespaced with a NUL so it
// can't collide with credential field names.
func (e *tokenEntry) resolveEndpointHeaders(ctx context.Context) (map[string]string, string, error) {
	if len(e.endpointHeaderSources) == 0 {
		return nil, "", nil
	}
	keys := make([]string, 0, len(e.endpointHeaderSources))
	for k := range e.endpointHeaderSources {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make(map[string]string, len(e.endpointHeaderSources))
	var fp strings.Builder
	fp.WriteByte(0)
	fp.WriteString("endpoint_headers")
	fp.WriteByte(0)
	for _, k := range keys {
		v, err := e.endpointHeaderSources[k].Get(ctx)
		if err != nil {
			return nil, "", fmt.Errorf("loading token_endpoint_headers[%q] from %q: %w", k, e.endpointHeaderSources[k].Name(), err)
		}
		out[k] = v
		fp.WriteString(k)
		fp.WriteByte('=')
		fp.WriteString(v)
		fp.WriteByte(0)
	}
	return out, fp.String(), nil
}

// headerInjectingTransport sets configured headers on every request before
// delegating to the underlying RoundTripper. Used to decorate token-endpoint
// POSTs with vendor-specific headers like x-api-key.
type headerInjectingTransport struct {
	headers map[string]string
	base    http.RoundTripper
}

func (t *headerInjectingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone before mutating: the oauth2 lib may retry, and we must not leak
	// header mutations back to the caller's request object.
	r := req.Clone(req.Context())
	for k, v := range t.headers {
		r.Header.Set(k, v)
	}
	return t.base.RoundTrip(r)
}

func newHeaderInjectingClient(headers map[string]string) *http.Client {
	return &http.Client{Transport: &headerInjectingTransport{
		headers: headers,
		base:    http.DefaultTransport,
	}}
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
	case grantPassword:
		return passwordTokenSource(ctx, vals, scopes, cfgEndpoint)
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

// passwordTokenSource builds a token source for the RFC 6749 4.3 password
// (resource owner password credentials) grant. When the token endpoint returns
// a refresh_token the standard oauth2.Config token source uses it; otherwise
// the source re-runs the password exchange to refresh.
func passwordTokenSource(ctx context.Context, vals map[string]string, scopes []string, cfgEndpoint string) (oauth2.TokenSource, error) {
	username := vals[fieldUsername]
	password := vals[fieldPassword]
	clientID := vals[fieldClientID]
	clientSecret := vals[fieldClientSecret] // optional
	if username == "" || password == "" {
		return nil, fmt.Errorf("password grant is missing the username or password")
	}
	if clientID == "" {
		return nil, fmt.Errorf("password grant is missing the client id")
	}
	if cfgEndpoint == "" {
		return nil, fmt.Errorf("password grant needs a token endpoint: set \"token_endpoint\"")
	}

	cfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			TokenURL:  cfgEndpoint,
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
	src := &passwordSource{ctx: ctx, cfg: cfg, username: username, password: password}
	return oauth2.ReuseTokenSource(nil, src), nil
}

// passwordSource implements oauth2.TokenSource by re-running the password
// exchange whenever a fresh token is requested. ReuseTokenSource wraps it to
// cache and single-flight, so this only fires on first use and after expiry.
type passwordSource struct {
	ctx                context.Context
	cfg                *oauth2.Config
	username, password string
}

func (s *passwordSource) Token() (*oauth2.Token, error) {
	return s.cfg.PasswordCredentialsToken(s.ctx, s.username, s.password)
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
