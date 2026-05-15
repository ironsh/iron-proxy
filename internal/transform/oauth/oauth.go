// Package oauth implements a transform that mints OAuth2 access tokens and
// injects them as Authorization: Bearer headers on matching requests.
//
// One oauth_token transform carries a list of token entries. Each entry
// names an OAuth2 grant (refresh_token, jwt_bearer, or client_credentials), a
// credential resolved from any secrets-package source (env, 1password,
// 1password_connect, aws_sm, aws_ssm), and host rules selecting the requests
// it applies to. Token exchange, caching, refresh, and single-flight are
// delegated to golang.org/x/oauth2 — the same code path the official SDKs use.
//
// jwt_bearer is a strict superset of the older gcp_auth transform: same
// JWT-bearer exchange, plus a subject field for Workspace domain-wide
// delegation.
//
// Like all header-injecting transforms, this requires MITM mode; sni-only
// mode has no way to rewrite headers.
package oauth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"

	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

const (
	grantRefreshToken      = "refresh_token"
	grantJWTBearer         = "jwt_bearer"
	grantClientCredentials = "client_credentials"
)

// stubAccessToken is the placeholder bearer returned to clients that fetch a
// token from a configured token endpoint through the proxy. The real token is
// minted by oauth_token and swapped in just before the request leaves the
// proxy, so the value here never reaches the upstream: it only has to look
// like an opaque token to the client SDK.
const stubAccessToken = "iron-proxy-stub-token"

var stubTokenJSON = []byte(`{"access_token":"` + stubAccessToken + `","expires_in":3600,"token_type":"Bearer"}`)

func init() {
	transform.Register("oauth_token", factory)
}

type config struct {
	Tokens []tokenEntryConfig `yaml:"tokens"`
}

type tokenEntryConfig struct {
	Grant         string                 `yaml:"grant"`
	Credential    yaml.Node              `yaml:"credential"`
	TokenEndpoint string                 `yaml:"token_endpoint,omitempty"`
	Scopes        []string               `yaml:"scopes,omitempty"`
	Subject       string                 `yaml:"subject,omitempty"`
	Rules         []hostmatch.RuleConfig `yaml:"rules"`
	Header        string                 `yaml:"header,omitempty"`
	ValuePrefix   string                 `yaml:"value_prefix,omitempty"`
}

// sourceBuilder is the signature of secrets.BuildSource. Pulled out so tests
// can inject a stub instead of constructing real source backends.
type sourceBuilder func(yaml.Node, *slog.Logger) (secrets.Source, error)

// OAuth is the transform.
type OAuth struct {
	entries       []*tokenEntry
	stubEndpoints []tokenEndpoint
}

// tokenEntry is one resolved entry from config.tokens.
type tokenEntry struct {
	grant       string
	scopes      []string
	subject     string // jwt_bearer only
	rules       []hostmatch.Rule
	header      string
	valuePrefix string
	cfgEndpoint string // config token_endpoint, "" if unset
	credential  secrets.Source
	logger      *slog.Logger

	// mu guards the lazily built token source and the credential blob it was
	// built from. The token source is rebuilt when the blob changes (e.g. the
	// credential's ttl expired and the secret store returned a new value).
	mu          sync.Mutex
	blob        string
	tokenSource oauth2.TokenSource
}

// tokenEndpoint is a host+path pair that, when matched by an inbound request,
// is served a synthetic token response instead of being forwarded.
type tokenEndpoint struct {
	host string
	path string
}

func factory(cfg yaml.Node, logger *slog.Logger) (transform.Transformer, error) {
	var c config
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing oauth_token config: %w", err)
	}
	return newFromConfig(c, logger, secrets.BuildSource)
}

func newFromConfig(c config, logger *slog.Logger, buildSource sourceBuilder) (*OAuth, error) {
	if len(c.Tokens) == 0 {
		return nil, fmt.Errorf("oauth_token: at least one entry in \"tokens\" is required")
	}
	o := &OAuth{}
	for i, tc := range c.Tokens {
		entry, stub, err := buildEntry(tc, logger, buildSource)
		if err != nil {
			return nil, fmt.Errorf("oauth_token: tokens[%d]: %w", i, err)
		}
		o.entries = append(o.entries, entry)
		if stub != nil {
			o.stubEndpoints = append(o.stubEndpoints, *stub)
		}
	}
	return o, nil
}

func buildEntry(tc tokenEntryConfig, logger *slog.Logger, buildSource sourceBuilder) (*tokenEntry, *tokenEndpoint, error) {
	switch tc.Grant {
	case grantRefreshToken, grantJWTBearer, grantClientCredentials:
	default:
		return nil, nil, fmt.Errorf("\"grant\" must be one of refresh_token, jwt_bearer, client_credentials (got %q)", tc.Grant)
	}
	if tc.Credential.Kind == 0 {
		return nil, nil, fmt.Errorf("\"credential\" is required")
	}
	if tc.Subject != "" && tc.Grant != grantJWTBearer {
		return nil, nil, fmt.Errorf("\"subject\" is only valid for the jwt_bearer grant")
	}
	if tc.Grant == grantClientCredentials && tc.TokenEndpoint == "" {
		return nil, nil, fmt.Errorf("client_credentials grant requires \"token_endpoint\"")
	}

	rules, err := hostmatch.CompileRules(tc.Rules, "rules")
	if err != nil {
		return nil, nil, err
	}
	if len(rules) == 0 {
		return nil, nil, fmt.Errorf("at least one entry in \"rules\" is required")
	}

	src, err := buildSource(tc.Credential, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("building credential source: %w", err)
	}

	var stub *tokenEndpoint
	if tc.TokenEndpoint != "" {
		stub, err = parseTokenEndpoint(tc.TokenEndpoint)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid token_endpoint: %w", err)
		}
	}

	header := tc.Header
	if header == "" {
		header = "Authorization"
	}
	valuePrefix := tc.ValuePrefix
	if valuePrefix == "" {
		valuePrefix = "Bearer "
	}

	return &tokenEntry{
		grant:       tc.Grant,
		scopes:      tc.Scopes,
		subject:     tc.Subject,
		rules:       rules,
		header:      header,
		valuePrefix: valuePrefix,
		cfgEndpoint: tc.TokenEndpoint,
		credential:  src,
		logger:      logger,
	}, stub, nil
}

// parseTokenEndpoint splits a configured token endpoint URL into the host and
// path used to recognize a client's token request for stubbing.
func parseTokenEndpoint(raw string) (*tokenEndpoint, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%q has no host", raw)
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	return &tokenEndpoint{host: hostmatch.StripPort(u.Host), path: path}, nil
}

func (o *OAuth) Name() string { return "oauth_token" }

func (o *OAuth) TransformRequest(ctx context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	// Stubbing a configured token endpoint runs before host rules so a
	// sandboxed SDK can always complete its own token dance against the proxy
	// with a placeholder token. oauth_token mints the real token separately
	// and injects it on the API request.
	if o.matchesTokenEndpoint(req) {
		tctx.Annotate("stubbed", "oauth2_token_endpoint")
		return &transform.TransformResult{
			Action:   transform.ActionStub,
			Response: stubTokenResponse(req),
		}, nil
	}

	// First entry whose rules host-match wins; config order is the tie-breaker.
	entry := o.matchEntry(req)
	if entry == nil {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}

	tok, err := entry.mint(ctx)
	if err != nil {
		reason := entry.logMintFailure(err)
		tctx.Annotate("grant", entry.grant)
		tctx.Annotate("error", reason)
		tctx.Annotate("rejected", "token_unavailable")
		// Fail closed with a 502: forwarding an unauthenticated request would
		// surface as a confusing upstream 401.
		return &transform.TransformResult{
			Action:   transform.ActionReject,
			Response: mintFailureResponse(req, entry.grant),
		}, nil
	}

	req.Header.Set(entry.header, entry.valuePrefix+tok)
	tctx.Annotate("grant", entry.grant)
	if entry.subject != "" {
		tctx.Annotate("subject", entry.subject)
	}
	tctx.Annotate("injected", []string{"header:" + http.CanonicalHeaderKey(entry.header)})
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (o *OAuth) TransformResponse(context.Context, *transform.TransformContext, *http.Request, *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

// matchEntry returns the first entry whose host rules match req, or nil.
func (o *OAuth) matchEntry(req *http.Request) *tokenEntry {
	for _, e := range o.entries {
		if hostmatch.MatchAnyRule(e.rules, req) {
			return e
		}
	}
	return nil
}

// matchesTokenEndpoint reports whether req targets one of the configured token
// endpoints, which the proxy serves with a synthetic token instead of
// forwarding.
func (o *OAuth) matchesTokenEndpoint(req *http.Request) bool {
	host := hostmatch.StripPort(req.Host)
	var path string
	if req.URL != nil {
		path = req.URL.Path
	}
	for _, te := range o.stubEndpoints {
		if te.host == host && te.path == path {
			return true
		}
	}
	return false
}

func stubTokenResponse(req *http.Request) *http.Response {
	return jsonResponse(req, http.StatusOK, "200 OK", stubTokenJSON)
}

func mintFailureResponse(req *http.Request, grant string) *http.Response {
	// grant is a config-validated enum, so it is safe to interpolate.
	body := []byte(`{"error":"oauth_token failed to mint an access token","grant":"` + grant + `"}`)
	return jsonResponse(req, http.StatusBadGateway, "502 Bad Gateway", body)
}

func jsonResponse(req *http.Request, status int, statusText string, body []byte) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Status:        statusText,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"application/json"}},
		Body:          transform.NewBufferedBodyFromBytes(body),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}
