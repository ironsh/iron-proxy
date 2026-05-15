// Package gcpauth implements a transform that mints short-lived GCP OAuth2
// access tokens from a service account keyfile and injects them as
// Authorization: Bearer headers on matching requests.
//
// The keyfile can be loaded from disk (keyfile_path) or from any secret
// source registered with the secrets package (env, aws_sm, aws_ssm,
// 1password, 1password_connect) via a nested keyfile block. Token minting,
// caching, and refresh are delegated to golang.org/x/oauth2/google — the same
// code path the official GCP SDKs use.
//
// Like all header-injecting transforms, this requires MITM mode; sni-only
// mode has no way to rewrite headers.
package gcpauth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

// stubAccessToken is the placeholder bearer returned to clients that fetch a
// token from a GCP OAuth2 endpoint through the proxy. The real token is minted
// by gcp_auth and swapped in just before the request leaves the proxy, so the
// value here is never sent to Google: it just has to look like an opaque token
// to the client SDK.
const stubAccessToken = "iron-proxy-stub-token"

var stubTokenJSON = []byte(`{"access_token":"` + stubAccessToken + `","expires_in":3600,"token_type":"Bearer"}`)

func init() {
	transform.Register("gcp_auth", factory)
}

type config struct {
	KeyfilePath string                 `yaml:"keyfile_path,omitempty"`
	Keyfile     yaml.Node              `yaml:"keyfile,omitempty"`
	Scopes      []string               `yaml:"scopes"`
	Rules       []hostmatch.RuleConfig `yaml:"rules"`
}

// GCPAuth is the transform.
type GCPAuth struct {
	scopes  []string
	rules   []hostmatch.Rule // empty = apply to all requests
	loadKey func(ctx context.Context) ([]byte, error)
	logger  *slog.Logger

	mu          sync.Mutex
	tokenSource oauth2.TokenSource
	email       string
}

// sourceBuilder is the signature of secrets.BuildSource. Pulled out so tests
// can inject a stub instead of constructing real source backends.
type sourceBuilder func(yaml.Node, *slog.Logger) (secrets.Source, error)

func factory(cfg yaml.Node, logger *slog.Logger) (transform.Transformer, error) {
	var c config
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing gcp_auth config: %w", err)
	}
	return newFromConfig(c, logger, os.ReadFile, secrets.BuildSource)
}

func newFromConfig(c config, logger *slog.Logger, readFile func(string) ([]byte, error), buildSource sourceBuilder) (*GCPAuth, error) {
	hasPath := c.KeyfilePath != ""
	hasNested := c.Keyfile.Kind != 0
	if hasPath == hasNested {
		return nil, fmt.Errorf("gcp_auth: requires exactly one of \"keyfile_path\" or \"keyfile\"")
	}
	if len(c.Scopes) == 0 {
		return nil, fmt.Errorf("gcp_auth: at least one entry in \"scopes\" is required")
	}
	rules, err := hostmatch.CompileRules(c.Rules, "gcp_auth")
	if err != nil {
		return nil, err
	}

	var load func(context.Context) ([]byte, error)
	if hasPath {
		path := c.KeyfilePath
		load = func(context.Context) ([]byte, error) {
			data, err := readFile(path)
			if err != nil {
				return nil, fmt.Errorf("reading GCP keyfile %q: %w", path, err)
			}
			return data, nil
		}
	} else {
		nested, err := buildSource(c.Keyfile, logger)
		if err != nil {
			return nil, fmt.Errorf("gcp_auth: building keyfile source: %w", err)
		}
		load = func(ctx context.Context) ([]byte, error) {
			v, err := nested.Get(ctx)
			if err != nil {
				return nil, fmt.Errorf("loading GCP keyfile from %q: %w", nested.Name(), err)
			}
			return []byte(v), nil
		}
	}

	return &GCPAuth{
		scopes:  c.Scopes,
		rules:   rules,
		loadKey: load,
		logger:  logger,
	}, nil
}

func (g *GCPAuth) Name() string { return "gcp_auth" }

func (g *GCPAuth) TransformRequest(ctx context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	// Stubbing the well-known OAuth2 token endpoints runs before host rules
	// so client SDKs always complete their token dance against the proxy,
	// even when the user's rules only target API hosts like
	// bigquery.googleapis.com. gcp_auth itself mints the real token.
	if isTokenEndpoint(req) {
		tctx.Annotate("stubbed", "oauth2_token_endpoint")
		return &transform.TransformResult{
			Action:   transform.ActionStub,
			Response: stubTokenResponse(req),
		}, nil
	}

	if len(g.rules) > 0 && !hostmatch.MatchAnyRule(g.rules, req) {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}

	tok, err := g.mintToken(ctx)
	if err != nil {
		tctx.Annotate("error", err.Error())
		tctx.Annotate("rejected", "token_unavailable")
		return &transform.TransformResult{Action: transform.ActionReject}, nil
	}

	req.Header.Set("Authorization", "Bearer "+tok)
	if g.email != "" {
		tctx.Annotate("service_account", g.email)
	}
	tctx.Annotate("injected", []string{"header:Authorization"})
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (g *GCPAuth) TransformResponse(context.Context, *transform.TransformContext, *http.Request, *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (g *GCPAuth) mintToken(ctx context.Context) (string, error) {
	ts, err := g.loadTokenSource(ctx)
	if err != nil {
		return "", err
	}
	tok, err := ts.Token()
	if err != nil {
		return "", fmt.Errorf("minting GCP access token: %w", err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("GCP token source returned empty access token")
	}
	return tok.AccessToken, nil
}

func (g *GCPAuth) loadTokenSource(ctx context.Context) (oauth2.TokenSource, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.tokenSource != nil {
		return g.tokenSource, nil
	}
	keyJSON, err := g.loadKey(ctx)
	if err != nil {
		return nil, err
	}
	// JWTConfigFromJSON is the narrowed, non-deprecated form of credential
	// loading. It only accepts service-account JSON keyfiles, which is what
	// gcp_auth is designed for; we don't want to silently accept the broader
	// set of credential configurations (workload identity federation,
	// external_account, etc.) that CredentialsFromJSON allows.
	cfg, err := google.JWTConfigFromJSON(keyJSON, g.scopes...)
	if err != nil {
		return nil, fmt.Errorf("parsing GCP service account keyfile: %w", err)
	}
	var meta struct {
		ClientEmail string `json:"client_email"`
	}
	if err := json.Unmarshal(keyJSON, &meta); err == nil {
		g.email = meta.ClientEmail
	}
	g.tokenSource = cfg.TokenSource(ctx)
	return g.tokenSource, nil
}

// isTokenEndpoint reports whether req targets a well-known GCP OAuth2 token
// endpoint. Covers the JWT bearer grant endpoint used by service account
// keyfiles (oauth2.googleapis.com/token) and the GCE/GKE metadata server
// endpoints clients hit when they believe they are running on GCP.
func isTokenEndpoint(req *http.Request) bool {
	host := hostmatch.StripPort(req.Host)
	var path string
	if req.URL != nil {
		path = req.URL.Path
	}
	switch host {
	case "oauth2.googleapis.com":
		return path == "/token"
	case "metadata.google.internal", "169.254.169.254":
		return strings.HasPrefix(path, "/computeMetadata/v1/instance/service-accounts/") &&
			strings.HasSuffix(path, "/token")
	}
	return false
}

func stubTokenResponse(req *http.Request) *http.Response {
	body := transform.NewBufferedBodyFromBytes(stubTokenJSON)
	return &http.Response{
		StatusCode:    http.StatusOK,
		Status:        "200 OK",
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"application/json"}},
		Body:          body,
		ContentLength: int64(len(stubTokenJSON)),
		Request:       req,
	}
}
