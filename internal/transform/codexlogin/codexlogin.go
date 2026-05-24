package codexlogin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

const (
	defaultClientID      = "app_EMoamEEZ73f0CkXaXp7hrann"
	defaultTokenEndpoint = "https://auth.openai.com/oauth/token"
	defaultRefreshSkew   = 5 * time.Minute

	stubJWT          = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJleHAiOjQxMDI0NDQ4MDAsImVtYWlsIjoiaXJvbi1wcm94eS1jb2RleC1zdHViQGV4YW1wbGUuaW52YWxpZCIsImh0dHBzOi8vYXBpLm9wZW5haS5jb20vcHJvZmlsZSI6eyJlbWFpbCI6Imlyb24tcHJveHktY29kZXgtc3R1YkBleGFtcGxlLmludmFsaWQifSwiaHR0cHM6Ly9hcGkub3BlbmFpLmNvbS9hdXRoIjp7InVzZXJfaWQiOiJpcm9uLXByb3h5LWNvZGV4LXN0dWItdXNlciIsImNoYXRncHRfdXNlcl9pZCI6Imlyb24tcHJveHktY29kZXgtc3R1Yi11c2VyIiwiY2hhdGdwdF9hY2NvdW50X2lkIjoiaXJvbi1wcm94eS1jb2RleC1zdHViLWFjY291bnQiLCJjaGF0Z3B0X2FjY291bnRfaXNfZmVkcmFtcCI6ZmFsc2V9fQ.stub-signature"
	stubAccessToken  = stubJWT
	stubRefreshToken = "iron-proxy-codex-stub-refresh-token"
	stubIDToken      = stubJWT
)

var stubTokenJSON = []byte(`{"access_token":"` + stubAccessToken + `","refresh_token":"` + stubRefreshToken + `","id_token":"` + stubIDToken + `","expires_in":3600,"token_type":"Bearer"}`)

func init() {
	transform.Register("codex_login", factory)
}

type config struct {
	AuthJSON      authJSONConfig         `yaml:"auth_json"`
	Rules         []hostmatch.RuleConfig `yaml:"rules"`
	ClientID      string                 `yaml:"client_id,omitempty"`
	TokenEndpoint string                 `yaml:"token_endpoint,omitempty"`
	RefreshSkew   string                 `yaml:"refresh_skew,omitempty"`
}

type authJSONConfig struct {
	Source    yaml.Node `yaml:"source"`
	Writeback yaml.Node `yaml:"writeback"`
}

type sourceBuilder func(yaml.Node, *slog.Logger) (secrets.Source, error)
type writerBuilder func(yaml.Node, *slog.Logger) (authJSONWriter, error)

type authJSONWriter interface {
	CompareAndSwap(ctx context.Context, oldRefreshToken, newValue string) (currentValue string, swapped bool, err error)
}

type CodexLogin struct {
	auth          *authEntry
	rules         []hostmatch.Rule
	tokenEndpoint tokenEndpoint
	clientID      string
	refreshSkew   time.Duration
	now           func() time.Time
	httpClient    *http.Client
}

type authEntry struct {
	source    secrets.Source
	writer    authJSONWriter
	mu        sync.Mutex
	cachedRaw string
}

type tokenEndpoint struct {
	scheme    string
	host      string
	matchHost string
	path      string
}

func factory(cfg yaml.Node, logger *slog.Logger) (transform.Transformer, error) {
	var c config
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing codex_login config: %w", err)
	}
	return newFromConfig(c, logger, secrets.BuildSource, buildAuthJSONWriter)
}

func newFromConfig(c config, logger *slog.Logger, buildSource sourceBuilder, buildWriter writerBuilder) (*CodexLogin, error) {
	if c.AuthJSON.Source.Kind == 0 {
		return nil, fmt.Errorf("codex_login: auth_json.source is required")
	}
	if c.AuthJSON.Writeback.Kind == 0 {
		return nil, fmt.Errorf("codex_login: auth_json.writeback is required")
	}
	src, err := buildSource(c.AuthJSON.Source, logger)
	if err != nil {
		return nil, fmt.Errorf("codex_login: building auth_json.source: %w", err)
	}
	writer, err := buildWriter(c.AuthJSON.Writeback, logger)
	if err != nil {
		return nil, fmt.Errorf("codex_login: building auth_json.writeback: %w", err)
	}
	rules, err := hostmatch.CompileRules(c.Rules, "codex_login")
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("codex_login: at least one entry in \"rules\" is required")
	}
	tokenURL := c.TokenEndpoint
	if tokenURL == "" {
		tokenURL = defaultTokenEndpoint
	}
	endpoint, err := parseTokenEndpoint(tokenURL)
	if err != nil {
		return nil, fmt.Errorf("codex_login: invalid token_endpoint: %w", err)
	}
	clientID := c.ClientID
	if clientID == "" {
		clientID = defaultClientID
	}
	refreshSkew := defaultRefreshSkew
	if c.RefreshSkew != "" {
		refreshSkew, err = time.ParseDuration(c.RefreshSkew)
		if err != nil {
			return nil, fmt.Errorf("codex_login: parsing refresh_skew: %w", err)
		}
	}
	return &CodexLogin{
		auth:          &authEntry{source: src, writer: writer},
		rules:         rules,
		tokenEndpoint: *endpoint,
		clientID:      clientID,
		refreshSkew:   refreshSkew,
		now:           time.Now,
		httpClient:    http.DefaultClient,
	}, nil
}

func (c *CodexLogin) Name() string { return "codex_login" }

func (c *CodexLogin) TransformRequest(ctx context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	if c.matchesTokenEndpoint(req) {
		tctx.Annotate("stubbed", "codex_token_endpoint")
		return &transform.TransformResult{
			Action:   transform.ActionStub,
			Response: jsonResponse(req, http.StatusOK, "200 OK", stubTokenJSON),
		}, nil
	}
	if !hostmatch.MatchAnyRule(c.rules, req) {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}

	auth, err := c.authForRequest(ctx)
	if err != nil {
		tctx.Annotate("error", "codex_auth_unavailable")
		tctx.Annotate("rejected", "token_unavailable")
		return &transform.TransformResult{
			Action:   transform.ActionReject,
			Response: jsonResponse(req, http.StatusBadGateway, "502 Bad Gateway", []byte(`{"error":"codex_login failed to load auth"}`)),
		}, nil
	}
	req.Header.Set("Authorization", "Bearer "+auth.accessToken)
	req.Header.Set("ChatGPT-Account-ID", auth.accountID)
	tctx.Annotate("injected", []string{"header:Authorization", "header:ChatGPT-Account-ID"})
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (c *CodexLogin) TransformResponse(context.Context, *transform.TransformContext, *http.Request, *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (c *CodexLogin) authForRequest(ctx context.Context) (*codexAuth, error) {
	c.auth.mu.Lock()
	defer c.auth.mu.Unlock()

	raw, err := c.auth.source.Get(ctx)
	if err != nil {
		return nil, err
	}
	auth, err := parseAuthJSON(raw)
	if err != nil {
		return nil, err
	}
	if c.auth.cachedRaw != "" {
		if cachedAuth, cacheErr := parseAuthJSON(c.auth.cachedRaw); cacheErr == nil {
			if auth.refreshToken != cachedAuth.refreshToken && auth.needsRefresh(c.now(), c.refreshSkew) {
				raw = c.auth.cachedRaw
				auth = cachedAuth
			} else {
				c.auth.cachedRaw = raw
			}
		}
	}
	if !auth.needsRefresh(c.now(), c.refreshSkew) {
		return auth, nil
	}
	refreshed, err := c.refreshWithCAS(ctx, raw, auth)
	if err != nil {
		return nil, err
	}
	c.auth.cachedRaw = refreshed.rawString
	return refreshed, nil
}

func (c *CodexLogin) refreshWithCAS(ctx context.Context, raw string, auth *codexAuth) (*codexAuth, error) {
	currentRaw := raw
	currentAuth := auth
	for attempt := 0; attempt < 2; attempt++ {
		if currentAuth.refreshToken == "" {
			return nil, fmt.Errorf("auth_json tokens.refresh_token is required")
		}
		updatedRaw, updatedAuth, err := c.refresh(ctx, currentAuth)
		if err != nil {
			return nil, err
		}
		storedRaw, swapped, err := c.auth.writer.CompareAndSwap(ctx, currentAuth.refreshToken, updatedRaw)
		if err != nil {
			return nil, err
		}
		if swapped {
			return updatedAuth, nil
		}
		currentRaw = storedRaw
		currentAuth, err = parseAuthJSON(currentRaw)
		if err != nil {
			return nil, err
		}
		if !currentAuth.needsRefresh(c.now(), c.refreshSkew) {
			return currentAuth, nil
		}
	}
	return nil, fmt.Errorf("auth_json refresh token changed during writeback")
}

func (c *CodexLogin) refresh(ctx context.Context, auth *codexAuth) (string, *codexAuth, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {auth.refreshToken},
		"client_id":     {c.clientID},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenEndpoint.scheme+"://"+c.tokenEndpoint.host+c.tokenEndpoint.path, strings.NewReader(form.Encode()))
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("refreshing codex auth: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", nil, fmt.Errorf("reading codex refresh response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", nil, fmt.Errorf("codex refresh returned %d", resp.StatusCode)
	}
	var tokenResp map[string]any
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", nil, fmt.Errorf("parsing codex refresh response: %w", err)
	}
	updatedRaw, err := auth.updatedRaw(tokenResp, c.now())
	if err != nil {
		return "", nil, err
	}
	updatedAuth, err := parseAuthJSON(updatedRaw)
	if err != nil {
		return "", nil, err
	}
	return updatedRaw, updatedAuth, nil
}

func (c *CodexLogin) matchesTokenEndpoint(req *http.Request) bool {
	host := hostmatch.StripPort(req.Host)
	path := ""
	if req.URL != nil {
		path = req.URL.Path
	}
	return host == c.tokenEndpoint.matchHost && path == c.tokenEndpoint.path
}

type codexAuth struct {
	raw          map[string]any
	rawString    string
	accessToken  string
	refreshToken string
	accountID    string
}

func parseAuthJSON(raw string) (*codexAuth, error) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nil, fmt.Errorf("parsing auth_json: %w", err)
	}
	auth := &codexAuth{
		rawString:    raw,
		raw:          doc,
		accessToken:  nestedString(doc, "tokens", "access_token"),
		refreshToken: nestedString(doc, "tokens", "refresh_token"),
		accountID:    nestedString(doc, "tokens", "account_id"),
	}
	if auth.accountID == "" {
		auth.accountID = stringValue(doc["account_id"])
	}
	if auth.accountID == "" {
		return nil, fmt.Errorf("auth_json tokens.account_id is required")
	}
	return auth, nil
}

func (a *codexAuth) needsRefresh(now time.Time, skew time.Duration) bool {
	if a.accessToken == "" {
		return true
	}
	exp, ok := jwtExpiry(a.accessToken)
	return ok && !now.Add(skew).Before(exp)
}

func (a *codexAuth) updatedRaw(tokenResp map[string]any, now time.Time) (string, error) {
	accessToken := stringValue(tokenResp["access_token"])
	if accessToken == "" {
		return "", fmt.Errorf("codex refresh response missing access_token")
	}
	clone := cloneMap(a.raw)
	tokens, _ := clone["tokens"].(map[string]any)
	if tokens == nil {
		tokens = make(map[string]any)
		clone["tokens"] = tokens
	}
	tokens["access_token"] = accessToken
	if refreshToken := stringValue(tokenResp["refresh_token"]); refreshToken != "" {
		tokens["refresh_token"] = refreshToken
	}
	if idToken := stringValue(tokenResp["id_token"]); idToken != "" {
		tokens["id_token"] = idToken
	}
	clone["last_refresh"] = now.UTC().Format(time.RFC3339)
	out, err := json.Marshal(clone)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func nestedString(doc map[string]any, path ...string) string {
	var current any = doc
	for _, part := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = m[part]
	}
	return stringValue(current)
}

func stringValue(v any) string {
	s, _ := v.(string)
	return s
}

func cloneMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		if m, ok := v.(map[string]any); ok {
			out[k] = cloneMap(m)
		} else {
			out[k] = v
		}
	}
	return out
}

func jwtExpiry(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp float64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == 0 {
		return time.Time{}, false
	}
	return time.Unix(int64(claims.Exp), 0), true
}

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
	scheme := u.Scheme
	if scheme == "" {
		scheme = "https"
	}
	return &tokenEndpoint{scheme: scheme, host: u.Host, matchHost: hostmatch.StripPort(u.Host), path: path}, nil
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
