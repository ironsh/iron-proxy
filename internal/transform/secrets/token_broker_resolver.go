package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/version"
)

const (
	defaultBrokerURLEnv      = "IRON_BROKER_URL"
	defaultBrokerTokenEnv    = "IRON_BROKER_TOKEN"
	defaultBrokerTTL         = time.Minute
	brokerHTTPClientTimeout  = 30 * time.Second
	brokerErrorBodyMaxBytes  = 512
)

// brokerHTTPClient is the subset of *http.Client used by the broker resolver,
// narrowed for testability.
type brokerHTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// tokenBrokerBuilder reads OAuth access tokens from a running iron-token-broker.
type tokenBrokerBuilder struct {
	clientFor func() (brokerHTTPClient, string, string, error)
	logger    *slog.Logger
	now       func() time.Time
}

type tokenBrokerConfig struct {
	Type         string `yaml:"type"`
	CredentialID string `yaml:"credential_id"`
	TTL          string `yaml:"ttl,omitempty"`
	FailureTTL   string `yaml:"failure_ttl,omitempty"`
}

func newTokenBrokerBuilder(logger *slog.Logger) *tokenBrokerBuilder {
	cache := &brokerClientCache{
		getenv: os.Getenv,
		newClient: func() brokerHTTPClient {
			return &http.Client{Timeout: brokerHTTPClientTimeout}
		},
	}
	return &tokenBrokerBuilder{clientFor: cache.get, logger: logger, now: time.Now}
}

func (r *tokenBrokerBuilder) Build(raw yaml.Node) (secretSource, error) {
	var cfg tokenBrokerConfig
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing token_broker source config: %w", err)
	}
	if cfg.CredentialID == "" {
		return nil, fmt.Errorf("token_broker source requires \"credential_id\" field")
	}
	ttl := defaultBrokerTTL
	if cfg.TTL != "" {
		parsed, err := time.ParseDuration(cfg.TTL)
		if err != nil {
			return nil, fmt.Errorf("parsing ttl %q: %w", cfg.TTL, err)
		}
		if parsed <= 0 {
			return nil, fmt.Errorf("token_broker source requires ttl > 0 (got %q); cache-forever does not make sense for broker-issued tokens", cfg.TTL)
		}
		ttl = parsed
	}
	name := "token_broker:" + cfg.CredentialID
	return buildLazySource(name, ttl.String(), cfg.FailureTTL, r.logger, func(ctx context.Context) (string, error) {
		return r.fetchToken(ctx, cfg.CredentialID, ttl)
	})
}

func (r *tokenBrokerBuilder) fetchToken(ctx context.Context, credentialID string, ttl time.Duration) (string, error) {
	client, baseURL, bearer, err := r.clientFor()
	if err != nil {
		return "", err
	}
	endpoint, err := brokerAccessTokenURL(baseURL, credentialID)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("building broker request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "iron-proxy/"+version.Version)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("calling broker %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, brokerErrorBodyMaxBytes))
		return "", fmt.Errorf("broker %s returned %d: %s", endpoint, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var body struct {
		AccessToken string    `json:"access_token"`
		ExpiresAt   time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("decoding broker response: %w", err)
	}
	if body.AccessToken == "" {
		return "", fmt.Errorf("broker returned empty access_token for credential %q", credentialID)
	}
	if body.ExpiresAt.IsZero() {
		return "", fmt.Errorf("broker returned no expires_at for credential %q", credentialID)
	}
	remaining := body.ExpiresAt.Sub(r.now())
	if remaining <= ttl {
		return "", fmt.Errorf("broker token for credential %q has remaining lifetime %s, which is not greater than cache ttl %s; lower the configured ttl or check broker token-endpoint settings", credentialID, remaining, ttl)
	}
	return body.AccessToken, nil
}

// brokerAccessTokenURL joins the broker base URL and the credential ID to
// form the access-token endpoint. The credential ID is escaped as a single
// opaque path segment, so IDs containing slashes or other URL-unsafe
// characters reach the broker without being mistaken for path separators.
func brokerAccessTokenURL(baseURL, credentialID string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parsing broker base url %q: %w", baseURL, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("broker base url %q must include scheme and host", baseURL)
	}
	basePath := strings.TrimRight(u.Path, "/")
	baseRaw := strings.TrimRight(u.EscapedPath(), "/")
	escaped := url.PathEscape(credentialID)
	u.Path = basePath + "/credentials/" + credentialID + "/access_token"
	u.RawPath = baseRaw + "/credentials/" + escaped + "/access_token"
	return u.String(), nil
}

// brokerClientCache reads the broker URL and bearer token from env once on
// first successful call and caches them with a shared *http.Client. Reading
// at fetch time (not Build) matches the 1password_connect pattern:
// misconfiguration surfaces on the first request, not at startup. Errors are
// not cached, so an env var that gets set after a failed call recovers on
// the next attempt.
type brokerClientCache struct {
	mu        sync.Mutex
	getenv    func(string) string
	newClient func() brokerHTTPClient

	client  brokerHTTPClient
	baseURL string
	bearer  string
}

func (c *brokerClientCache) get() (brokerHTTPClient, string, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != nil {
		return c.client, c.baseURL, c.bearer, nil
	}
	baseURL := c.getenv(defaultBrokerURLEnv)
	if baseURL == "" {
		return nil, "", "", fmt.Errorf("env var %q is not set or empty", defaultBrokerURLEnv)
	}
	bearer := c.getenv(defaultBrokerTokenEnv)
	if bearer == "" {
		return nil, "", "", fmt.Errorf("env var %q is not set or empty", defaultBrokerTokenEnv)
	}
	c.client = c.newClient()
	c.baseURL = baseURL
	c.bearer = bearer
	return c.client, c.baseURL, c.bearer, nil
}
