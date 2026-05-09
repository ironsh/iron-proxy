package secrets

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	onepassword "github.com/1password/onepassword-sdk-go"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/version"
)

// defaultOPTokenEnv is the conventional environment variable for 1Password
// service account tokens, matching the SDK's own examples.
const defaultOPTokenEnv = "OP_SERVICE_ACCOUNT_TOKEN"

// opClient is the subset of the 1Password SDK used by opBuilder, narrowed for testability.
type opClient interface {
	Resolve(ctx context.Context, ref string) (string, error)
}

// opBuilder reads secrets from 1Password using a service account token.
type opBuilder struct {
	clientFor func(ctx context.Context, tokenEnv string) (opClient, error)
	logger    *slog.Logger
}

type opConfig struct {
	Type       string `yaml:"type"`
	SecretRef  string `yaml:"secret_ref"`
	TokenEnv   string `yaml:"token_env,omitempty"`
	TTL        string `yaml:"ttl,omitempty"`
	FailureTTL string `yaml:"failure_ttl,omitempty"`
}

func newOPBuilder(logger *slog.Logger) *opBuilder {
	cache := &opClientCache{
		clients: make(map[string]opClient),
		getenv:  os.Getenv,
		newClient: func(ctx context.Context, token string) (opClient, error) {
			c, err := onepassword.NewClient(ctx,
				onepassword.WithServiceAccountToken(token),
				onepassword.WithIntegrationInfo("iron-proxy", version.Version),
			)
			if err != nil {
				return nil, err
			}
			return opSDKClient{c: c}, nil
		},
	}
	return &opBuilder{clientFor: cache.get, logger: logger}
}

func (r *opBuilder) Build(raw yaml.Node) (secretSource, error) {
	var cfg opConfig
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing 1password source config: %w", err)
	}
	if cfg.SecretRef == "" {
		return nil, fmt.Errorf("1password source requires \"secret_ref\" field")
	}
	if !strings.HasPrefix(cfg.SecretRef, "op://") {
		return nil, fmt.Errorf("1password secret_ref %q must start with \"op://\"", cfg.SecretRef)
	}
	if cfg.TokenEnv == "" {
		cfg.TokenEnv = defaultOPTokenEnv
	}
	return buildLazySource(cfg.SecretRef, cfg.TTL, cfg.FailureTTL, r.logger, func(ctx context.Context) (string, error) {
		return r.fetchSecret(ctx, cfg)
	})
}

func (r *opBuilder) fetchSecret(ctx context.Context, cfg opConfig) (string, error) {
	client, err := r.clientFor(ctx, cfg.TokenEnv)
	if err != nil {
		return "", fmt.Errorf("creating 1password client: %w", err)
	}
	val, err := client.Resolve(ctx, cfg.SecretRef)
	if err != nil {
		return "", fmt.Errorf("resolving 1password secret %q: %w", cfg.SecretRef, err)
	}
	if val == "" {
		return "", fmt.Errorf("1password secret %q resolved to empty value", cfg.SecretRef)
	}
	return val, nil
}

// opClientCache caches one SDK client per token-env-name. The 1P SDK loads a
// Wasm module on NewClient, so reusing the client across multiple secret
// entries is significantly cheaper than creating one per entry.
type opClientCache struct {
	mu        sync.Mutex
	clients   map[string]opClient
	getenv    func(string) string
	newClient func(ctx context.Context, token string) (opClient, error)
}

func (c *opClientCache) get(ctx context.Context, tokenEnv string) (opClient, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if client, ok := c.clients[tokenEnv]; ok {
		return client, nil
	}
	token := c.getenv(tokenEnv)
	if token == "" {
		return nil, fmt.Errorf("env var %q is not set or empty", tokenEnv)
	}
	client, err := c.newClient(ctx, token)
	if err != nil {
		return nil, err
	}
	c.clients[tokenEnv] = client
	return client, nil
}

// opSDKClient adapts the 1Password SDK *Client to the opClient interface.
type opSDKClient struct{ c *onepassword.Client }

func (a opSDKClient) Resolve(ctx context.Context, ref string) (string, error) {
	return a.c.Secrets().Resolve(ctx, ref)
}
