package secrets

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/1Password/connect-sdk-go/connect"
	"github.com/1Password/connect-sdk-go/onepassword"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/version"
)

const (
	defaultOPConnectHostEnv  = "OP_CONNECT_HOST"
	defaultOPConnectTokenEnv = "OP_CONNECT_TOKEN"
)

// opConnectClient is the subset of the Connect SDK client used by
// opConnectBuilder, narrowed for testability.
type opConnectClient interface {
	GetVault(ref string) (*onepassword.Vault, error)
	GetItem(itemRef, vaultRef string) (*onepassword.Item, error)
}

// opConnectBuilder reads secrets from a 1Password Connect server.
type opConnectBuilder struct {
	clientFor func(ctx context.Context, hostEnv, tokenEnv string) (opConnectClient, error)
	logger    *slog.Logger
}

type opConnectConfig struct {
	Type       string `yaml:"type"`
	SecretRef  string `yaml:"secret_ref"`
	HostEnv    string `yaml:"host_env,omitempty"`
	TokenEnv   string `yaml:"token_env,omitempty"`
	TTL        string `yaml:"ttl,omitempty"`
	FailureTTL string `yaml:"failure_ttl,omitempty"`
}

func newOPConnectBuilder(logger *slog.Logger) *opConnectBuilder {
	cache := &opConnectClientCache{
		clients: make(map[string]opConnectClient),
		getenv:  os.Getenv,
		newClient: func(host, token string) opConnectClient {
			return opConnectSDKClient{c: connect.NewClientWithUserAgent(host, token, "iron-proxy/"+version.Version)}
		},
	}
	return &opConnectBuilder{clientFor: cache.get, logger: logger}
}

func (r *opConnectBuilder) Build(raw yaml.Node) (secretSource, error) {
	var cfg opConnectConfig
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing 1password_connect source config: %w", err)
	}
	if cfg.SecretRef == "" {
		return nil, fmt.Errorf("1password_connect source requires \"secret_ref\" field")
	}
	ref, err := ParseOPRef(cfg.SecretRef)
	if err != nil {
		return nil, fmt.Errorf("1password_connect: %w", err)
	}
	if cfg.HostEnv == "" {
		cfg.HostEnv = defaultOPConnectHostEnv
	}
	if cfg.TokenEnv == "" {
		cfg.TokenEnv = defaultOPConnectTokenEnv
	}
	return buildLazySource(cfg.SecretRef, cfg.TTL, cfg.FailureTTL, r.logger, func(ctx context.Context) (string, error) {
		return r.fetchSecret(ctx, cfg, ref)
	})
}

func (r *opConnectBuilder) fetchSecret(ctx context.Context, cfg opConnectConfig, ref OPRef) (string, error) {
	client, err := r.clientFor(ctx, cfg.HostEnv, cfg.TokenEnv)
	if err != nil {
		return "", fmt.Errorf("creating 1password_connect client: %w", err)
	}
	vault, err := client.GetVault(ref.Vault)
	if err != nil {
		return "", fmt.Errorf("resolving 1password_connect secret %q: looking up vault %q: %w", cfg.SecretRef, ref.Vault, err)
	}
	item, err := client.GetItem(ref.Item, vault.ID)
	if err != nil {
		return "", fmt.Errorf("resolving 1password_connect secret %q: looking up item %q: %w", cfg.SecretRef, ref.Item, err)
	}
	val, err := SelectConnectField(item, ref)
	if err != nil {
		return "", fmt.Errorf("resolving 1password_connect secret %q: %w", cfg.SecretRef, err)
	}
	if val == "" {
		return "", fmt.Errorf("1password_connect secret %q resolved to empty value", cfg.SecretRef)
	}
	return val, nil
}

// OPRef is a parsed op://vault/item/[section/]field reference. Exported so
// other packages (notably internal/broker/store) can share the parser and
// the Connect-side field selector without re-implementing them.
type OPRef struct {
	Vault   string
	Item    string
	Section string // optional
	Field   string
}

// ParseOPRef parses an "op://vault/item/[section/]field" reference.
// vault, item, section, and field may be UUIDs or human titles. Empty
// segments and lengths outside [3, 4] are rejected.
func ParseOPRef(ref string) (OPRef, error) {
	rest, ok := strings.CutPrefix(ref, "op://")
	if !ok {
		return OPRef{}, fmt.Errorf("secret_ref %q must start with \"op://\"", ref)
	}
	parts := strings.Split(rest, "/")
	if len(parts) < 3 || len(parts) > 4 {
		return OPRef{}, fmt.Errorf("secret_ref %q must have 3 or 4 path segments (op://vault/item/[section/]field)", ref)
	}
	for _, p := range parts {
		if p == "" {
			return OPRef{}, fmt.Errorf("secret_ref %q has an empty path segment", ref)
		}
	}
	out := OPRef{Vault: parts[0], Item: parts[1]}
	if len(parts) == 3 {
		out.Field = parts[2]
	} else {
		out.Section = parts[2]
		out.Field = parts[3]
	}
	return out, nil
}

// SelectConnectField returns the value of the field identified by ref on
// a 1Password Connect item. Field is matched by ID or Label. When ref has
// a section, the field's Section must also match by ID or Label.
func SelectConnectField(item *onepassword.Item, ref OPRef) (string, error) {
	for _, f := range item.Fields {
		if f == nil {
			continue
		}
		if f.ID != ref.Field && f.Label != ref.Field {
			continue
		}
		if ref.Section != "" {
			if f.Section == nil {
				continue
			}
			if f.Section.ID != ref.Section && f.Section.Label != ref.Section {
				continue
			}
		}
		return f.Value, nil
	}
	if ref.Section != "" {
		return "", fmt.Errorf("field %q in section %q not found on item", ref.Field, ref.Section)
	}
	return "", fmt.Errorf("field %q not found on item", ref.Field)
}

// opConnectClientCache caches one Connect client per (hostEnv, tokenEnv)
// pair. Reusing a client pools the underlying HTTP transport.
type opConnectClientCache struct {
	mu        sync.Mutex
	clients   map[string]opConnectClient
	getenv    func(string) string
	newClient func(host, token string) opConnectClient
}

func (c *opConnectClientCache) get(_ context.Context, hostEnv, tokenEnv string) (opConnectClient, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := hostEnv + "|" + tokenEnv
	if client, ok := c.clients[key]; ok {
		return client, nil
	}
	host := c.getenv(hostEnv)
	if host == "" {
		return nil, fmt.Errorf("env var %q is not set or empty", hostEnv)
	}
	token := c.getenv(tokenEnv)
	if token == "" {
		return nil, fmt.Errorf("env var %q is not set or empty", tokenEnv)
	}
	client := c.newClient(host, token)
	c.clients[key] = client
	return client, nil
}

// opConnectSDKClient adapts a connect.Client to the opConnectClient interface.
type opConnectSDKClient struct{ c connect.Client }

func (a opConnectSDKClient) GetVault(ref string) (*onepassword.Vault, error) {
	return a.c.GetVault(ref)
}

func (a opConnectSDKClient) GetItem(itemRef, vaultRef string) (*onepassword.Item, error) {
	return a.c.GetItem(itemRef, vaultRef)
}
