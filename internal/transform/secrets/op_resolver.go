package secrets

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"

	onepassword "github.com/1password/onepassword-sdk-go"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/version"
)

// defaultOPTokenEnv is the conventional environment variable for 1Password
// service account tokens, matching the SDK's own examples.
const defaultOPTokenEnv = "OP_SERVICE_ACCOUNT_TOKEN"

// opClient is the subset of the 1Password SDK used by opBuilder, narrowed for
// testability. We don't use the SDK's Secrets().Resolve() because its
// reference parser rejects anything outside [A-Za-z0-9_.-]: vault/item names
// containing spaces or "&" can't be referenced at all, and percent-encoding
// is also rejected. Looking up by title via the typed Vaults/Items APIs
// sidesteps that limitation.
type opClient interface {
	ListVaults(ctx context.Context) ([]onepassword.VaultOverview, error)
	ListItems(ctx context.Context, vaultID string) ([]onepassword.ItemOverview, error)
	GetItem(ctx context.Context, vaultID, itemID string) (onepassword.Item, error)
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
	ref, err := parseOPRef(cfg.SecretRef)
	if err != nil {
		return nil, fmt.Errorf("1password: %w", err)
	}
	if cfg.TokenEnv == "" {
		cfg.TokenEnv = defaultOPTokenEnv
	}
	return buildLazySource(cfg.SecretRef, cfg.TTL, cfg.FailureTTL, r.logger, func(ctx context.Context) (string, error) {
		return r.fetchSecret(ctx, cfg, ref)
	})
}

func (r *opBuilder) fetchSecret(ctx context.Context, cfg opConfig, ref opRef) (string, error) {
	client, err := r.clientFor(ctx, cfg.TokenEnv)
	if err != nil {
		return "", fmt.Errorf("creating 1password client: %w", err)
	}

	vaults, err := client.ListVaults(ctx)
	if err != nil {
		return "", fmt.Errorf("resolving 1password secret %q: listing vaults: %w", cfg.SecretRef, err)
	}
	vaultID, ok := findVaultID(vaults, ref.vault)
	if !ok {
		return "", fmt.Errorf("resolving 1password secret %q: vault %q not found", cfg.SecretRef, ref.vault)
	}

	items, err := client.ListItems(ctx, vaultID)
	if err != nil {
		return "", fmt.Errorf("resolving 1password secret %q: listing items in vault %q: %w", cfg.SecretRef, ref.vault, err)
	}
	itemID, ok := findItemID(items, ref.item)
	if !ok {
		return "", fmt.Errorf("resolving 1password secret %q: item %q not found in vault %q", cfg.SecretRef, ref.item, ref.vault)
	}

	item, err := client.GetItem(ctx, vaultID, itemID)
	if err != nil {
		return "", fmt.Errorf("resolving 1password secret %q: getting item %q: %w", cfg.SecretRef, ref.item, err)
	}
	val, err := selectSDKField(item, ref)
	if err != nil {
		return "", fmt.Errorf("resolving 1password secret %q: %w", cfg.SecretRef, err)
	}
	if val == "" {
		return "", fmt.Errorf("1password secret %q resolved to empty value", cfg.SecretRef)
	}
	return val, nil
}

// findVaultID returns the ID of the vault whose ID or title matches ref. ID
// matches take precedence so users can disambiguate vaults that share a title.
func findVaultID(vaults []onepassword.VaultOverview, ref string) (string, bool) {
	for _, v := range vaults {
		if v.ID == ref {
			return v.ID, true
		}
	}
	for _, v := range vaults {
		if v.Title == ref {
			return v.ID, true
		}
	}
	return "", false
}

// findItemID returns the ID of the item whose ID or title matches ref. ID
// matches take precedence so users can disambiguate items that share a title.
func findItemID(items []onepassword.ItemOverview, ref string) (string, bool) {
	for _, i := range items {
		if i.ID == ref {
			return i.ID, true
		}
	}
	for _, i := range items {
		if i.Title == ref {
			return i.ID, true
		}
	}
	return "", false
}

// selectSDKField returns the value of the field identified by ref on item.
// Field is matched by ID or Title. When a section is specified, the field's
// SectionID must point at a section whose ID or Title matches.
func selectSDKField(item onepassword.Item, ref opRef) (string, error) {
	var wantSectionID string
	if ref.section != "" {
		found := false
		for _, s := range item.Sections {
			if s.ID == ref.section || s.Title == ref.section {
				wantSectionID = s.ID
				found = true
				break
			}
		}
		if !found {
			return "", fmt.Errorf("section %q not found on item", ref.section)
		}
	}
	for _, f := range item.Fields {
		if f.ID != ref.field && f.Title != ref.field {
			continue
		}
		if ref.section != "" {
			if f.SectionID == nil || *f.SectionID != wantSectionID {
				continue
			}
		}
		return f.Value, nil
	}
	if ref.section != "" {
		return "", fmt.Errorf("field %q in section %q not found on item", ref.field, ref.section)
	}
	return "", fmt.Errorf("field %q not found on item", ref.field)
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

func (a opSDKClient) ListVaults(ctx context.Context) ([]onepassword.VaultOverview, error) {
	return a.c.Vaults().List(ctx)
}

func (a opSDKClient) ListItems(ctx context.Context, vaultID string) ([]onepassword.ItemOverview, error) {
	return a.c.Items().List(ctx, vaultID)
}

func (a opSDKClient) GetItem(ctx context.Context, vaultID, itemID string) (onepassword.Item, error) {
	return a.c.Items().Get(ctx, vaultID, itemID)
}
