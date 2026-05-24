package codexlogin

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	connectsdk "github.com/1Password/connect-sdk-go/connect"
	connectop "github.com/1Password/connect-sdk-go/onepassword"
	opsdk "github.com/1password/onepassword-sdk-go"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/version"
)

const (
	defaultOPTokenEnv        = "OP_SERVICE_ACCOUNT_TOKEN"
	defaultOPConnectHostEnv  = "OP_CONNECT_HOST"
	defaultOPConnectTokenEnv = "OP_CONNECT_TOKEN"
)

type writerTypeHint struct {
	Type string `yaml:"type"`
}

type opRef struct {
	vault   string
	item    string
	section string
	field   string
}

func buildAuthJSONWriter(raw yaml.Node, _ *slog.Logger) (authJSONWriter, error) {
	var hint writerTypeHint
	if err := raw.Decode(&hint); err != nil {
		return nil, fmt.Errorf("parsing writeback source type: %w", err)
	}
	switch hint.Type {
	case "1password":
		return newOPWriter(raw)
	case "1password_connect":
		return newOPConnectWriter(raw)
	case "":
		return nil, fmt.Errorf("writeback source requires \"type\" field")
	default:
		return nil, fmt.Errorf("unsupported writeback source type %q", hint.Type)
	}
}

func parseOPRef(ref string) (opRef, error) {
	rest, ok := strings.CutPrefix(ref, "op://")
	if !ok {
		return opRef{}, fmt.Errorf("secret_ref %q must start with \"op://\"", ref)
	}
	parts := strings.Split(rest, "/")
	if len(parts) < 3 || len(parts) > 4 {
		return opRef{}, fmt.Errorf("secret_ref %q must have 3 or 4 path segments (op://vault/item/[section/]field)", ref)
	}
	for _, p := range parts {
		if p == "" {
			return opRef{}, fmt.Errorf("secret_ref %q has an empty path segment", ref)
		}
	}
	out := opRef{vault: parts[0], item: parts[1]}
	if len(parts) == 3 {
		out.field = parts[2]
	} else {
		out.section = parts[2]
		out.field = parts[3]
	}
	return out, nil
}

func refreshTokenFromRaw(raw string) (string, error) {
	auth, err := parseAuthJSON(raw)
	if err != nil {
		return "", err
	}
	return auth.refreshToken, nil
}

type opWriterConfig struct {
	Type      string `yaml:"type"`
	SecretRef string `yaml:"secret_ref"`
	TokenEnv  string `yaml:"token_env,omitempty"`
}

type opWriter struct {
	ref      opRef
	tokenEnv string
	mu       sync.Mutex
	client   *opsdk.Client
}

func newOPWriter(raw yaml.Node) (*opWriter, error) {
	var cfg opWriterConfig
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing 1password writeback config: %w", err)
	}
	if cfg.SecretRef == "" {
		return nil, fmt.Errorf("1password writeback requires \"secret_ref\" field")
	}
	ref, err := parseOPRef(cfg.SecretRef)
	if err != nil {
		return nil, fmt.Errorf("1password writeback: %w", err)
	}
	if cfg.TokenEnv == "" {
		cfg.TokenEnv = defaultOPTokenEnv
	}
	return &opWriter{ref: ref, tokenEnv: cfg.TokenEnv}, nil
}

func (w *opWriter) CompareAndSwap(ctx context.Context, oldRefreshToken, newValue string) (string, bool, error) {
	client, err := w.clientFor(ctx)
	if err != nil {
		return "", false, err
	}
	vaultID, err := resolveOPVaultID(ctx, client, w.ref.vault)
	if err != nil {
		return "", false, err
	}
	itemID, err := resolveOPItemID(ctx, client, vaultID, w.ref.item)
	if err != nil {
		return "", false, err
	}
	item, err := client.Items().Get(ctx, vaultID, itemID)
	if err != nil {
		return "", false, fmt.Errorf("loading 1password item: %w", err)
	}
	field, err := selectOPField(&item, w.ref)
	if err != nil {
		return "", false, err
	}
	current := field.Value
	currentRefresh, err := refreshTokenFromRaw(current)
	if err != nil {
		return current, false, err
	}
	if currentRefresh != oldRefreshToken {
		return current, false, nil
	}
	field.Value = newValue
	if _, err := client.Items().Put(ctx, item); err != nil {
		return "", false, fmt.Errorf("updating 1password item: %w", err)
	}
	return newValue, true, nil
}

func (w *opWriter) Current(ctx context.Context) (string, error) {
	client, err := w.clientFor(ctx)
	if err != nil {
		return "", err
	}
	vaultID, err := resolveOPVaultID(ctx, client, w.ref.vault)
	if err != nil {
		return "", err
	}
	itemID, err := resolveOPItemID(ctx, client, vaultID, w.ref.item)
	if err != nil {
		return "", err
	}
	item, err := client.Items().Get(ctx, vaultID, itemID)
	if err != nil {
		return "", fmt.Errorf("loading 1password item: %w", err)
	}
	field, err := selectOPField(&item, w.ref)
	if err != nil {
		return "", err
	}
	return field.Value, nil
}

func (w *opWriter) clientFor(ctx context.Context) (*opsdk.Client, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.client != nil {
		return w.client, nil
	}
	token := os.Getenv(w.tokenEnv)
	if token == "" {
		return nil, fmt.Errorf("env var %q is not set or empty", w.tokenEnv)
	}
	client, err := opsdk.NewClient(ctx,
		opsdk.WithServiceAccountToken(token),
		opsdk.WithIntegrationInfo("iron-proxy", version.Version),
	)
	if err != nil {
		return nil, err
	}
	w.client = client
	return client, nil
}

func resolveOPVaultID(ctx context.Context, client *opsdk.Client, ref string) (string, error) {
	vaults, err := client.Vaults().List(ctx)
	if err != nil {
		return "", fmt.Errorf("listing 1password vaults: %w", err)
	}
	for _, vault := range vaults {
		if vault.ID == ref || vault.Title == ref {
			return vault.ID, nil
		}
	}
	return "", fmt.Errorf("1password vault %q not found", ref)
}

func resolveOPItemID(ctx context.Context, client *opsdk.Client, vaultID, ref string) (string, error) {
	items, err := client.Items().List(ctx, vaultID)
	if err != nil {
		return "", fmt.Errorf("listing 1password items: %w", err)
	}
	for _, item := range items {
		if item.ID == ref || item.Title == ref {
			return item.ID, nil
		}
	}
	return "", fmt.Errorf("1password item %q not found", ref)
}

func selectOPField(item *opsdk.Item, ref opRef) (*opsdk.ItemField, error) {
	sectionID := ""
	if ref.section != "" {
		for _, section := range item.Sections {
			if section.ID == ref.section || section.Title == ref.section {
				sectionID = section.ID
				break
			}
		}
		if sectionID == "" {
			return nil, fmt.Errorf("section %q not found on item", ref.section)
		}
	}
	for i := range item.Fields {
		field := &item.Fields[i]
		if field.ID != ref.field && field.Title != ref.field {
			continue
		}
		if ref.section != "" {
			if field.SectionID == nil || *field.SectionID != sectionID {
				continue
			}
		}
		return field, nil
	}
	if ref.section != "" {
		return nil, fmt.Errorf("field %q in section %q not found on item", ref.field, ref.section)
	}
	return nil, fmt.Errorf("field %q not found on item", ref.field)
}

type opConnectWriterConfig struct {
	Type      string `yaml:"type"`
	SecretRef string `yaml:"secret_ref"`
	HostEnv   string `yaml:"host_env,omitempty"`
	TokenEnv  string `yaml:"token_env,omitempty"`
}

type opConnectClient interface {
	GetVault(ref string) (*connectop.Vault, error)
	GetItem(itemRef, vaultRef string) (*connectop.Item, error)
	UpdateItem(item *connectop.Item, vaultRef string) (*connectop.Item, error)
}

type opConnectWriter struct {
	ref      opRef
	hostEnv  string
	tokenEnv string
	mu       sync.Mutex
	client   opConnectClient
}

func newOPConnectWriter(raw yaml.Node) (*opConnectWriter, error) {
	var cfg opConnectWriterConfig
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing 1password_connect writeback config: %w", err)
	}
	if cfg.SecretRef == "" {
		return nil, fmt.Errorf("1password_connect writeback requires \"secret_ref\" field")
	}
	ref, err := parseOPRef(cfg.SecretRef)
	if err != nil {
		return nil, fmt.Errorf("1password_connect writeback: %w", err)
	}
	if cfg.HostEnv == "" {
		cfg.HostEnv = defaultOPConnectHostEnv
	}
	if cfg.TokenEnv == "" {
		cfg.TokenEnv = defaultOPConnectTokenEnv
	}
	return &opConnectWriter{ref: ref, hostEnv: cfg.HostEnv, tokenEnv: cfg.TokenEnv}, nil
}

func (w *opConnectWriter) CompareAndSwap(ctx context.Context, oldRefreshToken, newValue string) (string, bool, error) {
	client, err := w.clientFor(ctx)
	if err != nil {
		return "", false, err
	}
	vault, err := client.GetVault(w.ref.vault)
	if err != nil {
		return "", false, fmt.Errorf("loading 1password_connect vault %q: %w", w.ref.vault, err)
	}
	item, err := client.GetItem(w.ref.item, vault.ID)
	if err != nil {
		return "", false, fmt.Errorf("loading 1password_connect item %q: %w", w.ref.item, err)
	}
	item.Vault.ID = vault.ID
	field, err := selectOPConnectField(item, w.ref)
	if err != nil {
		return "", false, err
	}
	current := field.Value
	currentRefresh, err := refreshTokenFromRaw(current)
	if err != nil {
		return current, false, err
	}
	if currentRefresh != oldRefreshToken {
		return current, false, nil
	}
	field.Value = newValue
	if _, err := client.UpdateItem(item, vault.ID); err != nil {
		return "", false, fmt.Errorf("updating 1password_connect item: %w", err)
	}
	return newValue, true, nil
}

func (w *opConnectWriter) Current(ctx context.Context) (string, error) {
	client, err := w.clientFor(ctx)
	if err != nil {
		return "", err
	}
	vault, err := client.GetVault(w.ref.vault)
	if err != nil {
		return "", fmt.Errorf("loading 1password_connect vault %q: %w", w.ref.vault, err)
	}
	item, err := client.GetItem(w.ref.item, vault.ID)
	if err != nil {
		return "", fmt.Errorf("loading 1password_connect item %q: %w", w.ref.item, err)
	}
	field, err := selectOPConnectField(item, w.ref)
	if err != nil {
		return "", err
	}
	return field.Value, nil
}

func (w *opConnectWriter) clientFor(context.Context) (opConnectClient, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.client != nil {
		return w.client, nil
	}
	host := os.Getenv(w.hostEnv)
	if host == "" {
		return nil, fmt.Errorf("env var %q is not set or empty", w.hostEnv)
	}
	token := os.Getenv(w.tokenEnv)
	if token == "" {
		return nil, fmt.Errorf("env var %q is not set or empty", w.tokenEnv)
	}
	w.client = connectsdk.NewClientWithUserAgent(host, token, "iron-proxy/"+version.Version)
	return w.client, nil
}

func selectOPConnectField(item *connectop.Item, ref opRef) (*connectop.ItemField, error) {
	for _, field := range item.Fields {
		if field == nil {
			continue
		}
		if field.ID != ref.field && field.Label != ref.field {
			continue
		}
		if ref.section != "" {
			if field.Section == nil {
				continue
			}
			if field.Section.ID != ref.section && field.Section.Label != ref.section {
				continue
			}
		}
		return field, nil
	}
	if ref.section != "" {
		return nil, fmt.Errorf("field %q in section %q not found on item", ref.field, ref.section)
	}
	return nil, fmt.Errorf("field %q not found on item", ref.field)
}
