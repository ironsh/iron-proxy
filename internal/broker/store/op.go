package store

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	onepassword "github.com/1password/onepassword-sdk-go"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform/secrets"
	"github.com/ironsh/iron-proxy/internal/version"
)

// opTokenEnv mirrors the constant used by the read-side resolver in
// internal/transform/secrets.
const opTokenEnv = "OP_SERVICE_ACCOUNT_TOKEN"

type opBuilder struct{}

type opConfig struct {
	Type      string `yaml:"type"`
	SecretRef string `yaml:"secret_ref"`
}

func (opBuilder) Build(raw yaml.Node, logger *slog.Logger) (Handle, error) {
	var cfg opConfig
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing 1password store config: %w", err)
	}
	if cfg.SecretRef == "" {
		return nil, fmt.Errorf("1password store requires \"secret_ref\" field")
	}
	ref, err := secrets.ParseOPRef(cfg.SecretRef)
	if err != nil {
		return nil, fmt.Errorf("1password store: %w", err)
	}
	return &opHandle{
		ref:    ref,
		secret: cfg.SecretRef,
		logger: logger,
	}, nil
}

// opSDKItemsAPI is the subset of the 1Password SDK Items API used by
// opHandle, narrowed for testability.
type opSDKItemsAPI interface {
	Get(ctx context.Context, vaultID, itemID string) (onepassword.Item, error)
	Put(ctx context.Context, item onepassword.Item) (onepassword.Item, error)
	List(ctx context.Context, vaultID string, filters ...onepassword.ItemListFilter) ([]onepassword.ItemOverview, error)
}

// opSDKVaultsAPI is the subset of the 1Password SDK Vaults API used by
// opHandle, narrowed for testability.
type opSDKVaultsAPI interface {
	List(ctx context.Context, params ...onepassword.VaultListParams) ([]onepassword.VaultOverview, error)
}

// opHandle persists the credential blob as the value of a single field on
// a 1Password item.
type opHandle struct {
	ref    secrets.OPRef
	secret string // original secret_ref string for log/Name output
	logger *slog.Logger

	mu              sync.Mutex
	items           opSDKItemsAPI
	vaults          opSDKVaultsAPI
	resolvedVaultID string
	resolvedItemID  string
}

func (h *opHandle) Name() string { return h.secret }

func (h *opHandle) Get(ctx context.Context) (CredentialBlob, error) {
	vaultID, itemID, err := h.resolve(ctx)
	if err != nil {
		return CredentialBlob{}, err
	}
	item, err := h.items.Get(ctx, vaultID, itemID)
	if err != nil {
		if isOPNotFound(err) {
			return CredentialBlob{}, ErrNotFound
		}
		return CredentialBlob{}, fmt.Errorf("1password Items.Get %q: %w", h.secret, err)
	}
	raw, err := selectOPField(item, h.ref)
	if err != nil {
		return CredentialBlob{}, fmt.Errorf("1password store %q: %w", h.secret, err)
	}
	if raw == "" {
		// An empty field reads as not-bootstrapped: the operator created
		// the item shell but hasn't dropped the blob in yet.
		return CredentialBlob{}, ErrNotFound
	}
	blob, err := unmarshalBlob([]byte(raw))
	if err != nil {
		return CredentialBlob{}, fmt.Errorf("1password store %q: %w", h.secret, err)
	}
	return blob, nil
}

func (h *opHandle) Put(ctx context.Context, blob CredentialBlob) error {
	vaultID, itemID, err := h.resolve(ctx)
	if err != nil {
		return err
	}
	// Re-fetch the item before mutating: the SDK Put requires the full
	// Item document, so we hydrate it from the server to avoid clobbering
	// any unrelated fields the operator added in 1Password's UI.
	item, err := h.items.Get(ctx, vaultID, itemID)
	if err != nil {
		return fmt.Errorf("1password Items.Get (pre-put) %q: %w", h.secret, err)
	}
	raw, err := marshalBlob(blob)
	if err != nil {
		return err
	}
	if !setOPField(&item, h.ref, string(raw)) {
		return fmt.Errorf("1password store %q: field %q not found on item; create it before bootstrap", h.secret, h.ref.Field)
	}
	if _, err := h.items.Put(ctx, item); err != nil {
		return fmt.Errorf("1password Items.Put %q: %w", h.secret, err)
	}
	return nil
}

// resolve returns the cached vault and item UUIDs, initializing the SDK
// client and looking up titles on first use. After the first successful
// call all subsequent Get/Put operations go straight to Items.Get with
// the cached IDs — title resolution costs at most one Vaults.List and
// one Items.List per handle lifetime.
func (h *opHandle) resolve(ctx context.Context) (string, string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.ensureClientLocked(ctx); err != nil {
		return "", "", err
	}
	if h.resolvedVaultID == "" {
		id, err := h.resolveVaultLocked(ctx)
		if err != nil {
			return "", "", err
		}
		h.resolvedVaultID = id
	}
	if h.resolvedItemID == "" {
		id, err := h.resolveItemLocked(ctx, h.resolvedVaultID)
		if err != nil {
			return "", "", err
		}
		h.resolvedItemID = id
	}
	return h.resolvedVaultID, h.resolvedItemID, nil
}

func (h *opHandle) ensureClientLocked(ctx context.Context) error {
	if h.items != nil && h.vaults != nil {
		return nil
	}
	token := os.Getenv(opTokenEnv)
	if token == "" {
		return fmt.Errorf("1password store %q: env var %q is not set or empty", h.secret, opTokenEnv)
	}
	client, err := onepassword.NewClient(ctx,
		onepassword.WithServiceAccountToken(token),
		onepassword.WithIntegrationInfo("iron-token-broker", version.Version),
	)
	if err != nil {
		return fmt.Errorf("1password store %q: creating client: %w", h.secret, err)
	}
	if h.items == nil {
		h.items = client.Items()
	}
	if h.vaults == nil {
		h.vaults = client.Vaults()
	}
	return nil
}

func (h *opHandle) resolveVaultLocked(ctx context.Context) (string, error) {
	if looksLikeUUID(h.ref.Vault) {
		return h.ref.Vault, nil
	}
	vaults, err := h.vaults.List(ctx)
	if err != nil {
		return "", fmt.Errorf("1password store %q: Vaults.List: %w", h.secret, err)
	}
	var match string
	for _, v := range vaults {
		if v.Title == h.ref.Vault {
			if match != "" {
				return "", fmt.Errorf("1password store %q: multiple vaults named %q; use the vault UUID instead", h.secret, h.ref.Vault)
			}
			match = v.ID
		}
	}
	if match == "" {
		return "", fmt.Errorf("1password store %q: vault %q not found (service account has access to %d vault(s))", h.secret, h.ref.Vault, len(vaults))
	}
	return match, nil
}

func (h *opHandle) resolveItemLocked(ctx context.Context, vaultID string) (string, error) {
	if looksLikeUUID(h.ref.Item) {
		return h.ref.Item, nil
	}
	items, err := h.items.List(ctx, vaultID)
	if err != nil {
		return "", fmt.Errorf("1password store %q: Items.List: %w", h.secret, err)
	}
	var match string
	for _, it := range items {
		if it.Title == h.ref.Item {
			if match != "" {
				return "", fmt.Errorf("1password store %q: multiple items named %q in vault; use the item UUID instead", h.secret, h.ref.Item)
			}
			match = it.ID
		}
	}
	if match == "" {
		return "", fmt.Errorf("1password store %q: item %q not found in vault", h.secret, h.ref.Item)
	}
	return match, nil
}

// selectOPField looks up the field identified by ref on item. Field is
// matched by ID or Title; when ref carries a section, the field's
// SectionID must point at a section whose ID or Title matches.
// Symmetric with secrets.SelectConnectField but specialized for the
// SDK's onepassword.Item type, which carries sections in a separate slice
// and references them from fields via SectionID.
func selectOPField(item onepassword.Item, ref secrets.OPRef) (string, error) {
	sectionID, err := resolveOPSectionID(item.Sections, ref.Section)
	if err != nil {
		return "", err
	}
	for _, f := range item.Fields {
		if f.ID != ref.Field && f.Title != ref.Field {
			continue
		}
		if ref.Section != "" {
			if f.SectionID == nil || *f.SectionID != sectionID {
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

// setOPField writes value into the field identified by ref. Returns true
// if a matching field was found and mutated. Does not create new fields:
// the operator must shape the item during bootstrap.
func setOPField(item *onepassword.Item, ref secrets.OPRef, value string) bool {
	sectionID, err := resolveOPSectionID(item.Sections, ref.Section)
	if err != nil {
		return false
	}
	for i := range item.Fields {
		f := &item.Fields[i]
		if f.ID != ref.Field && f.Title != ref.Field {
			continue
		}
		if ref.Section != "" {
			if f.SectionID == nil || *f.SectionID != sectionID {
				continue
			}
		}
		f.Value = value
		return true
	}
	return false
}

// resolveOPSectionID maps a section ref (ID or Title) to its concrete
// section ID for use against ItemField.SectionID. Returns "" with no
// error when ref is empty (no section constraint).
func resolveOPSectionID(sections []onepassword.ItemSection, ref string) (string, error) {
	if ref == "" {
		return "", nil
	}
	for _, s := range sections {
		if s.ID == ref || s.Title == ref {
			return s.ID, nil
		}
	}
	return "", fmt.Errorf("section %q not found on item", ref)
}

// isOPNotFound matches the SDK's item-not-found error message.
func isOPNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "itemnotfound") || strings.Contains(msg, "item not found")
}

// looksLikeUUID is a loose syntactic check for the 26-character base32 IDs
// used by 1Password (e.g. "abcd1234efgh5678ijkl9012mn") and standard
// 36-character UUIDs. Used to decide whether a secret_ref segment is
// already an ID we can pass straight to Items.Get or whether we need to
// look it up by title via Vaults.List / Items.List.
func looksLikeUUID(s string) bool {
	if len(s) == 0 {
		return false
	}
	// 1Password item/vault IDs are 26 lowercase alphanumerics.
	if len(s) == 26 && isAlnumLower(s) {
		return true
	}
	// RFC 4122 UUIDs are 36 characters with 4 dashes.
	if len(s) == 36 && strings.Count(s, "-") == 4 {
		return true
	}
	return false
}

func isAlnumLower(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}
