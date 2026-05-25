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

// defaultOPTokenEnv mirrors the constant used by the read-side resolver in
// internal/transform/secrets so operators don't have to maintain two
// environment variables when they use 1Password for both the broker store
// and other secrets.
const defaultOPTokenEnv = "OP_SERVICE_ACCOUNT_TOKEN"

type opBuilder struct{}

type opConfig struct {
	Type      string `yaml:"type"`
	SecretRef string `yaml:"secret_ref"`
	TokenEnv  string `yaml:"token_env,omitempty"`
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
	// The SDK's Items.Get takes raw vault and item IDs — there is no
	// name-lookup helper that doesn't require a separate List round trip
	// per resolution. Require UUIDs at config time so the broker doesn't
	// silently hit the list endpoint on every refresh.
	if !looksLikeUUID(ref.Vault) {
		return nil, fmt.Errorf("1password store secret_ref %q: vault segment must be a UUID (use the SDK \"Copy Vault UUID\" action)", cfg.SecretRef)
	}
	if !looksLikeUUID(ref.Item) {
		return nil, fmt.Errorf("1password store secret_ref %q: item segment must be a UUID (use the SDK \"Copy Item UUID\" action)", cfg.SecretRef)
	}
	if cfg.TokenEnv == "" {
		cfg.TokenEnv = defaultOPTokenEnv
	}
	return &opHandle{
		ref:      ref,
		secret:   cfg.SecretRef,
		tokenEnv: cfg.TokenEnv,
		logger:   logger,
	}, nil
}

// opSDKItemsAPI is the subset of the 1Password SDK Items API used by
// opHandle, narrowed for testability.
type opSDKItemsAPI interface {
	Get(ctx context.Context, vaultID, itemID string) (onepassword.Item, error)
	Put(ctx context.Context, item onepassword.Item) (onepassword.Item, error)
}

// opHandle persists the credential blob as the value of a single field on
// a 1Password item.
type opHandle struct {
	ref      secrets.OPRef
	secret   string // original secret_ref string for log/Name output
	tokenEnv string
	logger   *slog.Logger

	mu    sync.Mutex
	items opSDKItemsAPI
}

func (h *opHandle) Name() string { return h.secret }

func (h *opHandle) Get(ctx context.Context) (CredentialBlob, error) {
	items, err := h.getItems(ctx)
	if err != nil {
		return CredentialBlob{}, err
	}
	item, err := items.Get(ctx, h.ref.Vault, h.ref.Item)
	if err != nil {
		if isOPNotFound(err) {
			return CredentialBlob{}, ErrNotFound
		}
		return CredentialBlob{}, fmt.Errorf("1password Items.Get %q: %w", h.secret, err)
	}
	raw, err := selectOPField(item.Fields, h.ref)
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
	items, err := h.getItems(ctx)
	if err != nil {
		return err
	}
	// Re-fetch the item before mutating: the SDK Put requires the full
	// Item document, so we hydrate it from the server to avoid clobbering
	// any unrelated fields the operator added in 1Password's UI.
	item, err := items.Get(ctx, h.ref.Vault, h.ref.Item)
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
	if _, err := items.Put(ctx, item); err != nil {
		return fmt.Errorf("1password Items.Put %q: %w", h.secret, err)
	}
	return nil
}

func (h *opHandle) getItems(ctx context.Context) (opSDKItemsAPI, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.items != nil {
		return h.items, nil
	}
	token := os.Getenv(h.tokenEnv)
	if token == "" {
		return nil, fmt.Errorf("1password store %q: env var %q is not set or empty", h.secret, h.tokenEnv)
	}
	client, err := onepassword.NewClient(ctx,
		onepassword.WithServiceAccountToken(token),
		onepassword.WithIntegrationInfo("iron-token-broker", version.Version),
	)
	if err != nil {
		return nil, fmt.Errorf("1password store %q: creating client: %w", h.secret, err)
	}
	h.items = client.Items()
	return h.items, nil
}

// selectOPField looks up the field identified by ref on a list of SDK
// ItemFields. The field is matched by ID or Title; when ref carries a
// section, the field's SectionID must also match. Symmetric with
// secrets.SelectConnectField but specialized for the SDK's
// onepassword.ItemField type, which uses a SectionID pointer instead of
// the Connect SDK's *ItemSection.
func selectOPField(fields []onepassword.ItemField, ref secrets.OPRef) (string, error) {
	for _, f := range fields {
		if f.ID != ref.Field && f.Title != ref.Field {
			continue
		}
		if ref.Section != "" {
			if f.SectionID == nil || *f.SectionID != ref.Section {
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
	for i := range item.Fields {
		f := &item.Fields[i]
		if f.ID != ref.Field && f.Title != ref.Field {
			continue
		}
		if ref.Section != "" {
			if f.SectionID == nil || *f.SectionID != ref.Section {
				continue
			}
		}
		f.Value = value
		return true
	}
	return false
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
// 36-character UUIDs. Strict validation belongs to the SDK; this is just
// enough to catch operators pasting human titles into a field that needs an
// ID.
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
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
