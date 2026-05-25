package store

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

	"github.com/ironsh/iron-proxy/internal/transform/secrets"
	"github.com/ironsh/iron-proxy/internal/version"
)

const (
	opConnectHostEnv  = "OP_CONNECT_HOST"
	opConnectTokenEnv = "OP_CONNECT_TOKEN"
)

type opConnectBuilder struct{}

type opConnectConfig struct {
	Type      string `yaml:"type"`
	SecretRef string `yaml:"secret_ref"`
}

func (opConnectBuilder) Build(raw yaml.Node, logger *slog.Logger) (Handle, error) {
	var cfg opConnectConfig
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing 1password_connect store config: %w", err)
	}
	if cfg.SecretRef == "" {
		return nil, fmt.Errorf("1password_connect store requires \"secret_ref\" field")
	}
	ref, err := secrets.ParseOPRef(cfg.SecretRef)
	if err != nil {
		return nil, fmt.Errorf("1password_connect store: %w", err)
	}
	return &opConnectHandle{
		ref:    ref,
		secret: cfg.SecretRef,
		logger: logger,
	}, nil
}

// opConnectClient is the subset of the Connect SDK client used by
// opConnectHandle, narrowed for testability. Connect accepts both UUIDs
// and human titles for vault and item refs.
type opConnectClient interface {
	GetVault(ref string) (*onepassword.Vault, error)
	GetItem(itemRef, vaultRef string) (*onepassword.Item, error)
	UpdateItem(item *onepassword.Item, vaultUUID string) (*onepassword.Item, error)
}

// opConnectHandle persists the credential blob via a 1Password Connect
// server.
type opConnectHandle struct {
	ref    secrets.OPRef
	secret string
	logger *slog.Logger

	mu     sync.Mutex
	client opConnectClient
}

func (h *opConnectHandle) Name() string { return h.secret }

func (h *opConnectHandle) Get(_ context.Context) (CredentialBlob, error) {
	client, err := h.getClient()
	if err != nil {
		return CredentialBlob{}, err
	}
	vault, err := client.GetVault(h.ref.Vault)
	if err != nil {
		if isConnectNotFound(err) {
			return CredentialBlob{}, ErrNotFound
		}
		return CredentialBlob{}, fmt.Errorf("1password_connect GetVault %q: %w", h.ref.Vault, err)
	}
	item, err := client.GetItem(h.ref.Item, vault.ID)
	if err != nil {
		if isConnectNotFound(err) {
			return CredentialBlob{}, ErrNotFound
		}
		return CredentialBlob{}, fmt.Errorf("1password_connect GetItem %q: %w", h.ref.Item, err)
	}
	raw, err := secrets.SelectConnectField(item, h.ref)
	if err != nil {
		return CredentialBlob{}, fmt.Errorf("1password_connect store %q: %w", h.secret, err)
	}
	if raw == "" {
		return CredentialBlob{}, ErrNotFound
	}
	blob, err := unmarshalBlob([]byte(raw))
	if err != nil {
		return CredentialBlob{}, fmt.Errorf("1password_connect store %q: %w", h.secret, err)
	}
	return blob, nil
}

func (h *opConnectHandle) Put(_ context.Context, blob CredentialBlob) error {
	client, err := h.getClient()
	if err != nil {
		return err
	}
	vault, err := client.GetVault(h.ref.Vault)
	if err != nil {
		return fmt.Errorf("1password_connect GetVault (pre-put) %q: %w", h.ref.Vault, err)
	}
	// Hydrate the full Item: UpdateItem replaces the document wholesale,
	// so we need the live version to avoid clobbering operator-managed
	// fields.
	item, err := client.GetItem(h.ref.Item, vault.ID)
	if err != nil {
		return fmt.Errorf("1password_connect GetItem (pre-put) %q: %w", h.ref.Item, err)
	}
	raw, err := marshalBlob(blob)
	if err != nil {
		return err
	}
	if !setConnectField(item, h.ref, string(raw)) {
		return fmt.Errorf("1password_connect store %q: field %q not found on item; create it before bootstrap", h.secret, h.ref.Field)
	}
	if _, err := client.UpdateItem(item, vault.ID); err != nil {
		return fmt.Errorf("1password_connect UpdateItem %q: %w", h.secret, err)
	}
	return nil
}

func (h *opConnectHandle) getClient() (opConnectClient, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.client != nil {
		return h.client, nil
	}
	host := os.Getenv(opConnectHostEnv)
	if host == "" {
		return nil, fmt.Errorf("1password_connect store %q: env var %q is not set or empty", h.secret, opConnectHostEnv)
	}
	token := os.Getenv(opConnectTokenEnv)
	if token == "" {
		return nil, fmt.Errorf("1password_connect store %q: env var %q is not set or empty", h.secret, opConnectTokenEnv)
	}
	h.client = connect.NewClientWithUserAgent(host, token, "iron-token-broker/"+version.Version)
	return h.client, nil
}

// setConnectField writes value into the field identified by ref. Returns
// true if a matching field was found and mutated. Symmetric with
// secrets.SelectConnectField on the read side; the broker is the only
// writer.
func setConnectField(item *onepassword.Item, ref secrets.OPRef, value string) bool {
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
		f.Value = value
		return true
	}
	return false
}

func isConnectNotFound(err error) bool {
	if err == nil {
		return false
	}
	// Connect surfaces 404s as a typed APIError with StatusCode == 404,
	// but matching on the message keeps the dependency surface minimal and
	// is robust to small SDK churn.
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") || strings.Contains(msg, "404")
}

