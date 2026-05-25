package store

import (
	"errors"
	"sync"
	"testing"

	"github.com/1Password/connect-sdk-go/onepassword"
	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

// fakeConnectClient is an in-memory connect.Client subset.
type fakeConnectClient struct {
	mu     sync.Mutex
	vaults map[string]*onepassword.Vault
	items  map[string]*onepassword.Item // key: vaultID|itemID
}

func newFakeConnect() *fakeConnectClient {
	return &fakeConnectClient{
		vaults: map[string]*onepassword.Vault{},
		items:  map[string]*onepassword.Item{},
	}
}

func (f *fakeConnectClient) seedVault(v *onepassword.Vault) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.vaults[v.ID] = v
	f.vaults[v.Name] = v
}

func (f *fakeConnectClient) seedItem(item *onepassword.Item) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items[item.Vault.ID+"|"+item.ID] = item
}

func (f *fakeConnectClient) GetVault(ref string) (*onepassword.Vault, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.vaults[ref]
	if !ok {
		return nil, errors.New("404 not found")
	}
	return v, nil
}

func (f *fakeConnectClient) GetItem(itemRef, vaultUUID string) (*onepassword.Item, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, it := range f.items {
		if k == vaultUUID+"|"+itemRef || it.Title == itemRef {
			return it, nil
		}
	}
	return nil, errors.New("404 not found")
}

func (f *fakeConnectClient) UpdateItem(item *onepassword.Item, vaultUUID string) (*onepassword.Item, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := vaultUUID + "|" + item.ID
	if _, ok := f.items[key]; !ok {
		return nil, errors.New("404 not found")
	}
	stored := *item
	f.items[key] = &stored
	return &stored, nil
}

func newConnectHandle(t *testing.T, client opConnectClient, vault, item, field string) *opConnectHandle {
	t.Helper()
	return &opConnectHandle{
		ref:    secrets.OPRef{Vault: vault, Item: item, Field: field},
		secret: "op://" + vault + "/" + item + "/" + field,
		client: client,
	}
}

func TestOPConnectBuilderRequiresSecretRef(t *testing.T) {
	_, err := opConnectBuilder{}.Build(mustNode(t, `{type: 1password_connect}`), nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "secret_ref")
}

func TestOPConnectBuilderAcceptsHumanNames(t *testing.T) {
	// Unlike the SDK backend, Connect natively resolves names.
	_, err := opConnectBuilder{}.Build(mustNode(t, `{type: 1password_connect, secret_ref: "op://Engineering/openai-codex/credential_blob"}`), nil)
	require.NoError(t, err)
}

func TestOPConnectGetReturnsNotFoundOnMissingVault(t *testing.T) {
	h := newConnectHandle(t, newFakeConnect(), "Engineering", "openai-codex", "credential_blob")
	_, err := h.Get(t.Context())
	require.ErrorIs(t, err, ErrNotFound)
}

func TestOPConnectRoundTrip(t *testing.T) {
	fake := newFakeConnect()
	fake.seedVault(&onepassword.Vault{ID: "v-uuid", Name: "Engineering"})
	fake.seedItem(&onepassword.Item{
		ID:    "i-uuid",
		Title: "openai-codex",
		Vault: onepassword.ItemVault{ID: "v-uuid"},
		Fields: []*onepassword.ItemField{
			{ID: "fld_1", Label: "credential_blob", Value: `{"refresh_token":"rt-0"}`},
		},
	})
	h := newConnectHandle(t, fake, "Engineering", "openai-codex", "credential_blob")

	blob, err := h.Get(t.Context())
	require.NoError(t, err)
	require.Equal(t, "rt-0", blob.RefreshToken)

	mustPut(t, h, CredentialBlob{RefreshToken: "rt-1"})
	blob, err = h.Get(t.Context())
	require.NoError(t, err)
	require.Equal(t, "rt-1", blob.RefreshToken)
}
