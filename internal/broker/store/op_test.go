package store

import (
	"context"
	"errors"
	"sync"
	"testing"

	onepassword "github.com/1password/onepassword-sdk-go"
	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

const (
	testVaultUUID = "abcd1234efgh5678ijkl9012mn"
	testItemUUID  = "1234abcd5678efgh9012ijkl3m"
)

// fakeOPItems is an in-memory ItemsAPI subset keyed by (vault, item).
type fakeOPItems struct {
	mu    sync.Mutex
	items map[string]onepassword.Item // key: vault|item
}

func newFakeOPItems() *fakeOPItems {
	return &fakeOPItems{items: map[string]onepassword.Item{}}
}

func (f *fakeOPItems) seed(item onepassword.Item) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items[item.VaultID+"|"+item.ID] = item
}

func (f *fakeOPItems) Get(_ context.Context, vaultID, itemID string) (onepassword.Item, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	item, ok := f.items[vaultID+"|"+itemID]
	if !ok {
		return onepassword.Item{}, errors.New("itemNotFound")
	}
	return item, nil
}

func (f *fakeOPItems) Put(_ context.Context, item onepassword.Item) (onepassword.Item, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := item.VaultID + "|" + item.ID
	if _, ok := f.items[key]; !ok {
		return onepassword.Item{}, errors.New("itemNotFound")
	}
	f.items[key] = item
	return item, nil
}

func newOPHandle(t *testing.T, items opSDKItemsAPI, fieldTitle string) *opHandle {
	t.Helper()
	return &opHandle{
		ref:    secrets.OPRef{Vault: testVaultUUID, Item: testItemUUID, Field: fieldTitle},
		secret: "op://" + testVaultUUID + "/" + testItemUUID + "/" + fieldTitle,
		items:  items,
	}
}

func seedItem(items *fakeOPItems, fieldTitle, value string) {
	items.seed(onepassword.Item{
		ID:      testItemUUID,
		VaultID: testVaultUUID,
		Fields: []onepassword.ItemField{
			{ID: "fld_1", Title: fieldTitle, Value: value},
		},
	})
}

func TestOPBuilderRejectsNonUUIDVault(t *testing.T) {
	_, err := opBuilder{}.Build(mustNode(t, `{type: 1password, secret_ref: "op://MyVault/abcd1234efgh5678ijkl9012mn/credential_blob"}`), nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "vault segment must be a UUID")
}

func TestOPBuilderRejectsNonUUIDItem(t *testing.T) {
	_, err := opBuilder{}.Build(mustNode(t, `{type: 1password, secret_ref: "op://abcd1234efgh5678ijkl9012mn/My Item/credential_blob"}`), nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "item segment must be a UUID")
}

func TestOPBuilderAcceptsUUIDs(t *testing.T) {
	_, err := opBuilder{}.Build(mustNode(t, `{type: 1password, secret_ref: "op://`+testVaultUUID+`/`+testItemUUID+`/credential_blob"}`), nil)
	require.NoError(t, err)
}

func TestOPHandleGetReturnsNotFoundOnEmptyField(t *testing.T) {
	items := newFakeOPItems()
	seedItem(items, "credential_blob", "")
	h := newOPHandle(t, items, "credential_blob")
	_, err := h.Get(t.Context())
	require.ErrorIs(t, err, ErrNotFound)
}

func TestOPHandleGetReturnsNotFoundOnMissingItem(t *testing.T) {
	h := newOPHandle(t, newFakeOPItems(), "credential_blob")
	_, err := h.Get(t.Context())
	require.ErrorIs(t, err, ErrNotFound)
}

func TestOPHandleRoundTrip(t *testing.T) {
	items := newFakeOPItems()
	seedItem(items, "credential_blob", `{"refresh_token":"rt-0"}`)
	h := newOPHandle(t, items, "credential_blob")

	blob, err := h.Get(t.Context())
	require.NoError(t, err)
	require.Equal(t, "rt-0", blob.RefreshToken)

	mustPut(t, h, CredentialBlob{RefreshToken: "rt-1"})
	blob, err = h.Get(t.Context())
	require.NoError(t, err)
	require.Equal(t, "rt-1", blob.RefreshToken)
}

func TestOPHandlePutMissingFieldErrors(t *testing.T) {
	items := newFakeOPItems()
	seedItem(items, "wrong_field", `{"refresh_token":"rt"}`)
	h := newOPHandle(t, items, "credential_blob")
	err := h.Put(t.Context(), CredentialBlob{RefreshToken: "rt"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "credential_blob")
}

func TestLooksLikeUUID(t *testing.T) {
	require.True(t, looksLikeUUID("abcd1234efgh5678ijkl9012mn"))
	require.True(t, looksLikeUUID("123e4567-e89b-12d3-a456-426614174000"))
	require.False(t, looksLikeUUID(""))
	require.False(t, looksLikeUUID("MyVault"))
	require.False(t, looksLikeUUID("Engineering"))
}
