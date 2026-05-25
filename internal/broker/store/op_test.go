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
	mu       sync.Mutex
	items    map[string]onepassword.Item // key: vault|item
	listCalls int
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

func (f *fakeOPItems) List(_ context.Context, vaultID string, _ ...onepassword.ItemListFilter) ([]onepassword.ItemOverview, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listCalls++
	var out []onepassword.ItemOverview
	for _, it := range f.items {
		if it.VaultID != vaultID {
			continue
		}
		out = append(out, onepassword.ItemOverview{ID: it.ID, Title: it.Title, VaultID: it.VaultID})
	}
	return out, nil
}

// fakeOPVaults is an in-memory VaultsAPI subset.
type fakeOPVaults struct {
	mu        sync.Mutex
	vaults    []onepassword.VaultOverview
	listCalls int
}

func (f *fakeOPVaults) List(_ context.Context, _ ...onepassword.VaultListParams) ([]onepassword.VaultOverview, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listCalls++
	return append([]onepassword.VaultOverview(nil), f.vaults...), nil
}

func newOPHandle(t *testing.T, items opSDKItemsAPI, vaults opSDKVaultsAPI, ref secrets.OPRef, secret string) *opHandle {
	t.Helper()
	return &opHandle{
		ref:    ref,
		secret: secret,
		items:  items,
		vaults: vaults,
	}
}

func newOPHandleUUID(t *testing.T, items opSDKItemsAPI, fieldTitle string) *opHandle {
	t.Helper()
	return newOPHandle(t, items, &fakeOPVaults{},
		secrets.OPRef{Vault: testVaultUUID, Item: testItemUUID, Field: fieldTitle},
		"op://"+testVaultUUID+"/"+testItemUUID+"/"+fieldTitle,
	)
}

func seedItem(items *fakeOPItems, fieldTitle, value string) {
	seedItemTitled(items, "", fieldTitle, value)
}

func seedItemTitled(items *fakeOPItems, itemTitle, fieldTitle, value string) {
	items.seed(onepassword.Item{
		ID:      testItemUUID,
		Title:   itemTitle,
		VaultID: testVaultUUID,
		Fields: []onepassword.ItemField{
			{ID: "fld_1", Title: fieldTitle, Value: value},
		},
	})
}

func TestOPBuilderAcceptsUUIDs(t *testing.T) {
	_, err := opBuilder{}.Build(mustNode(t, `{type: 1password, secret_ref: "op://`+testVaultUUID+`/`+testItemUUID+`/credential_blob"}`), nil)
	require.NoError(t, err)
}

func TestOPBuilderAcceptsTitles(t *testing.T) {
	_, err := opBuilder{}.Build(mustNode(t, `{type: 1password, secret_ref: "op://ai-agents/CODEX_BLOB/credential"}`), nil)
	require.NoError(t, err)
}

func TestOPBuilderRejectsBadRef(t *testing.T) {
	_, err := opBuilder{}.Build(mustNode(t, `{type: 1password, secret_ref: "not-a-ref"}`), nil)
	require.Error(t, err)
}

func TestOPHandleGetReturnsNotFoundOnEmptyField(t *testing.T) {
	items := newFakeOPItems()
	seedItem(items, "credential_blob", "")
	h := newOPHandleUUID(t, items, "credential_blob")
	_, err := h.Get(t.Context())
	require.ErrorIs(t, err, ErrNotFound)
}

func TestOPHandleGetReturnsNotFoundOnMissingItem(t *testing.T) {
	h := newOPHandleUUID(t, newFakeOPItems(), "credential_blob")
	_, err := h.Get(t.Context())
	require.ErrorIs(t, err, ErrNotFound)
}

func TestOPHandleRoundTrip(t *testing.T) {
	items := newFakeOPItems()
	seedItem(items, "credential_blob", `{"refresh_token":"rt-0"}`)
	h := newOPHandleUUID(t, items, "credential_blob")

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
	h := newOPHandleUUID(t, items, "credential_blob")
	err := h.Put(t.Context(), CredentialBlob{RefreshToken: "rt"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "credential_blob")
}

func TestOPHandleResolvesTitles(t *testing.T) {
	items := newFakeOPItems()
	seedItemTitled(items, "CODEX_BLOB", "credential", `{"refresh_token":"rt-0"}`)
	vaults := &fakeOPVaults{vaults: []onepassword.VaultOverview{
		{ID: testVaultUUID, Title: "ai-agents"},
		{ID: "otheruuidabcdefghij012345m", Title: "unrelated"},
	}}
	h := newOPHandle(t, items, vaults,
		secrets.OPRef{Vault: "ai-agents", Item: "CODEX_BLOB", Field: "credential"},
		"op://ai-agents/CODEX_BLOB/credential",
	)

	blob, err := h.Get(t.Context())
	require.NoError(t, err)
	require.Equal(t, "rt-0", blob.RefreshToken)

	// Second call must hit the cached UUIDs, not re-list.
	_, err = h.Get(t.Context())
	require.NoError(t, err)
	require.Equal(t, 1, vaults.listCalls)
	require.Equal(t, 1, items.listCalls)
}

func TestOPHandleMixedTitleAndUUID(t *testing.T) {
	items := newFakeOPItems()
	seedItemTitled(items, "CODEX_BLOB", "credential", `{"refresh_token":"rt"}`)
	vaults := &fakeOPVaults{vaults: []onepassword.VaultOverview{
		{ID: testVaultUUID, Title: "ai-agents"},
	}}
	// Vault as UUID, item as title: only Items.List should be called.
	h := newOPHandle(t, items, vaults,
		secrets.OPRef{Vault: testVaultUUID, Item: "CODEX_BLOB", Field: "credential"},
		"op://"+testVaultUUID+"/CODEX_BLOB/credential",
	)
	_, err := h.Get(t.Context())
	require.NoError(t, err)
	require.Equal(t, 0, vaults.listCalls)
	require.Equal(t, 1, items.listCalls)
}

func TestOPHandleVaultTitleNotFound(t *testing.T) {
	vaults := &fakeOPVaults{vaults: []onepassword.VaultOverview{
		{ID: testVaultUUID, Title: "ai-agents"},
	}}
	h := newOPHandle(t, newFakeOPItems(), vaults,
		secrets.OPRef{Vault: "missing", Item: "CODEX_BLOB", Field: "credential"},
		"op://missing/CODEX_BLOB/credential",
	)
	_, err := h.Get(t.Context())
	require.Error(t, err)
	require.Contains(t, err.Error(), `vault "missing" not found`)
}

func TestOPHandleVaultTitleAmbiguous(t *testing.T) {
	vaults := &fakeOPVaults{vaults: []onepassword.VaultOverview{
		{ID: testVaultUUID, Title: "ai-agents"},
		{ID: "otheruuidabcdefghij012345m", Title: "ai-agents"},
	}}
	h := newOPHandle(t, newFakeOPItems(), vaults,
		secrets.OPRef{Vault: "ai-agents", Item: "CODEX_BLOB", Field: "credential"},
		"op://ai-agents/CODEX_BLOB/credential",
	)
	_, err := h.Get(t.Context())
	require.Error(t, err)
	require.Contains(t, err.Error(), "multiple vaults named")
}

func TestOPHandleItemTitleNotFound(t *testing.T) {
	items := newFakeOPItems()
	seedItemTitled(items, "OTHER", "credential", `{"refresh_token":"rt"}`)
	vaults := &fakeOPVaults{vaults: []onepassword.VaultOverview{
		{ID: testVaultUUID, Title: "ai-agents"},
	}}
	h := newOPHandle(t, items, vaults,
		secrets.OPRef{Vault: "ai-agents", Item: "CODEX_BLOB", Field: "credential"},
		"op://ai-agents/CODEX_BLOB/credential",
	)
	_, err := h.Get(t.Context())
	require.Error(t, err)
	require.Contains(t, err.Error(), `item "CODEX_BLOB" not found`)
}

func TestOPHandleSectionByTitle(t *testing.T) {
	items := newFakeOPItems()
	sectionID := "sec-123"
	items.seed(onepassword.Item{
		ID:      testItemUUID,
		Title:   "CODEX_BLOB",
		VaultID: testVaultUUID,
		Sections: []onepassword.ItemSection{
			{ID: sectionID, Title: "api"},
		},
		Fields: []onepassword.ItemField{
			{ID: "fld_1", Title: "credential", SectionID: &sectionID, Value: `{"refresh_token":"rt"}`},
		},
	})
	vaults := &fakeOPVaults{vaults: []onepassword.VaultOverview{
		{ID: testVaultUUID, Title: "ai-agents"},
	}}
	h := newOPHandle(t, items, vaults,
		secrets.OPRef{Vault: "ai-agents", Item: "CODEX_BLOB", Section: "api", Field: "credential"},
		"op://ai-agents/CODEX_BLOB/api/credential",
	)
	blob, err := h.Get(t.Context())
	require.NoError(t, err)
	require.Equal(t, "rt", blob.RefreshToken)
}

func TestLooksLikeUUID(t *testing.T) {
	require.True(t, looksLikeUUID("abcd1234efgh5678ijkl9012mn"))
	require.True(t, looksLikeUUID("123e4567-e89b-12d3-a456-426614174000"))
	require.False(t, looksLikeUUID(""))
	require.False(t, looksLikeUUID("MyVault"))
	require.False(t, looksLikeUUID("Engineering"))
}
