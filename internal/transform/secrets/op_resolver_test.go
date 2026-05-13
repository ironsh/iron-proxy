package secrets

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	onepassword "github.com/1password/onepassword-sdk-go"
	"github.com/stretchr/testify/require"
)

// mockOPClient is a configurable mock for the 1Password SDK client.
type mockOPClient struct {
	listVaults func(ctx context.Context) ([]onepassword.VaultOverview, error)
	listItems  func(ctx context.Context, vaultID string) ([]onepassword.ItemOverview, error)
	getItem    func(ctx context.Context, vaultID, itemID string) (onepassword.Item, error)
}

func (m *mockOPClient) ListVaults(ctx context.Context) ([]onepassword.VaultOverview, error) {
	return m.listVaults(ctx)
}

func (m *mockOPClient) ListItems(ctx context.Context, vaultID string) ([]onepassword.ItemOverview, error) {
	return m.listItems(ctx, vaultID)
}

func (m *mockOPClient) GetItem(ctx context.Context, vaultID, itemID string) (onepassword.Item, error) {
	return m.getItem(ctx, vaultID, itemID)
}

func sampleSDKVaults() []onepassword.VaultOverview {
	return []onepassword.VaultOverview{
		{ID: "vault-uuid", Title: "Engineering"},
	}
}

func sampleSDKItems() []onepassword.ItemOverview {
	return []onepassword.ItemOverview{
		{ID: "item-uuid", Title: "OpenAI", VaultID: "vault-uuid"},
	}
}

func sampleSDKItem() onepassword.Item {
	sectionID := "section-uuid"
	return onepassword.Item{
		ID:      "item-uuid",
		Title:   "OpenAI",
		VaultID: "vault-uuid",
		Sections: []onepassword.ItemSection{
			{ID: "section-uuid", Title: "api"},
		},
		Fields: []onepassword.ItemField{
			{ID: "field-uuid", Title: "credential", Value: "real-secret"},
			{ID: "other", Title: "username", Value: "alice"},
			{
				ID:        "section-field-uuid",
				Title:     "api_key",
				Value:     "section-secret",
				SectionID: &sectionID,
			},
		},
	}
}

// staticOPClient returns an opClient that always serves the same vault, item,
// and item details — sufficient for tests that only care about the proxy
// glue, not the lookup logic.
func staticOPClient() *mockOPClient {
	return &mockOPClient{
		listVaults: func(context.Context) ([]onepassword.VaultOverview, error) {
			return sampleSDKVaults(), nil
		},
		listItems: func(context.Context, string) ([]onepassword.ItemOverview, error) {
			return sampleSDKItems(), nil
		},
		getItem: func(context.Context, string, string) (onepassword.Item, error) {
			return sampleSDKItem(), nil
		},
	}
}

func newTestOPBuilder(client opClient) *opBuilder {
	return &opBuilder{
		clientFor: func(_ context.Context, _ string) (opClient, error) {
			return client, nil
		},
		logger: slog.Default(),
	}
}

func TestOPBuilder_HappyPath_DefaultTokenEnv(t *testing.T) {
	var gotEnv string
	r := &opBuilder{
		clientFor: func(_ context.Context, tokenEnv string) (opClient, error) {
			gotEnv = tokenEnv
			return staticOPClient(), nil
		},
		logger: slog.Default(),
	}

	node := yamlNode(t, map[string]string{
		"type":       "1password",
		"secret_ref": "op://Engineering/OpenAI/credential",
	})
	result, err := r.Build(node)
	require.NoError(t, err)
	require.Equal(t, "op://Engineering/OpenAI/credential", result.Name())

	val, err := result.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "real-secret", val)
	require.Equal(t, "OP_SERVICE_ACCOUNT_TOKEN", gotEnv)
}

func TestOPBuilder_HappyPath_CustomTokenEnv(t *testing.T) {
	var gotEnv string
	r := &opBuilder{
		clientFor: func(_ context.Context, tokenEnv string) (opClient, error) {
			gotEnv = tokenEnv
			return staticOPClient(), nil
		},
		logger: slog.Default(),
	}

	node := yamlNode(t, map[string]string{
		"type":       "1password",
		"secret_ref": "op://Engineering/OpenAI/credential",
		"token_env":  "CUSTOM_OP_TOKEN",
	})
	result, err := r.Build(node)
	require.NoError(t, err)

	val, err := result.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "real-secret", val)
	require.Equal(t, "CUSTOM_OP_TOKEN", gotEnv)
}

func TestOPBuilder_TTLReturnsCachedValue(t *testing.T) {
	r := newTestOPBuilder(staticOPClient())
	node := yamlNode(t, map[string]string{
		"type":       "1password",
		"secret_ref": "op://Engineering/OpenAI/credential",
		"ttl":        "15m",
	})
	result, err := r.Build(node)
	require.NoError(t, err)

	val, err := result.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "real-secret", val)
}

func TestOPBuilder_LooksUpByTitle(t *testing.T) {
	var gotVaultID, gotItemVaultID, gotItemID string
	client := &mockOPClient{
		listVaults: func(context.Context) ([]onepassword.VaultOverview, error) {
			return sampleSDKVaults(), nil
		},
		listItems: func(_ context.Context, vaultID string) ([]onepassword.ItemOverview, error) {
			gotVaultID = vaultID
			return sampleSDKItems(), nil
		},
		getItem: func(_ context.Context, vaultID, itemID string) (onepassword.Item, error) {
			gotItemVaultID = vaultID
			gotItemID = itemID
			return sampleSDKItem(), nil
		},
	}
	r := newTestOPBuilder(client)
	node := yamlNode(t, map[string]string{
		"type":       "1password",
		"secret_ref": "op://Engineering/OpenAI/credential",
	})
	result, err := r.Build(node)
	require.NoError(t, err)
	val, err := result.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "real-secret", val)
	require.Equal(t, "vault-uuid", gotVaultID)
	require.Equal(t, "vault-uuid", gotItemVaultID)
	require.Equal(t, "item-uuid", gotItemID)
}

// TestOPBuilder_SpecialCharsInVaultName verifies that vault/item/field names
// containing characters the SDK's reference parser rejects (spaces, "&", etc.)
// resolve via the title-based lookup.
func TestOPBuilder_SpecialCharsInVaultName(t *testing.T) {
	vaults := []onepassword.VaultOverview{
		{ID: "vault-uuid", Title: "AI Keys & Passwords"},
	}
	items := []onepassword.ItemOverview{
		{ID: "item-uuid", Title: "OpenAI", VaultID: "vault-uuid"},
	}
	item := sampleSDKItem()
	client := &mockOPClient{
		listVaults: func(context.Context) ([]onepassword.VaultOverview, error) { return vaults, nil },
		listItems:  func(context.Context, string) ([]onepassword.ItemOverview, error) { return items, nil },
		getItem:    func(context.Context, string, string) (onepassword.Item, error) { return item, nil },
	}

	r := newTestOPBuilder(client)
	node := yamlNode(t, map[string]string{
		"type":       "1password",
		"secret_ref": "op://AI Keys & Passwords/OpenAI/credential",
	})
	result, err := r.Build(node)
	require.NoError(t, err)
	val, err := result.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "real-secret", val)
}

func TestOPBuilder_SectionRef(t *testing.T) {
	r := newTestOPBuilder(staticOPClient())
	node := yamlNode(t, map[string]string{
		"type":       "1password",
		"secret_ref": "op://Engineering/OpenAI/api/api_key",
	})
	result, err := r.Build(node)
	require.NoError(t, err)
	val, err := result.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "section-secret", val)
}

func TestOPBuilder_Errors(t *testing.T) {
	emptyVaults := &mockOPClient{
		listVaults: func(context.Context) ([]onepassword.VaultOverview, error) { return nil, nil },
	}
	emptyItems := &mockOPClient{
		listVaults: func(context.Context) ([]onepassword.VaultOverview, error) { return sampleSDKVaults(), nil },
		listItems:  func(context.Context, string) ([]onepassword.ItemOverview, error) { return nil, nil },
	}
	listVaultsErr := &mockOPClient{
		listVaults: func(context.Context) ([]onepassword.VaultOverview, error) {
			return nil, fmt.Errorf("network down")
		},
	}
	emptyItem := &mockOPClient{
		listVaults: func(context.Context) ([]onepassword.VaultOverview, error) { return sampleSDKVaults(), nil },
		listItems:  func(context.Context, string) ([]onepassword.ItemOverview, error) { return sampleSDKItems(), nil },
		getItem: func(context.Context, string, string) (onepassword.Item, error) {
			return onepassword.Item{ID: "item-uuid"}, nil
		},
	}
	emptyValue := &mockOPClient{
		listVaults: func(context.Context) ([]onepassword.VaultOverview, error) { return sampleSDKVaults(), nil },
		listItems:  func(context.Context, string) ([]onepassword.ItemOverview, error) { return sampleSDKItems(), nil },
		getItem: func(context.Context, string, string) (onepassword.Item, error) {
			return onepassword.Item{
				ID:     "item-uuid",
				Fields: []onepassword.ItemField{{Title: "credential", Value: ""}},
			}, nil
		},
	}

	tests := []struct {
		name   string
		client *mockOPClient
		input  map[string]string
		errMsg string
		errAt  string
	}{
		{
			name:   "missing secret_ref",
			client: staticOPClient(),
			input:  map[string]string{"type": "1password"},
			errMsg: "\"secret_ref\" field",
			errAt:  "build",
		},
		{
			name:   "secret_ref without op:// prefix",
			client: staticOPClient(),
			input:  map[string]string{"type": "1password", "secret_ref": "vault/item/field"},
			errMsg: "must start with \"op://\"",
			errAt:  "build",
		},
		{
			name:   "invalid ttl",
			client: staticOPClient(),
			input:  map[string]string{"type": "1password", "secret_ref": "op://Engineering/OpenAI/credential", "ttl": "not-a-duration"},
			errMsg: "parsing ttl",
			errAt:  "build",
		},
		{
			name:   "list vaults error",
			client: listVaultsErr,
			input:  map[string]string{"type": "1password", "secret_ref": "op://Engineering/OpenAI/credential"},
			errMsg: "network down",
			errAt:  "fetch",
		},
		{
			name:   "vault not found",
			client: emptyVaults,
			input:  map[string]string{"type": "1password", "secret_ref": "op://Engineering/OpenAI/credential"},
			errMsg: "vault \"Engineering\" not found",
			errAt:  "fetch",
		},
		{
			name:   "item not found",
			client: emptyItems,
			input:  map[string]string{"type": "1password", "secret_ref": "op://Engineering/OpenAI/credential"},
			errMsg: "item \"OpenAI\" not found in vault \"Engineering\"",
			errAt:  "fetch",
		},
		{
			name:   "field not found",
			client: emptyItem,
			input:  map[string]string{"type": "1password", "secret_ref": "op://Engineering/OpenAI/credential"},
			errMsg: "field \"credential\" not found",
			errAt:  "fetch",
		},
		{
			name:   "empty secret value",
			client: emptyValue,
			input:  map[string]string{"type": "1password", "secret_ref": "op://Engineering/OpenAI/credential"},
			errMsg: "empty value",
			errAt:  "fetch",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newTestOPBuilder(tt.client)
			node := yamlNode(t, tt.input)
			result, err := r.Build(node)
			if tt.errAt == "build" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
				return
			}
			require.NoError(t, err)
			_, err = result.Get(context.Background())
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

func TestSelectSDKField(t *testing.T) {
	item := sampleSDKItem()

	tests := []struct {
		name    string
		ref     opRef
		want    string
		wantErr string
	}{
		{
			name: "match by title",
			ref:  opRef{field: "credential"},
			want: "real-secret",
		},
		{
			name: "match by id",
			ref:  opRef{field: "field-uuid"},
			want: "real-secret",
		},
		{
			name: "match with section title",
			ref:  opRef{section: "api", field: "api_key"},
			want: "section-secret",
		},
		{
			name: "match with section id",
			ref:  opRef{section: "section-uuid", field: "api_key"},
			want: "section-secret",
		},
		{
			name:    "section not found",
			ref:     opRef{section: "missing", field: "api_key"},
			wantErr: "section \"missing\" not found",
		},
		{
			name:    "field in section not found",
			ref:     opRef{section: "api", field: "credential"},
			wantErr: "field \"credential\" in section \"api\" not found",
		},
		{
			name:    "missing field",
			ref:     opRef{field: "nope"},
			wantErr: "field \"nope\" not found",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := selectSDKField(item, tt.ref)
			if tt.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

// --- opClientCache tests ---

func TestOPClientCache_ReadsTokenFromEnv(t *testing.T) {
	var gotToken string
	cache := &opClientCache{
		clients: make(map[string]opClient),
		getenv: func(key string) string {
			if key == "MY_OP_TOKEN" {
				return "ops_secret_value"
			}
			return ""
		},
		newClient: func(_ context.Context, token string) (opClient, error) {
			gotToken = token
			return staticOPClient(), nil
		},
	}

	_, err := cache.get(context.Background(), "MY_OP_TOKEN")
	require.NoError(t, err)
	require.Equal(t, "ops_secret_value", gotToken)
}

func TestOPClientCache_ErrorOnMissingEnvVar(t *testing.T) {
	cache := &opClientCache{
		clients:   make(map[string]opClient),
		getenv:    func(string) string { return "" },
		newClient: func(_ context.Context, _ string) (opClient, error) { return nil, nil },
	}

	_, err := cache.get(context.Background(), "MISSING_OP_TOKEN")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not set or empty")
}

func TestOPClientCache_ReusesClientPerTokenEnv(t *testing.T) {
	calls := 0
	cache := &opClientCache{
		clients: make(map[string]opClient),
		getenv:  func(string) string { return "tok" },
		newClient: func(_ context.Context, _ string) (opClient, error) {
			calls++
			return staticOPClient(), nil
		},
	}

	_, err := cache.get(context.Background(), "ENV1")
	require.NoError(t, err)
	_, err = cache.get(context.Background(), "ENV1")
	require.NoError(t, err)
	require.Equal(t, 1, calls, "second get on the same token_env should reuse the cached client")

	_, err = cache.get(context.Background(), "ENV2")
	require.NoError(t, err)
	require.Equal(t, 2, calls, "different token_env should create a new client")
}

func TestOPClientCache_PropagatesNewClientError(t *testing.T) {
	cache := &opClientCache{
		clients: make(map[string]opClient),
		getenv:  func(string) string { return "tok" },
		newClient: func(_ context.Context, _ string) (opClient, error) {
			return nil, fmt.Errorf("sdk init failed")
		},
	}

	_, err := cache.get(context.Background(), "ENV")
	require.Error(t, err)
	require.Contains(t, err.Error(), "sdk init failed")
}
