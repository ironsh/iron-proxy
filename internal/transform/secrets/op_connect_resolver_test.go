package secrets

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	"github.com/1Password/connect-sdk-go/onepassword"
	"github.com/stretchr/testify/require"
)

// mockOPConnectClient is a configurable mock for the Connect SDK client.
type mockOPConnectClient struct {
	getVault func(ref string) (*onepassword.Vault, error)
	getItem  func(itemRef, vaultRef string) (*onepassword.Item, error)
}

func (m *mockOPConnectClient) GetVault(ref string) (*onepassword.Vault, error) {
	return m.getVault(ref)
}

func (m *mockOPConnectClient) GetItem(itemRef, vaultRef string) (*onepassword.Item, error) {
	return m.getItem(itemRef, vaultRef)
}

// staticOPConnectClient returns a client that resolves to the given vault and item.
func staticOPConnectClient(vault *onepassword.Vault, item *onepassword.Item) *mockOPConnectClient {
	return &mockOPConnectClient{
		getVault: func(string) (*onepassword.Vault, error) { return vault, nil },
		getItem:  func(string, string) (*onepassword.Item, error) { return item, nil },
	}
}

func newTestOPConnectBuilder(client opConnectClient) *opConnectBuilder {
	return &opConnectBuilder{
		clientFor: func(_ context.Context, _, _ string) (opConnectClient, error) {
			return client, nil
		},
		logger: slog.Default(),
	}
}

func sampleItem() *onepassword.Item {
	return &onepassword.Item{
		ID: "item-uuid",
		Fields: []*onepassword.ItemField{
			{ID: "field-uuid", Label: "credential", Value: "real-secret"},
			{ID: "other", Label: "username", Value: "alice"},
			{
				ID:      "section-field-uuid",
				Label:   "api_key",
				Value:   "section-secret",
				Section: &onepassword.ItemSection{ID: "section-uuid", Label: "api"},
			},
		},
	}
}

func sampleVault() *onepassword.Vault {
	return &onepassword.Vault{ID: "vault-uuid", Name: "Engineering"}
}

func TestOPConnectBuilder_HappyPath_DefaultEnvs(t *testing.T) {
	var gotHostEnv, gotTokenEnv string
	r := &opConnectBuilder{
		clientFor: func(_ context.Context, hostEnv, tokenEnv string) (opConnectClient, error) {
			gotHostEnv = hostEnv
			gotTokenEnv = tokenEnv
			return staticOPConnectClient(sampleVault(), sampleItem()), nil
		},
		logger: slog.Default(),
	}

	node := yamlNode(t, map[string]string{
		"type":       "1password_connect",
		"secret_ref": "op://Engineering/OpenAI/credential",
	})
	result, err := r.Build(node)
	require.NoError(t, err)
	require.Equal(t, "op://Engineering/OpenAI/credential", result.Name())

	val, err := result.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "real-secret", val)
	require.Equal(t, "OP_CONNECT_HOST", gotHostEnv)
	require.Equal(t, "OP_CONNECT_TOKEN", gotTokenEnv)
}

func TestOPConnectBuilder_HappyPath_CustomEnvs(t *testing.T) {
	var gotHostEnv, gotTokenEnv string
	r := &opConnectBuilder{
		clientFor: func(_ context.Context, hostEnv, tokenEnv string) (opConnectClient, error) {
			gotHostEnv = hostEnv
			gotTokenEnv = tokenEnv
			return staticOPConnectClient(sampleVault(), sampleItem()), nil
		},
		logger: slog.Default(),
	}

	node := yamlNode(t, map[string]string{
		"type":       "1password_connect",
		"secret_ref": "op://Engineering/OpenAI/credential",
		"host_env":   "MY_CONNECT_HOST",
		"token_env":  "MY_CONNECT_TOKEN",
	})
	result, err := r.Build(node)
	require.NoError(t, err)

	_, err = result.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "MY_CONNECT_HOST", gotHostEnv)
	require.Equal(t, "MY_CONNECT_TOKEN", gotTokenEnv)
}

func TestOPConnectBuilder_PassesParsedRefToClient(t *testing.T) {
	var gotVaultRef, gotItemRef, gotItemVaultRef string
	client := &mockOPConnectClient{
		getVault: func(ref string) (*onepassword.Vault, error) {
			gotVaultRef = ref
			return sampleVault(), nil
		},
		getItem: func(itemRef, vaultRef string) (*onepassword.Item, error) {
			gotItemRef = itemRef
			gotItemVaultRef = vaultRef
			return sampleItem(), nil
		},
	}
	r := newTestOPConnectBuilder(client)
	node := yamlNode(t, map[string]string{
		"type":       "1password_connect",
		"secret_ref": "op://Engineering/OpenAI/credential",
	})
	result, err := r.Build(node)
	require.NoError(t, err)
	_, err = result.Get(context.Background())
	require.NoError(t, err)

	require.Equal(t, "Engineering", gotVaultRef)
	require.Equal(t, "OpenAI", gotItemRef)
	require.Equal(t, "vault-uuid", gotItemVaultRef)
}

// TestOPConnectBuilder_SpecialCharsInRef verifies that vault/item names
// containing characters like spaces and "&" pass through the parser
// unchanged. The Connect SDK handles URL encoding for the API call.
func TestOPConnectBuilder_SpecialCharsInRef(t *testing.T) {
	var gotVaultRef string
	client := &mockOPConnectClient{
		getVault: func(ref string) (*onepassword.Vault, error) {
			gotVaultRef = ref
			return sampleVault(), nil
		},
		getItem: func(string, string) (*onepassword.Item, error) {
			return sampleItem(), nil
		},
	}
	r := newTestOPConnectBuilder(client)
	node := yamlNode(t, map[string]string{
		"type":       "1password_connect",
		"secret_ref": "op://AI Keys & Passwords/OpenAI/credential",
	})
	result, err := r.Build(node)
	require.NoError(t, err)
	_, err = result.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "AI Keys & Passwords", gotVaultRef)
}

func TestOPConnectBuilder_SectionRef(t *testing.T) {
	r := newTestOPConnectBuilder(staticOPConnectClient(sampleVault(), sampleItem()))
	node := yamlNode(t, map[string]string{
		"type":       "1password_connect",
		"secret_ref": "op://Engineering/OpenAI/api/api_key",
	})
	result, err := r.Build(node)
	require.NoError(t, err)
	val, err := result.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "section-secret", val)
}

func TestOPConnectBuilder_TTLReturnsCachedValue(t *testing.T) {
	r := newTestOPConnectBuilder(staticOPConnectClient(sampleVault(), sampleItem()))
	node := yamlNode(t, map[string]string{
		"type":       "1password_connect",
		"secret_ref": "op://Engineering/OpenAI/credential",
		"ttl":        "15m",
	})
	result, err := r.Build(node)
	require.NoError(t, err)
	val, err := result.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "real-secret", val)
}

func TestOPConnectBuilder_Errors(t *testing.T) {
	vaultNotFound := &mockOPConnectClient{
		getVault: func(string) (*onepassword.Vault, error) { return nil, fmt.Errorf("vault not found") },
	}
	itemNotFound := &mockOPConnectClient{
		getVault: func(string) (*onepassword.Vault, error) { return sampleVault(), nil },
		getItem:  func(string, string) (*onepassword.Item, error) { return nil, fmt.Errorf("item not found") },
	}
	emptyItem := staticOPConnectClient(sampleVault(), &onepassword.Item{ID: "item-uuid"})
	emptyValue := staticOPConnectClient(sampleVault(), &onepassword.Item{
		ID: "item-uuid",
		Fields: []*onepassword.ItemField{
			{Label: "credential", Value: ""},
		},
	})

	tests := []struct {
		name   string
		client opConnectClient
		input  map[string]string
		errMsg string
		errAt  string
	}{
		{
			name:   "missing secret_ref",
			input:  map[string]string{"type": "1password_connect"},
			errMsg: "\"secret_ref\" field",
			errAt:  "build",
		},
		{
			name:   "secret_ref without op:// prefix",
			input:  map[string]string{"type": "1password_connect", "secret_ref": "vault/item/field"},
			errMsg: "must start with \"op://\"",
			errAt:  "build",
		},
		{
			name:   "secret_ref too few segments",
			input:  map[string]string{"type": "1password_connect", "secret_ref": "op://v/i"},
			errMsg: "must have 3 or 4 path segments",
			errAt:  "build",
		},
		{
			name:   "secret_ref too many segments",
			input:  map[string]string{"type": "1password_connect", "secret_ref": "op://v/i/s/f/extra"},
			errMsg: "must have 3 or 4 path segments",
			errAt:  "build",
		},
		{
			name:   "secret_ref empty segment",
			input:  map[string]string{"type": "1password_connect", "secret_ref": "op://v//f"},
			errMsg: "empty path segment",
			errAt:  "build",
		},
		{
			name:   "invalid ttl",
			input:  map[string]string{"type": "1password_connect", "secret_ref": "op://v/i/f", "ttl": "not-a-duration"},
			errMsg: "parsing ttl",
			errAt:  "build",
		},
		{
			name:   "vault lookup error",
			client: vaultNotFound,
			input:  map[string]string{"type": "1password_connect", "secret_ref": "op://v/i/f"},
			errMsg: "vault not found",
			errAt:  "fetch",
		},
		{
			name:   "item lookup error",
			client: itemNotFound,
			input:  map[string]string{"type": "1password_connect", "secret_ref": "op://v/i/f"},
			errMsg: "item not found",
			errAt:  "fetch",
		},
		{
			name:   "field not found",
			client: emptyItem,
			input:  map[string]string{"type": "1password_connect", "secret_ref": "op://v/i/credential"},
			errMsg: "field \"credential\" not found",
			errAt:  "fetch",
		},
		{
			name:   "field in section not found",
			client: staticOPConnectClient(sampleVault(), sampleItem()),
			input:  map[string]string{"type": "1password_connect", "secret_ref": "op://v/i/wrong-section/credential"},
			errMsg: "field \"credential\" in section \"wrong-section\" not found",
			errAt:  "fetch",
		},
		{
			name:   "empty value rejected",
			client: emptyValue,
			input:  map[string]string{"type": "1password_connect", "secret_ref": "op://v/i/credential"},
			errMsg: "empty value",
			errAt:  "fetch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newTestOPConnectBuilder(tt.client)
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

func TestParseOPRef(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    opRef
		wantErr string
	}{
		{
			name:  "three segments",
			input: "op://Engineering/OpenAI/credential",
			want:  opRef{vault: "Engineering", item: "OpenAI", field: "credential"},
		},
		{
			name:  "four segments with section",
			input: "op://Engineering/OpenAI/api/key",
			want:  opRef{vault: "Engineering", item: "OpenAI", section: "api", field: "key"},
		},
		{
			name:    "missing op:// prefix",
			input:   "Engineering/OpenAI/credential",
			wantErr: "must start with",
		},
		{
			name:    "one segment",
			input:   "op://Engineering",
			wantErr: "3 or 4 path segments",
		},
		{
			name:    "two segments",
			input:   "op://Engineering/OpenAI",
			wantErr: "3 or 4 path segments",
		},
		{
			name:    "five segments",
			input:   "op://a/b/c/d/e",
			wantErr: "3 or 4 path segments",
		},
		{
			name:    "empty segment",
			input:   "op://a//c",
			wantErr: "empty path segment",
		},
		{
			name:  "literal special chars",
			input: "op://AI Keys & Passwords/OpenAI/credential",
			want:  opRef{vault: "AI Keys & Passwords", item: "OpenAI", field: "credential"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseOPRef(tt.input)
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

func TestSelectField(t *testing.T) {
	item := sampleItem()

	tests := []struct {
		name    string
		ref     opRef
		want    string
		wantErr string
	}{
		{
			name: "match by label",
			ref:  opRef{field: "credential"},
			want: "real-secret",
		},
		{
			name: "match by id",
			ref:  opRef{field: "field-uuid"},
			want: "real-secret",
		},
		{
			name: "match with section label",
			ref:  opRef{section: "api", field: "api_key"},
			want: "section-secret",
		},
		{
			name: "match with section id",
			ref:  opRef{section: "section-uuid", field: "api_key"},
			want: "section-secret",
		},
		{
			name:    "section specified but field has no section",
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
			got, err := selectField(item, tt.ref)
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

// --- opConnectClientCache tests ---

func TestOPConnectClientCache_ReadsHostAndTokenFromEnv(t *testing.T) {
	var gotHost, gotToken string
	cache := &opConnectClientCache{
		clients: make(map[string]opConnectClient),
		getenv: func(key string) string {
			switch key {
			case "MY_HOST":
				return "https://connect.internal"
			case "MY_TOKEN":
				return "tok"
			}
			return ""
		},
		newClient: func(host, token string) opConnectClient {
			gotHost, gotToken = host, token
			return staticOPConnectClient(sampleVault(), sampleItem())
		},
	}

	_, err := cache.get(context.Background(), "MY_HOST", "MY_TOKEN")
	require.NoError(t, err)
	require.Equal(t, "https://connect.internal", gotHost)
	require.Equal(t, "tok", gotToken)
}

func TestOPConnectClientCache_ErrorOnMissingHost(t *testing.T) {
	cache := &opConnectClientCache{
		clients: make(map[string]opConnectClient),
		getenv: func(key string) string {
			if key == "TOK" {
				return "tok"
			}
			return ""
		},
		newClient: func(string, string) opConnectClient { return nil },
	}
	_, err := cache.get(context.Background(), "MISSING_HOST", "TOK")
	require.Error(t, err)
	require.Contains(t, err.Error(), "\"MISSING_HOST\" is not set or empty")
}

func TestOPConnectClientCache_ErrorOnMissingToken(t *testing.T) {
	cache := &opConnectClientCache{
		clients: make(map[string]opConnectClient),
		getenv: func(key string) string {
			if key == "HOST" {
				return "https://connect.internal"
			}
			return ""
		},
		newClient: func(string, string) opConnectClient { return nil },
	}
	_, err := cache.get(context.Background(), "HOST", "MISSING_TOKEN")
	require.Error(t, err)
	require.Contains(t, err.Error(), "\"MISSING_TOKEN\" is not set or empty")
}

func TestOPConnectClientCache_ReusesPerEnvPair(t *testing.T) {
	calls := 0
	cache := &opConnectClientCache{
		clients: make(map[string]opConnectClient),
		getenv:  func(string) string { return "x" },
		newClient: func(string, string) opConnectClient {
			calls++
			return staticOPConnectClient(sampleVault(), sampleItem())
		},
	}

	_, err := cache.get(context.Background(), "H1", "T1")
	require.NoError(t, err)
	_, err = cache.get(context.Background(), "H1", "T1")
	require.NoError(t, err)
	require.Equal(t, 1, calls, "same host/token env pair should reuse the client")

	_, err = cache.get(context.Background(), "H1", "T2")
	require.NoError(t, err)
	require.Equal(t, 2, calls, "different token env should create a new client")

	_, err = cache.get(context.Background(), "H2", "T1")
	require.NoError(t, err)
	require.Equal(t, 3, calls, "different host env should create a new client")
}
