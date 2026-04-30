package secrets

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

// mockOPClient is a configurable mock for the 1Password SDK client.
type mockOPClient struct {
	fn func(ctx context.Context, ref string) (string, error)
}

func (m *mockOPClient) Resolve(ctx context.Context, ref string) (string, error) {
	return m.fn(ctx, ref)
}

// staticOPClient returns an opClient that always returns the given value/error.
func staticOPClient(value string, err error) *mockOPClient {
	return &mockOPClient{fn: func(_ context.Context, _ string) (string, error) {
		return value, err
	}}
}

func newTestOPResolver(client opClient) *opResolver {
	return &opResolver{
		clientFor: func(_ context.Context, _ string) (opClient, error) {
			return client, nil
		},
		logger: slog.Default(),
	}
}

func TestOPResolver_HappyPath_DefaultTokenEnv(t *testing.T) {
	var gotEnv string
	r := &opResolver{
		clientFor: func(_ context.Context, tokenEnv string) (opClient, error) {
			gotEnv = tokenEnv
			return staticOPClient("real-secret", nil), nil
		},
		logger: slog.Default(),
	}

	node := yamlNode(t, map[string]string{
		"type":       "1password",
		"secret_ref": "op://Engineering/OpenAI/credential",
	})
	result, err := r.Resolve(context.Background(), node)
	require.NoError(t, err)
	require.Equal(t, "op://Engineering/OpenAI/credential", result.Name)
	require.Equal(t, "OP_SERVICE_ACCOUNT_TOKEN", gotEnv)

	val, err := result.GetValue(context.Background())
	require.NoError(t, err)
	require.Equal(t, "real-secret", val)
}

func TestOPResolver_HappyPath_CustomTokenEnv(t *testing.T) {
	var gotEnv string
	r := &opResolver{
		clientFor: func(_ context.Context, tokenEnv string) (opClient, error) {
			gotEnv = tokenEnv
			return staticOPClient("custom-token-secret", nil), nil
		},
		logger: slog.Default(),
	}

	node := yamlNode(t, map[string]string{
		"type":       "1password",
		"secret_ref": "op://Engineering/OpenAI/credential",
		"token_env":  "CUSTOM_OP_TOKEN",
	})
	result, err := r.Resolve(context.Background(), node)
	require.NoError(t, err)
	require.Equal(t, "CUSTOM_OP_TOKEN", gotEnv)

	val, err := result.GetValue(context.Background())
	require.NoError(t, err)
	require.Equal(t, "custom-token-secret", val)
}

func TestOPResolver_TTLReturnsCachedValue(t *testing.T) {
	r := newTestOPResolver(staticOPClient("value", nil))
	node := yamlNode(t, map[string]string{
		"type":       "1password",
		"secret_ref": "op://Engineering/OpenAI/credential",
		"ttl":        "15m",
	})
	result, err := r.Resolve(context.Background(), node)
	require.NoError(t, err)

	val, err := result.GetValue(context.Background())
	require.NoError(t, err)
	require.Equal(t, "value", val)
}

func TestOPResolver_PassesSecretRefToClient(t *testing.T) {
	var gotRef string
	client := &mockOPClient{fn: func(_ context.Context, ref string) (string, error) {
		gotRef = ref
		return "v", nil
	}}
	r := newTestOPResolver(client)
	node := yamlNode(t, map[string]string{
		"type":       "1password",
		"secret_ref": "op://vault/item/section/field",
	})
	_, err := r.Resolve(context.Background(), node)
	require.NoError(t, err)
	require.Equal(t, "op://vault/item/section/field", gotRef)
}

func TestOPResolver_Errors(t *testing.T) {
	tests := []struct {
		name   string
		client *mockOPClient
		input  map[string]string
		errMsg string
	}{
		{
			name:   "missing secret_ref",
			client: staticOPClient("", nil),
			input:  map[string]string{"type": "1password"},
			errMsg: "\"secret_ref\" field",
		},
		{
			name:   "secret_ref without op:// prefix",
			client: staticOPClient("", nil),
			input:  map[string]string{"type": "1password", "secret_ref": "vault/item/field"},
			errMsg: "must start with \"op://\"",
		},
		{
			name:   "sdk error",
			client: staticOPClient("", fmt.Errorf("vault not found")),
			input:  map[string]string{"type": "1password", "secret_ref": "op://v/i/f"},
			errMsg: "vault not found",
		},
		{
			name:   "empty secret value",
			client: staticOPClient("", nil),
			input:  map[string]string{"type": "1password", "secret_ref": "op://v/i/f"},
			errMsg: "empty value",
		},
		{
			name:   "invalid ttl",
			client: staticOPClient("v", nil),
			input:  map[string]string{"type": "1password", "secret_ref": "op://v/i/f", "ttl": "not-a-duration"},
			errMsg: "parsing ttl",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newTestOPResolver(tt.client)
			node := yamlNode(t, tt.input)
			_, err := r.Resolve(context.Background(), node)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.errMsg)
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
			return staticOPClient("v", nil), nil
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
			return staticOPClient("v", nil), nil
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
