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
			return staticOPClient("real-secret", nil), nil
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
			return staticOPClient("custom-token-secret", nil), nil
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
	require.Equal(t, "custom-token-secret", val)
	require.Equal(t, "CUSTOM_OP_TOKEN", gotEnv)
}

func TestOPBuilder_TTLReturnsCachedValue(t *testing.T) {
	r := newTestOPBuilder(staticOPClient("value", nil))
	node := yamlNode(t, map[string]string{
		"type":       "1password",
		"secret_ref": "op://Engineering/OpenAI/credential",
		"ttl":        "15m",
	})
	result, err := r.Build(node)
	require.NoError(t, err)

	val, err := result.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "value", val)
}

func TestOPBuilder_PassesSecretRefToClient(t *testing.T) {
	var gotRef string
	client := &mockOPClient{fn: func(_ context.Context, ref string) (string, error) {
		gotRef = ref
		return "v", nil
	}}
	r := newTestOPBuilder(client)
	node := yamlNode(t, map[string]string{
		"type":       "1password",
		"secret_ref": "op://vault/item/section/field",
	})
	result, err := r.Build(node)
	require.NoError(t, err)
	_, err = result.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "op://vault/item/section/field", gotRef)
}

func TestOPBuilder_Errors(t *testing.T) {
	tests := []struct {
		name   string
		client *mockOPClient
		input  map[string]string
		errMsg string
		errAt  string
	}{
		{
			name:   "missing secret_ref",
			client: staticOPClient("", nil),
			input:  map[string]string{"type": "1password"},
			errMsg: "\"secret_ref\" field",
			errAt:  "build",
		},
		{
			name:   "secret_ref without op:// prefix",
			client: staticOPClient("", nil),
			input:  map[string]string{"type": "1password", "secret_ref": "vault/item/field"},
			errMsg: "must start with \"op://\"",
			errAt:  "build",
		},
		{
			name:   "invalid ttl",
			client: staticOPClient("v", nil),
			input:  map[string]string{"type": "1password", "secret_ref": "op://v/i/f", "ttl": "not-a-duration"},
			errMsg: "parsing ttl",
			errAt:  "build",
		},
		{
			name:   "sdk error",
			client: staticOPClient("", fmt.Errorf("vault not found")),
			input:  map[string]string{"type": "1password", "secret_ref": "op://v/i/f"},
			errMsg: "vault not found",
			errAt:  "fetch",
		},
		{
			name:   "empty secret value",
			client: staticOPClient("", nil),
			input:  map[string]string{"type": "1password", "secret_ref": "op://v/i/f"},
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
