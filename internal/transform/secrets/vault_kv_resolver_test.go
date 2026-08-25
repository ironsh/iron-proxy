package secrets

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
)

type mockVaultKVClient struct {
	read func(ctx context.Context, mount, secretPath string, version int) (map[string]any, error)
}

func (m mockVaultKVClient) ReadKV(ctx context.Context, mount, secretPath string, version int) (map[string]any, error) {
	return m.read(ctx, mount, secretPath, version)
}

func staticVaultKVClient(data map[string]any, err error) vaultKVClient {
	return &mockVaultKVClient{read: func(context.Context, string, string, int) (map[string]any, error) {
		return data, err
	}}
}

func newTestVaultKVBuilder(client vaultKVClient) *vaultKVBuilder {
	return &vaultKVBuilder{
		clientFor: func(context.Context) (vaultKVClient, error) { return client, nil },
		logger:    slog.Default(),
	}
}

func TestVaultKVBuilder_ReadsKVVersions(t *testing.T) {
	cases := []struct {
		name        string
		configured  int
		wantVersion int
	}{
		{name: "defaults to KV v2", configured: 0, wantVersion: 2},
		{name: "KV v1", configured: 1, wantVersion: 1},
		{name: "KV v2", configured: 2, wantVersion: 2},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := mockVaultKVClient{read: func(_ context.Context, mount, secretPath string, version int) (map[string]any, error) {
				require.Equal(t, "secret", mount)
				require.Equal(t, "services/openai", secretPath)
				require.Equal(t, tc.wantVersion, version)
				return map[string]any{"api_key": "real-value", "region": "us-east-1"}, nil
			}}
			builder := newTestVaultKVBuilder(client)
			node := yamlNode(t, map[string]any{
				"type":       "vault_kv",
				"mount":      "secret",
				"path":       "services/openai",
				"kv_version": tc.configured,
			})

			source, err := builder.Build(node)
			require.NoError(t, err)
			require.Equal(t, "vault_kv:secret/services/openai", source.Name())

			value, err := source.Get(context.Background())
			require.NoError(t, err)
			require.JSONEq(t, `{"api_key":"real-value","region":"us-east-1"}`, value)
		})
	}
}

func TestVaultKVBuilder_JSONKey(t *testing.T) {
	builder := newTestVaultKVBuilder(staticVaultKVClient(map[string]any{
		"api_key": "real-value",
		"ignored": "other-value",
	}, nil))
	node := yamlNode(t, map[string]any{
		"type":     "vault_kv",
		"mount":    "secret",
		"path":     "services/openai",
		"json_key": "api_key",
	})

	source, err := resolveSource(sourceBuilderRegistry{"vault_kv": builder}, node)
	require.NoError(t, err)
	value, err := source.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "real-value", value)
}

func TestVaultKVBuilder_ConfigErrors(t *testing.T) {
	cases := []struct {
		name   string
		input  map[string]any
		errMsg string
	}{
		{
			name:   "missing mount",
			input:  map[string]any{"type": "vault_kv", "path": "services/openai"},
			errMsg: `requires "mount" field`,
		},
		{
			name:   "missing path",
			input:  map[string]any{"type": "vault_kv", "mount": "secret"},
			errMsg: `requires "path" field`,
		},
		{
			name:   "unsupported KV version",
			input:  map[string]any{"type": "vault_kv", "mount": "secret", "path": "app", "kv_version": 3},
			errMsg: "kv_version must be 1 or 2",
		},
		{
			name:   "invalid TTL",
			input:  map[string]any{"type": "vault_kv", "mount": "secret", "path": "app", "ttl": "later"},
			errMsg: "parsing ttl",
		},
		{
			name:   "invalid failure TTL",
			input:  map[string]any{"type": "vault_kv", "mount": "secret", "path": "app", "failure_ttl": "later"},
			errMsg: "parsing failure_ttl",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			builder := newTestVaultKVBuilder(staticVaultKVClient(nil, nil))
			_, err := builder.Build(yamlNode(t, tc.input))
			require.Error(t, err)
			require.ErrorContains(t, err, tc.errMsg)
		})
	}
}

func TestVaultKVBuilder_FetchErrors(t *testing.T) {
	cases := []struct {
		name      string
		clientFor func(context.Context) (vaultKVClient, error)
		errMsg    string
	}{
		{
			name: "client creation",
			clientFor: func(context.Context) (vaultKVClient, error) {
				return nil, fmt.Errorf("bad Vault environment")
			},
			errMsg: "creating Vault client: bad Vault environment",
		},
		{
			name: "read failure",
			clientFor: func(context.Context) (vaultKVClient, error) {
				return staticVaultKVClient(nil, fmt.Errorf("permission denied")), nil
			},
			errMsg: "permission denied",
		},
		{
			name: "missing data",
			clientFor: func(context.Context) (vaultKVClient, error) {
				return staticVaultKVClient(nil, nil), nil
			},
			errMsg: "resolved without data",
		},
		{
			name: "unencodable data",
			clientFor: func(context.Context) (vaultKVClient, error) {
				return staticVaultKVClient(map[string]any{"bad": make(chan int)}, nil), nil
			},
			errMsg: "encoding Vault KV secret",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			builder := &vaultKVBuilder{clientFor: tc.clientFor, logger: slog.Default()}
			source, err := builder.Build(yamlNode(t, map[string]any{
				"type": "vault_kv", "mount": "secret", "path": "app",
			}))
			require.NoError(t, err)
			_, err = source.Get(context.Background())
			require.Error(t, err)
			require.ErrorContains(t, err, tc.errMsg)
		})
	}
}

func TestVaultKVBuilder_BuildIsLazy(t *testing.T) {
	var calls atomic.Int64
	builder := &vaultKVBuilder{
		clientFor: func(context.Context) (vaultKVClient, error) {
			calls.Add(1)
			return staticVaultKVClient(map[string]any{"value": "secret"}, nil), nil
		},
		logger: slog.Default(),
	}
	source, err := builder.Build(yamlNode(t, map[string]any{
		"type": "vault_kv", "mount": "secret", "path": "app",
	}))
	require.NoError(t, err)
	require.Equal(t, int64(0), calls.Load())

	_, err = source.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, int64(1), calls.Load())
}

func TestVaultKVClientCache_ReusesClient(t *testing.T) {
	var calls atomic.Int64
	want := staticVaultKVClient(map[string]any{"value": "secret"}, nil)
	cache := &vaultKVClientCache{newClient: func() (vaultKVClient, error) {
		calls.Add(1)
		return want, nil
	}}

	first, err := cache.get(context.Background())
	require.NoError(t, err)
	second, err := cache.get(context.Background())
	require.NoError(t, err)
	require.Same(t, want, first)
	require.Same(t, want, second)
	require.Equal(t, int64(1), calls.Load())
}

func TestVaultKVBuilder_OfficialClientEnvironment(t *testing.T) {
	type requestRecord struct {
		path      string
		token     string
		namespace string
	}
	requests := make(chan requestRecord, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- requestRecord{
			path:      r.URL.Path,
			token:     r.Header.Get("X-Vault-Token"),
			namespace: r.Header.Get("X-Vault-Namespace"),
		}
		w.Header().Set("Content-Type", "application/json")
		// The test server and response writer are in-memory; a write failure is
		// irrelevant because the client call below reports it as a read error.
		if r.URL.Path == "/v1/secret/legacy/openai" {
			_, _ = io.WriteString(w, `{"data":{"api_key":"kv1-value"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"data":{"api_key":"kv2-value"},"metadata":{}}}`)
	}))
	t.Cleanup(server.Close)

	// Clear endpoint overrides that may be present in a developer's shell, then
	// set the standard environment consumed by vault/api.NewClient.
	t.Setenv(vaultapi.EnvVaultAgentAddr, "")
	t.Setenv(vaultapi.EnvVaultProxyAddr, "")
	t.Setenv(vaultapi.EnvVaultCACert, "")
	t.Setenv(vaultapi.EnvVaultCAPath, "")
	t.Setenv(vaultapi.EnvVaultClientCert, "")
	t.Setenv(vaultapi.EnvVaultClientKey, "")
	t.Setenv(vaultapi.EnvVaultAddress, server.URL)
	t.Setenv(vaultapi.EnvVaultToken, "test-token")
	t.Setenv(vaultapi.EnvVaultNamespace, "engineering")

	cases := []struct {
		name        string
		path        string
		version     int
		wantValue   string
		wantAPIPath string
	}{
		{name: "KV v1", path: "legacy/openai", version: 1, wantValue: "kv1-value", wantAPIPath: "/v1/secret/legacy/openai"},
		{name: "KV v2", path: "services/openai", version: 2, wantValue: "kv2-value", wantAPIPath: "/v1/secret/data/services/openai"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			node := yamlNode(t, map[string]any{
				"type": "vault_kv", "mount": "secret", "path": tc.path, "kv_version": tc.version, "json_key": "api_key",
			})
			source, err := resolveSource(defaultRegistry(slog.Default()), node)
			require.NoError(t, err)
			value, err := source.Get(context.Background())
			require.NoError(t, err)
			require.Equal(t, tc.wantValue, value)

			record := <-requests
			require.Equal(t, tc.wantAPIPath, record.path)
			require.Equal(t, "test-token", record.token)
			require.Equal(t, "engineering", record.namespace)
		})
	}
}
