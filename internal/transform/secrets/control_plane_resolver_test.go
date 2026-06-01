package secrets

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestControlPlaneSourceReturnsStaticValue(t *testing.T) {
	registry := defaultRegistry(slog.Default())
	src, err := resolveSource(registry, yamlNode(t, map[string]any{
		"type":  "control_plane",
		"value": "super-secret",
	}))
	require.NoError(t, err)
	require.Equal(t, "control_plane", src.Name())

	got, err := src.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "super-secret", got)
}

func TestControlPlaneSourceRequiresValue(t *testing.T) {
	registry := defaultRegistry(slog.Default())
	_, err := resolveSource(registry, yamlNode(t, map[string]any{
		"type": "control_plane",
	}))
	require.Error(t, err)
	require.Contains(t, err.Error(), "requires \"value\" field")
}

func TestControlPlaneSourceWithJSONKey(t *testing.T) {
	registry := defaultRegistry(slog.Default())
	src, err := resolveSource(registry, yamlNode(t, map[string]any{
		"type":     "control_plane",
		"value":    `{"api_key":"abc123"}`,
		"json_key": "api_key",
	}))
	require.NoError(t, err)

	got, err := src.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "abc123", got)
}
