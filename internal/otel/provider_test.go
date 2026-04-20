package otel

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExportConfigEnabled(t *testing.T) {
	t.Run("disabled when no endpoint", func(t *testing.T) {
		t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
		t.Setenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "")
		require.False(t, ExportConfig{}.Enabled())
	})

	t.Run("enabled via default endpoint", func(t *testing.T) {
		t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
		t.Setenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "")
		cfg := ExportConfig{DefaultEndpoint: "https://ingest.iron.sh"}
		require.True(t, cfg.Enabled())
	})

	t.Run("enabled via env endpoint", func(t *testing.T) {
		t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://example.com")
		require.True(t, ExportConfig{}.Enabled())
	})

	t.Run("enabled via logs-specific env endpoint", func(t *testing.T) {
		t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
		t.Setenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "https://example.com")
		require.True(t, ExportConfig{}.Enabled())
	})
}

func TestHTTPOptionsUsesDefaultsWhenEnvUnset(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "")
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_HEADERS", "")

	cfg := ExportConfig{
		DefaultEndpoint: "https://ingest.iron.sh",
		DefaultHeaders:  map[string]string{"Authorization": "Bearer t"},
	}
	// Both defaults should produce options.
	require.Len(t, httpOptions(cfg), 2)
	require.Len(t, grpcOptions(cfg), 2)
}

func TestHTTPOptionsOmittedWhenEnvSet(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://env-endpoint.example")
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "X-Token=from-env")

	cfg := ExportConfig{
		DefaultEndpoint: "https://ingest.iron.sh",
		DefaultHeaders:  map[string]string{"Authorization": "Bearer t"},
	}
	// Env takes precedence; no options should be generated so the SDK reads env.
	require.Empty(t, httpOptions(cfg))
	require.Empty(t, grpcOptions(cfg))
}

func TestHTTPOptionsMixedPrecedence(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://env-endpoint.example")
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "")
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_HEADERS", "")

	cfg := ExportConfig{
		DefaultEndpoint: "https://ingest.iron.sh",
		DefaultHeaders:  map[string]string{"Authorization": "Bearer t"},
	}
	// Endpoint comes from env; headers use the default.
	require.Len(t, httpOptions(cfg), 1)
	require.Len(t, grpcOptions(cfg), 1)
}
