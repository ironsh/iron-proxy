package config

import (
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func loadYAML(t *testing.T, src string) (*Config, error) {
	t.Helper()
	return Load(strings.NewReader(src))
}

func TestLoadAppliesDefaults(t *testing.T) {
	cfg, err := loadYAML(t, `
credentials:
  - id: example
    token_endpoint: https://idp.example/oauth/token
    client_id:
      type: env
      var: EXAMPLE_CLIENT_ID
    store:
      type: file
      path: /tmp/example.json
`)
	require.NoError(t, err)
	require.Equal(t, ":8181", cfg.Listen)
	require.Equal(t, ":9091", cfg.MetricsListen)
	require.Equal(t, "info", cfg.Log.Level)
	require.Equal(t, "text", cfg.Log.Format)
	require.Equal(t, 24*time.Hour, time.Duration(cfg.Defaults.MaxRefreshInterval))
}

func TestLoadRejectsDuplicateID(t *testing.T) {
	_, err := loadYAML(t, `
credentials:
  - id: dup
    token_endpoint: https://a
    client_id: {type: env, var: X}
    store: {type: file, path: /tmp/a.json}
  - id: dup
    token_endpoint: https://b
    client_id: {type: env, var: Y}
    store: {type: file, path: /tmp/b.json}
`)
	require.Error(t, err)
	require.Contains(t, err.Error(), "duplicate id")
}

func TestLoadRequiresTokenEndpoint(t *testing.T) {
	_, err := loadYAML(t, `
credentials:
  - id: x
    client_id: {type: env, var: X}
    store: {type: file, path: /tmp/x.json}
`)
	require.Error(t, err)
	require.Contains(t, err.Error(), "token_endpoint")
}

func TestLoadRejectsUnknownField(t *testing.T) {
	_, err := loadYAML(t, `
not_a_field: oops
credentials: []
`)
	require.Error(t, err)
}

func TestBuildCredentialsResolvesSources(t *testing.T) {
	t.Setenv("EXAMPLE_CLIENT_ID", "client-A")
	cfg, err := loadYAML(t, `
credentials:
  - id: example
    token_endpoint: https://idp.example/oauth/token
    early_refresh_slack: "10m"
    client_id:
      type: env
      var: EXAMPLE_CLIENT_ID
    store:
      type: file
      path: `+filepath.Join(t.TempDir(), "creds.json")+`
`)
	require.NoError(t, err)
	built, err := BuildCredentials(cfg, slog.Default())
	require.NoError(t, err)
	require.Len(t, built, 1)
	require.Equal(t, "example", built[0].ID)
	require.Equal(t, 10*time.Minute, built[0].EarlyRefreshSlack)
	// Default ceiling carries through when the credential doesn't override.
	require.Equal(t, 24*time.Hour, built[0].MaxRefreshInterval)

	val, err := built[0].ClientID.Get(t.Context())
	require.NoError(t, err)
	require.Equal(t, "client-A", val)
}

func TestLoadRejectsNegativePerCredentialOverrides(t *testing.T) {
	for _, tc := range []struct {
		name  string
		field string
	}{
		{"refresh_timeout", "refresh_timeout: -1s"},
		{"max_refresh_interval", "max_refresh_interval: -1h"},
		{"early_refresh_slack", "early_refresh_slack: -5m"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadYAML(t, `
credentials:
  - id: example
    token_endpoint: https://idp.example
    client_id: {type: env, var: X}
    store: {type: file, path: /tmp/x.json}
    `+tc.field+`
`)
			require.Error(t, err)
			require.Contains(t, err.Error(), "non-negative")
		})
	}
}

func TestParseLogLevel(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error"} {
		_, err := ParseLogLevel(level)
		require.NoError(t, err, level)
	}
	_, err := ParseLogLevel("unknown")
	require.Error(t, err)
}
