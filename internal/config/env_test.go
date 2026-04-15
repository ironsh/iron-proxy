package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadConfig_EnvOnly_Defaults(t *testing.T) {
	setEnvs(t, map[string]string{
		"IRON_DNS_PROXY_IP": "127.0.0.1",
		"IRON_TLS_CA_CERT":  "/ca.pem",
		"IRON_TLS_CA_KEY":   "/ca-key.pem",
	})

	cfg, err := LoadConfig("")
	require.NoError(t, err)

	require.Equal(t, ":53", cfg.DNS.Listen)
	require.Equal(t, "127.0.0.1", cfg.DNS.ProxyIP)
	require.Equal(t, "", cfg.DNS.UpstreamResolver)
	require.Equal(t, ":80", cfg.Proxy.HTTPListen)
	require.Equal(t, ":443", cfg.Proxy.HTTPSListen)
	require.Equal(t, "", cfg.Proxy.TunnelListen)
	require.Equal(t, int64(1<<20), cfg.Proxy.MaxRequestBodyBytes)
	require.Equal(t, int64(0), cfg.Proxy.MaxResponseBodyBytes)
	require.Equal(t, "/ca.pem", cfg.TLS.CACert)
	require.Equal(t, "/ca-key.pem", cfg.TLS.CAKey)
	require.Equal(t, 1000, cfg.TLS.CertCacheSize)
	require.Equal(t, 72, cfg.TLS.LeafCertExpiryHours)
	require.Equal(t, ":9090", cfg.Metrics.Listen)
	require.Equal(t, "info", cfg.Log.Level)
	require.Empty(t, cfg.Transforms)
}

func TestLoadConfig_EnvOnly_AllOverrides(t *testing.T) {
	setEnvs(t, map[string]string{
		"IRON_DNS_LISTEN":                    ":5353",
		"IRON_DNS_PROXY_IP":                  "10.0.0.1",
		"IRON_DNS_UPSTREAM_RESOLVER":         "8.8.8.8:53",
		"IRON_PROXY_HTTP_LISTEN":             ":8080",
		"IRON_PROXY_HTTPS_LISTEN":            ":8443",
		"IRON_PROXY_TUNNEL_LISTEN":           ":1080",
		"IRON_PROXY_MAX_REQUEST_BODY_BYTES":  "2097152",
		"IRON_PROXY_MAX_RESPONSE_BODY_BYTES": "4194304",
		"IRON_TLS_CA_CERT":                   "/custom/ca.pem",
		"IRON_TLS_CA_KEY":                    "/custom/ca-key.pem",
		"IRON_TLS_CERT_CACHE_SIZE":           "500",
		"IRON_TLS_LEAF_CERT_EXPIRY_HOURS":    "24",
		"IRON_METRICS_LISTEN":                ":2112",
		"IRON_LOG_LEVEL":                     "debug",
	})

	cfg, err := LoadConfig("")
	require.NoError(t, err)

	require.Equal(t, ":5353", cfg.DNS.Listen)
	require.Equal(t, "10.0.0.1", cfg.DNS.ProxyIP)
	require.Equal(t, "8.8.8.8:53", cfg.DNS.UpstreamResolver)
	require.Equal(t, ":8080", cfg.Proxy.HTTPListen)
	require.Equal(t, ":8443", cfg.Proxy.HTTPSListen)
	require.Equal(t, ":1080", cfg.Proxy.TunnelListen)
	require.Equal(t, int64(2097152), cfg.Proxy.MaxRequestBodyBytes)
	require.Equal(t, int64(4194304), cfg.Proxy.MaxResponseBodyBytes)
	require.Equal(t, "/custom/ca.pem", cfg.TLS.CACert)
	require.Equal(t, "/custom/ca-key.pem", cfg.TLS.CAKey)
	require.Equal(t, 500, cfg.TLS.CertCacheSize)
	require.Equal(t, 24, cfg.TLS.LeafCertExpiryHours)
	require.Equal(t, ":2112", cfg.Metrics.Listen)
	require.Equal(t, "debug", cfg.Log.Level)
}

func TestLoadConfig_EnvOnly_InvalidIntegers(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		value   string
		wantErr string
	}{
		{
			name:    "bad max_request_body_bytes",
			key:     "IRON_PROXY_MAX_REQUEST_BODY_BYTES",
			value:   "notanumber",
			wantErr: "IRON_PROXY_MAX_REQUEST_BODY_BYTES",
		},
		{
			name:    "bad max_response_body_bytes",
			key:     "IRON_PROXY_MAX_RESPONSE_BODY_BYTES",
			value:   "abc",
			wantErr: "IRON_PROXY_MAX_RESPONSE_BODY_BYTES",
		},
		{
			name:    "bad cert_cache_size",
			key:     "IRON_TLS_CERT_CACHE_SIZE",
			value:   "xyz",
			wantErr: "IRON_TLS_CERT_CACHE_SIZE",
		},
		{
			name:    "bad leaf_cert_expiry_hours",
			key:     "IRON_TLS_LEAF_CERT_EXPIRY_HOURS",
			value:   "1.5",
			wantErr: "IRON_TLS_LEAF_CERT_EXPIRY_HOURS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setEnvs(t, map[string]string{
				tt.key: tt.value,
			})

			_, err := LoadConfig("")
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestLoadConfig_FileWithEnvOverrides(t *testing.T) {
	// Write a config file, then override some values via env.
	cfgFile := t.TempDir() + "/proxy.yaml"
	writeFile(t, cfgFile, `
dns:
  proxy_ip: "10.0.0.1"
proxy:
  http_listen: ":8080"
  https_listen: ":8443"
tls:
  ca_cert: "/file/ca.crt"
  ca_key: "/file/ca.key"
log:
  level: "debug"
`)

	// Override proxy_ip and ca_cert via env.
	setEnvs(t, map[string]string{
		"IRON_DNS_PROXY_IP": "10.0.0.99",
		"IRON_TLS_CA_CERT":  "/env/ca.crt",
	})

	cfg, err := LoadConfig(cfgFile)
	require.NoError(t, err)

	// Overridden by env.
	require.Equal(t, "10.0.0.99", cfg.DNS.ProxyIP)
	require.Equal(t, "/env/ca.crt", cfg.TLS.CACert)

	// From file (env was empty).
	require.Equal(t, ":8080", cfg.Proxy.HTTPListen)
	require.Equal(t, ":8443", cfg.Proxy.HTTPSListen)
	require.Equal(t, "/file/ca.key", cfg.TLS.CAKey)
	require.Equal(t, "debug", cfg.Log.Level)
}

func TestApplyEnvOverrides_OnlyOverridesSetVars(t *testing.T) {
	setEnvs(t, map[string]string{
		"IRON_DNS_PROXY_IP":      "10.0.0.99",
		"IRON_PROXY_HTTP_LISTEN": ":9090",
	})

	cfg := Config{
		DNS: DNS{
			Listen:  ":5353",
			ProxyIP: "10.0.0.1",
		},
		Proxy: Proxy{
			HTTPListen:  ":80",
			HTTPSListen: ":443",
		},
		TLS: TLS{
			CACert: "/original/ca.crt",
			CAKey:  "/original/ca.key",
		},
		Log: Log{
			Level: "debug",
		},
	}

	err := applyEnvOverrides(&cfg)
	require.NoError(t, err)

	// Overridden by env vars.
	require.Equal(t, "10.0.0.99", cfg.DNS.ProxyIP)
	require.Equal(t, ":9090", cfg.Proxy.HTTPListen)

	// Not overridden: env vars were empty.
	require.Equal(t, ":5353", cfg.DNS.Listen)
	require.Equal(t, ":443", cfg.Proxy.HTTPSListen)
	require.Equal(t, "/original/ca.crt", cfg.TLS.CACert)
	require.Equal(t, "/original/ca.key", cfg.TLS.CAKey)
	require.Equal(t, "debug", cfg.Log.Level)
}

func TestApplyEnvOverrides_IntegerFields(t *testing.T) {
	setEnvs(t, map[string]string{
		"IRON_PROXY_MAX_REQUEST_BODY_BYTES": "5242880",
		"IRON_TLS_CERT_CACHE_SIZE":          "2000",
		"IRON_TLS_LEAF_CERT_EXPIRY_HOURS":   "48",
	})

	cfg := Config{
		Proxy: Proxy{
			MaxRequestBodyBytes: 1024,
		},
		TLS: TLS{
			CertCacheSize:       500,
			LeafCertExpiryHours: 24,
		},
	}

	err := applyEnvOverrides(&cfg)
	require.NoError(t, err)

	require.Equal(t, int64(5242880), cfg.Proxy.MaxRequestBodyBytes)
	require.Equal(t, 2000, cfg.TLS.CertCacheSize)
	require.Equal(t, 48, cfg.TLS.LeafCertExpiryHours)
}

func TestApplyEnvOverrides_InvalidInteger(t *testing.T) {
	setEnvs(t, map[string]string{
		"IRON_PROXY_MAX_REQUEST_BODY_BYTES": "notanumber",
	})

	var cfg Config
	err := applyEnvOverrides(&cfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "IRON_PROXY_MAX_REQUEST_BODY_BYTES")
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

// setEnvs sets environment variables for the duration of the test, clearing
// all IRON_* env vars first to ensure a clean slate.
func setEnvs(t *testing.T, envs map[string]string) {
	t.Helper()

	// Clear all IRON_* env vars to prevent cross-test leakage.
	ironKeys := []string{
		"IRON_DNS_LISTEN",
		"IRON_DNS_PROXY_IP",
		"IRON_DNS_UPSTREAM_RESOLVER",
		"IRON_PROXY_HTTP_LISTEN",
		"IRON_PROXY_HTTPS_LISTEN",
		"IRON_PROXY_TUNNEL_LISTEN",
		"IRON_PROXY_MAX_REQUEST_BODY_BYTES",
		"IRON_PROXY_MAX_RESPONSE_BODY_BYTES",
		"IRON_TLS_CA_CERT",
		"IRON_TLS_CA_KEY",
		"IRON_TLS_CERT_CACHE_SIZE",
		"IRON_TLS_LEAF_CERT_EXPIRY_HOURS",
		"IRON_METRICS_LISTEN",
		"IRON_LOG_LEVEL",
	}
	for _, k := range ironKeys {
		t.Setenv(k, "")
	}

	for k, v := range envs {
		t.Setenv(k, v)
	}
}
