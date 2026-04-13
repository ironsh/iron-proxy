package config

import (
	"fmt"
	"os"
	"strconv"
)

// FromEnv builds a Config by reading IRON_* environment variables.
// String fields are read directly; integer fields are parsed with descriptive
// errors. After reading, applyDefaults and validate are called just like the
// YAML path. The Transforms slice is always empty (transforms come from the
// control plane in managed mode).
func FromEnv() (*Config, error) {
	cfg := Config{
		DNS: DNS{
			Listen:           os.Getenv("IRON_DNS_LISTEN"),
			ProxyIP:          os.Getenv("IRON_DNS_PROXY_IP"),
			UpstreamResolver: os.Getenv("IRON_DNS_UPSTREAM_RESOLVER"),
		},
		Proxy: Proxy{
			HTTPListen:   os.Getenv("IRON_PROXY_HTTP_LISTEN"),
			HTTPSListen:  os.Getenv("IRON_PROXY_HTTPS_LISTEN"),
			TunnelListen: os.Getenv("IRON_PROXY_TUNNEL_LISTEN"),
		},
		TLS: TLS{
			CACert: os.Getenv("IRON_TLS_CA_CERT"),
			CAKey:  os.Getenv("IRON_TLS_CA_KEY"),
		},
		Metrics: Metrics{
			Listen: os.Getenv("IRON_METRICS_LISTEN"),
		},
		Log: Log{
			Level: os.Getenv("IRON_LOG_LEVEL"),
		},
	}

	if v := os.Getenv("IRON_PROXY_MAX_REQUEST_BODY_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("IRON_PROXY_MAX_REQUEST_BODY_BYTES: %w", err)
		}
		cfg.Proxy.MaxRequestBodyBytes = n
	}

	if v := os.Getenv("IRON_PROXY_MAX_RESPONSE_BODY_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("IRON_PROXY_MAX_RESPONSE_BODY_BYTES: %w", err)
		}
		cfg.Proxy.MaxResponseBodyBytes = n
	}

	if v := os.Getenv("IRON_TLS_CERT_CACHE_SIZE"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("IRON_TLS_CERT_CACHE_SIZE: %w", err)
		}
		cfg.TLS.CertCacheSize = n
	}

	if v := os.Getenv("IRON_TLS_LEAF_CERT_EXPIRY_HOURS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("IRON_TLS_LEAF_CERT_EXPIRY_HOURS: %w", err)
		}
		cfg.TLS.LeafCertExpiryHours = n
	}

	applyDefaults(&cfg)

	if err := validate(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
