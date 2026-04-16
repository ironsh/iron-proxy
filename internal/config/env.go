package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// applyEnvOverrides layers IRON_* environment variables on top of an existing
// Config. Only non-empty environment variables override the corresponding field.
func applyEnvOverrides(cfg *Config) error {
	if v := os.Getenv("IRON_DNS_LISTEN"); v != "" {
		cfg.DNS.Listen = v
	}
	if v := os.Getenv("IRON_DNS_PROXY_IP"); v != "" {
		cfg.DNS.ProxyIP = v
	}
	if v := os.Getenv("IRON_DNS_UPSTREAM_RESOLVER"); v != "" {
		cfg.DNS.UpstreamResolver = v
	}
	if v := os.Getenv("IRON_PROXY_HTTP_LISTEN"); v != "" {
		cfg.Proxy.HTTPListen = v
	}
	if v := os.Getenv("IRON_PROXY_HTTPS_LISTEN"); v != "" {
		cfg.Proxy.HTTPSListen = v
	}
	if v := os.Getenv("IRON_PROXY_TUNNEL_LISTEN"); v != "" {
		cfg.Proxy.TunnelListen = v
	}
	if v := os.Getenv("IRON_TLS_CA_CERT"); v != "" {
		cfg.TLS.CACert = v
	}
	if v := os.Getenv("IRON_TLS_CA_KEY"); v != "" {
		cfg.TLS.CAKey = v
	}
	if v := os.Getenv("IRON_METRICS_LISTEN"); v != "" {
		cfg.Metrics.Listen = v
	}
	if v := os.Getenv("IRON_LOG_LEVEL"); v != "" {
		cfg.Log.Level = v
	}
	if v := os.Getenv("IRON_TAGS"); v != "" {
		tags := make([]string, 0)
		for _, t := range strings.Split(v, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				tags = append(tags, t)
			}
		}
		cfg.Tags = tags
	}

	if v := os.Getenv("IRON_PROXY_MAX_REQUEST_BODY_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("IRON_PROXY_MAX_REQUEST_BODY_BYTES: %w", err)
		}
		cfg.Proxy.MaxRequestBodyBytes = n
	}

	if v := os.Getenv("IRON_PROXY_MAX_RESPONSE_BODY_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("IRON_PROXY_MAX_RESPONSE_BODY_BYTES: %w", err)
		}
		cfg.Proxy.MaxResponseBodyBytes = n
	}

	if v := os.Getenv("IRON_TLS_CERT_CACHE_SIZE"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("IRON_TLS_CERT_CACHE_SIZE: %w", err)
		}
		cfg.TLS.CertCacheSize = n
	}

	if v := os.Getenv("IRON_TLS_LEAF_CERT_EXPIRY_HOURS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("IRON_TLS_LEAF_CERT_EXPIRY_HOURS: %w", err)
		}
		cfg.TLS.LeafCertExpiryHours = n
	}

	return nil
}
