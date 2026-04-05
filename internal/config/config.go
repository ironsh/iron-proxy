// Package config handles parsing and validation of iron-proxy's YAML configuration.
package config

import (
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration for iron-proxy.
type Config struct {
	DNS        DNS        `yaml:"dns"`
	Proxy      Proxy      `yaml:"proxy"`
	TLS        TLS        `yaml:"tls"`
	Transforms []Transform `yaml:"transforms"`
	Metrics    Metrics    `yaml:"metrics"`
	Log        Log        `yaml:"log"`
}

// DNS configures the built-in DNS server.
type DNS struct {
	Listen           string      `yaml:"listen"`
	ProxyIP          string      `yaml:"proxy_ip"`
	UpstreamResolver string      `yaml:"upstream_resolver"`
	Passthrough      []string    `yaml:"passthrough"`
	Records          []DNSRecord `yaml:"records"`
}

// DNSRecord is a static DNS record entry.
type DNSRecord struct {
	Name  string `yaml:"name"`
	Type  string `yaml:"type"`
	Value string `yaml:"value"`
}

// Proxy configures the HTTP/HTTPS listener addresses.
type Proxy struct {
	HTTPListen           string `yaml:"http_listen"`
	HTTPSListen          string `yaml:"https_listen"`
	MaxRequestBodyBytes  int64  `yaml:"max_request_body_bytes"`
	MaxResponseBodyBytes int64  `yaml:"max_response_body_bytes"`
}

// TLS configures certificate authority and cert caching for MITM.
type TLS struct {
	CACert             string `yaml:"ca_cert"`
	CAKey              string `yaml:"ca_key"`
	CertCacheSize      int    `yaml:"cert_cache_size"`
	LeafCertExpiryHours int   `yaml:"leaf_cert_expiry_hours"`
}

// Transform is a named transform with arbitrary config.
// Config is a raw yaml.Node so each transform can decode it into its own typed struct.
type Transform struct {
	Name   string    `yaml:"name"`
	Config yaml.Node `yaml:"config"`
}

// Metrics configures the OpenTelemetry/Prometheus metrics endpoint.
type Metrics struct {
	Listen string `yaml:"listen"`
}

// Log configures structured logging.
type Log struct {
	Level string `yaml:"level"`
}

// LoadFile reads and parses a YAML config from the given path. If the path is
// an S3 URL (s3://bucket/key), the config is fetched from S3 using the default
// AWS credential chain.
func LoadFile(path string) (*Config, error) {
	return loadFileOrS3(path)
}

// loadFromFile reads and parses a YAML config file from a local filesystem path.
func loadFromFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening config file: %w", err)
	}
	defer f.Close()

	return Load(f)
}

// Load parses a YAML config from the given reader and applies defaults.
func Load(r io.Reader) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	applyDefaults(&cfg)

	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return &cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.DNS.Listen == "" {
		cfg.DNS.Listen = ":53"
	}
	if cfg.Proxy.HTTPListen == "" {
		cfg.Proxy.HTTPListen = ":80"
	}
	if cfg.Proxy.HTTPSListen == "" {
		cfg.Proxy.HTTPSListen = ":443"
	}
	if cfg.Proxy.MaxRequestBodyBytes == 0 {
		cfg.Proxy.MaxRequestBodyBytes = 1 << 20 // 1 MiB
	}
	// MaxResponseBodyBytes defaults to 0 (uncapped).
	if cfg.TLS.CertCacheSize == 0 {
		cfg.TLS.CertCacheSize = 1000
	}
	if cfg.TLS.LeafCertExpiryHours == 0 {
		cfg.TLS.LeafCertExpiryHours = 72
	}
	if cfg.Metrics.Listen == "" {
		cfg.Metrics.Listen = ":9090"
	}
	if cfg.Log.Level == "" {
		cfg.Log.Level = "info"
	}
}

func validate(cfg *Config) error {
	if cfg.DNS.ProxyIP == "" {
		return fmt.Errorf("dns.proxy_ip is required")
	}
	if cfg.TLS.CACert == "" {
		return fmt.Errorf("tls.ca_cert is required")
	}
	if cfg.TLS.CAKey == "" {
		return fmt.Errorf("tls.ca_key is required")
	}

	if _, err := parseLogLevel(cfg.Log.Level); err != nil {
		return fmt.Errorf("log.level: %w", err)
	}

	for i, rec := range cfg.DNS.Records {
		if rec.Name == "" {
			return fmt.Errorf("dns.records[%d].name is required", i)
		}
		validTypes := map[string]bool{"A": true, "CNAME": true}
		if !validTypes[rec.Type] {
			return fmt.Errorf("dns.records[%d].type must be A or CNAME; got %q", i, rec.Type)
		}
		if rec.Value == "" {
			return fmt.Errorf("dns.records[%d].value is required", i)
		}
	}

	return nil
}
