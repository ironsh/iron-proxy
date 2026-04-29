// Package config handles parsing and validation of iron-proxy's YAML configuration.
package config

import (
	"fmt"
	"io"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultUpstreamResponseHeaderTimeout is applied when the policy does not
// set proxy.upstream_response_header_timeout. It matches the historical
// hard-coded value so existing configurations behave unchanged.
const DefaultUpstreamResponseHeaderTimeout = 30 * time.Second

// Config is the top-level configuration for iron-proxy.
type Config struct {
	DNS        DNS         `yaml:"dns"`
	Proxy      Proxy       `yaml:"proxy"`
	TLS        TLS         `yaml:"tls"`
	Transforms []Transform `yaml:"transforms"`
	Metrics    Metrics     `yaml:"metrics"`
	Log        Log         `yaml:"log"`
	Tags       []string    `yaml:"tags"`
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
	TunnelListen         string `yaml:"tunnel_listen"`
	MaxRequestBodyBytes  int64  `yaml:"max_request_body_bytes"`
	MaxResponseBodyBytes int64  `yaml:"max_response_body_bytes"`
	// UpstreamResponseHeaderTimeout caps how long the proxy waits for an
	// upstream response's headers before returning 502. Accepts Go duration
	// syntax: "30s" (default), "5m", "2h". Useful for upstream endpoints
	// (e.g. LLM context compaction) that legitimately take longer than the
	// 30-second default to begin replying.
	UpstreamResponseHeaderTimeout string `yaml:"upstream_response_header_timeout"`
}

// UpstreamResponseHeaderTimeoutDuration returns the parsed duration for the
// upstream response-header timeout, falling back to
// DefaultUpstreamResponseHeaderTimeout when the field is empty. Validate
// rejects invalid values up front, so this is safe to call on validated
// configs.
func (p Proxy) UpstreamResponseHeaderTimeoutDuration() time.Duration {
	if p.UpstreamResponseHeaderTimeout == "" {
		return DefaultUpstreamResponseHeaderTimeout
	}
	d, err := time.ParseDuration(p.UpstreamResponseHeaderTimeout)
	if err != nil || d <= 0 {
		return DefaultUpstreamResponseHeaderTimeout
	}
	return d
}

// TLS configures certificate authority and cert caching for MITM.
type TLS struct {
	// Mode selects how the HTTPS listener handles TLS connections.
	// "mitm" (default): terminate TLS, mint a leaf cert signed by the configured
	// CA, and run the full request/response pipeline.
	// "sni-only": peek the ClientHello SNI, run the pipeline with a host-only
	// synthetic request, and TCP-passthrough to the upstream. No CA required.
	Mode                string `yaml:"mode"`
	CACert              string `yaml:"ca_cert"`
	CAKey               string `yaml:"ca_key"`
	CertCacheSize       int    `yaml:"cert_cache_size"`
	LeafCertExpiryHours int    `yaml:"leaf_cert_expiry_hours"`
}

// TLS mode values.
const (
	TLSModeMITM    = "mitm"
	TLSModeSNIOnly = "sni-only"
)

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

// LoadConfig is the primary entry point for building a Config. It parses an
// optional YAML config file, layers in IRON_* environment variable overrides,
// and applies defaults. If path is empty, the config is built entirely from
// environment variables and defaults.
//
// Validation is intentionally not performed here so that callers can populate
// additional fields (e.g. from a control plane sync) before calling Validate.
func LoadConfig(path string) (*Config, error) {
	var cfg Config
	if path != "" {
		parsed, err := parseFileOrS3(path)
		if err != nil {
			return nil, err
		}
		cfg = *parsed
	}

	if err := applyEnvOverrides(&cfg); err != nil {
		return nil, err
	}

	applyDefaults(&cfg)

	return &cfg, nil
}

// Load parses a YAML config from the given reader, applies defaults, and
// validates. This is a convenience for tests and standalone readers.
func Load(r io.Reader) (*Config, error) {
	cfg, err := parse(r)
	if err != nil {
		return nil, err
	}
	applyDefaults(cfg)
	if err := Validate(cfg); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}
	return cfg, nil
}

func parse(r io.Reader) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
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
	if cfg.TLS.Mode == "" {
		cfg.TLS.Mode = TLSModeMITM
	}
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

// Validate checks required fields and value constraints.
func Validate(cfg *Config) error {
	if cfg.DNS.ProxyIP == "" {
		return fmt.Errorf("dns.proxy_ip is required")
	}

	switch cfg.TLS.Mode {
	case TLSModeMITM:
		if cfg.TLS.CACert == "" {
			return fmt.Errorf("tls.ca_cert is required")
		}
		if cfg.TLS.CAKey == "" {
			return fmt.Errorf("tls.ca_key is required")
		}
	case TLSModeSNIOnly:
		// CA cert/key are ignored in sni-only mode; no requirement.
	default:
		return fmt.Errorf("tls.mode must be %q or %q; got %q", TLSModeMITM, TLSModeSNIOnly, cfg.TLS.Mode)
	}

	if _, err := parseLogLevel(cfg.Log.Level); err != nil {
		return fmt.Errorf("log.level: %w", err)
	}

	if cfg.Proxy.UpstreamResponseHeaderTimeout != "" {
		d, err := time.ParseDuration(cfg.Proxy.UpstreamResponseHeaderTimeout)
		if err != nil {
			return fmt.Errorf("proxy.upstream_response_header_timeout: %w", err)
		}
		if d <= 0 {
			return fmt.Errorf("proxy.upstream_response_header_timeout must be positive; got %s", d)
		}
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
