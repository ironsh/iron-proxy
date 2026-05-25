// Package config parses iron-token-broker's YAML configuration. The broker
// configuration is deliberately separate from iron-proxy's: it has its own
// listener, its own log block, and a credentials[] list whose entries name
// per-credential OAuth refresh state.
//
// Each credential's client_id and (optional) client_secret are resolved
// through iron-proxy's existing secrets.Source builders so operators can
// store them anywhere they already store secrets. The credential's blob
// is persisted via store.Handle, which mirrors the secrets.Source schema
// but with write capability (see internal/broker/store).
package config

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/broker/store"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

// Duration is a time.Duration that decodes Go duration strings ("30s",
// "5m", "24h"). Mirrors the type in internal/config so operators see the
// same syntax across both binaries.
type Duration time.Duration

// UnmarshalYAML decodes a duration string into a Duration. An empty
// string decodes to the zero value so applyDefaults can fill in.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	if s == "" {
		*d = 0
		return nil
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

// Config is the top-level YAML structure for the broker.
type Config struct {
	Listen        string       `yaml:"listen"`
	MetricsListen string       `yaml:"metrics_listen"`
	BearerAuthEnv string       `yaml:"bearer_auth_env"`
	Log           Log          `yaml:"log"`
	Defaults      Defaults     `yaml:"defaults"`
	Credentials   []Credential `yaml:"credentials"`
}

// Log configures structured logging.
type Log struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// Defaults supplies broker-level fallbacks for per-credential timing
// knobs. A credential's own value overrides the matching default.
type Defaults struct {
	EarlyRefreshSlack    Duration `yaml:"early_refresh_slack"`
	EarlyRefreshFraction float64  `yaml:"early_refresh_fraction"`
	MaxRefreshInterval   Duration `yaml:"max_refresh_interval"`
	RefreshTimeout       Duration `yaml:"refresh_timeout"`
}

// Credential is one OAuth credential the broker manages. The store field
// holds the rotated blob (access_token, refresh_token, expires_at,
// last_refresh) and is written back on every successful refresh.
type Credential struct {
	ID            string   `yaml:"id"`
	TokenEndpoint string   `yaml:"token_endpoint"`
	Scopes        []string `yaml:"scopes,omitempty"`

	ClientID     yaml.Node `yaml:"client_id"`
	ClientSecret yaml.Node `yaml:"client_secret,omitempty"`
	Store        yaml.Node `yaml:"store"`

	// Per-credential overrides for the broker-level defaults.
	EarlyRefreshSlack    Duration `yaml:"early_refresh_slack,omitempty"`
	EarlyRefreshFraction float64  `yaml:"early_refresh_fraction,omitempty"`
	MaxRefreshInterval   Duration `yaml:"max_refresh_interval,omitempty"`
	RefreshTimeout       Duration `yaml:"refresh_timeout,omitempty"`
}

// LoadConfig reads a YAML config file, applies defaults, and validates.
func LoadConfig(path string) (*Config, error) {
	if path == "" {
		return nil, fmt.Errorf("config path is required")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening config %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	cfg, err := Load(f)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

// Load parses a YAML config from r, applies defaults, and validates.
// Exposed for tests and callers that already hold the bytes.
func Load(r io.Reader) (*Config, error) {
	cfg, err := parse(r)
	if err != nil {
		return nil, err
	}
	applyDefaults(cfg)
	if err := Validate(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func parse(r io.Reader) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing broker config: %w", err)
	}
	return &cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.Listen == "" {
		cfg.Listen = ":8181"
	}
	if cfg.MetricsListen == "" {
		cfg.MetricsListen = ":9091"
	}
	if cfg.Log.Level == "" {
		cfg.Log.Level = "info"
	}
	if cfg.Log.Format == "" {
		cfg.Log.Format = "text"
	}
	if cfg.Defaults.EarlyRefreshSlack == 0 {
		cfg.Defaults.EarlyRefreshSlack = Duration(5 * time.Minute)
	}
	if cfg.Defaults.EarlyRefreshFraction == 0 {
		cfg.Defaults.EarlyRefreshFraction = 0.2
	}
	if cfg.Defaults.MaxRefreshInterval == 0 {
		cfg.Defaults.MaxRefreshInterval = Duration(24 * time.Hour)
	}
	if cfg.Defaults.RefreshTimeout == 0 {
		cfg.Defaults.RefreshTimeout = Duration(30 * time.Second)
	}
}

// Validate checks shape and value constraints. It does not perform any
// I/O — credential sources and stores are validated only by builder
// construction (which the broker does separately at startup).
func Validate(cfg *Config) error {
	if cfg.Listen == "" {
		return fmt.Errorf("listen is required")
	}
	if _, err := ParseLogLevel(cfg.Log.Level); err != nil {
		return fmt.Errorf("log.level: %w", err)
	}
	switch cfg.Log.Format {
	case "text", "json":
	default:
		return fmt.Errorf("log.format must be \"text\" or \"json\"; got %q", cfg.Log.Format)
	}
	if cfg.Defaults.EarlyRefreshFraction < 0 || cfg.Defaults.EarlyRefreshFraction >= 1 {
		return fmt.Errorf("defaults.early_refresh_fraction must be in [0, 1); got %g", cfg.Defaults.EarlyRefreshFraction)
	}
	if cfg.Defaults.MaxRefreshInterval <= 0 {
		return fmt.Errorf("defaults.max_refresh_interval must be positive")
	}
	if cfg.Defaults.RefreshTimeout <= 0 {
		return fmt.Errorf("defaults.refresh_timeout must be positive")
	}

	seen := make(map[string]struct{}, len(cfg.Credentials))
	for i, c := range cfg.Credentials {
		if c.ID == "" {
			return fmt.Errorf("credentials[%d].id is required", i)
		}
		if _, dup := seen[c.ID]; dup {
			return fmt.Errorf("credentials[%d]: duplicate id %q", i, c.ID)
		}
		seen[c.ID] = struct{}{}
		if c.TokenEndpoint == "" {
			return fmt.Errorf("credentials[%q].token_endpoint is required", c.ID)
		}
		if c.ClientID.Kind == 0 {
			return fmt.Errorf("credentials[%q].client_id is required", c.ID)
		}
		if c.Store.Kind == 0 {
			return fmt.Errorf("credentials[%q].store is required", c.ID)
		}
		if c.EarlyRefreshFraction < 0 || c.EarlyRefreshFraction >= 1 {
			return fmt.Errorf("credentials[%q].early_refresh_fraction must be in [0, 1); got %g", c.ID, c.EarlyRefreshFraction)
		}
		// Durations override the broker-level defaults via nonZero(),
		// which only checks for the zero value — a negative override
		// would flow straight into context.WithTimeout / NewTimer and
		// cause a busy loop. Reject up front.
		if c.EarlyRefreshSlack < 0 {
			return fmt.Errorf("credentials[%q].early_refresh_slack must be non-negative", c.ID)
		}
		if c.MaxRefreshInterval < 0 {
			return fmt.Errorf("credentials[%q].max_refresh_interval must be non-negative", c.ID)
		}
		if c.RefreshTimeout < 0 {
			return fmt.Errorf("credentials[%q].refresh_timeout must be non-negative", c.ID)
		}
	}
	return nil
}

// BuiltCredential carries one credential's resolved sources and store
// alongside its effective timing knobs (per-credential override merged
// over the broker-level defaults). The broker holds one of these per
// configured credential.
type BuiltCredential struct {
	ID            string
	TokenEndpoint string
	Scopes        []string
	ClientID      secrets.Source
	ClientSecret  secrets.Source // nil for public clients
	Store         store.Handle

	EarlyRefreshSlack    time.Duration
	EarlyRefreshFraction float64
	MaxRefreshInterval   time.Duration
	RefreshTimeout       time.Duration
}

// BuildCredentials resolves each credential's secret sources and store
// handle into a live BuiltCredential, applying defaults to any per-
// credential timing knob the operator did not override. Build errors
// short-circuit: a single misconfigured credential takes the whole
// process down at startup, which is what the operator wants — silent
// fall-through would hide a credential that never refreshes.
func BuildCredentials(cfg *Config, logger *slog.Logger) ([]BuiltCredential, error) {
	out := make([]BuiltCredential, 0, len(cfg.Credentials))
	for _, c := range cfg.Credentials {
		clientID, err := secrets.BuildSource(c.ClientID, logger)
		if err != nil {
			return nil, fmt.Errorf("credentials[%q].client_id: %w", c.ID, err)
		}
		var clientSecret secrets.Source
		if c.ClientSecret.Kind != 0 {
			clientSecret, err = secrets.BuildSource(c.ClientSecret, logger)
			if err != nil {
				return nil, fmt.Errorf("credentials[%q].client_secret: %w", c.ID, err)
			}
		}
		handle, err := store.BuildHandle(c.Store, logger)
		if err != nil {
			return nil, fmt.Errorf("credentials[%q].store: %w", c.ID, err)
		}
		out = append(out, BuiltCredential{
			ID:                   c.ID,
			TokenEndpoint:        c.TokenEndpoint,
			Scopes:               append([]string(nil), c.Scopes...),
			ClientID:             clientID,
			ClientSecret:         clientSecret,
			Store:                handle,
			EarlyRefreshSlack:    nonZero(time.Duration(c.EarlyRefreshSlack), time.Duration(cfg.Defaults.EarlyRefreshSlack)),
			EarlyRefreshFraction: nonZeroFloat(c.EarlyRefreshFraction, cfg.Defaults.EarlyRefreshFraction),
			MaxRefreshInterval:   nonZero(time.Duration(c.MaxRefreshInterval), time.Duration(cfg.Defaults.MaxRefreshInterval)),
			RefreshTimeout:       nonZero(time.Duration(c.RefreshTimeout), time.Duration(cfg.Defaults.RefreshTimeout)),
		})
	}
	return out, nil
}

func nonZero(v, fallback time.Duration) time.Duration {
	if v == 0 {
		return fallback
	}
	return v
}

func nonZeroFloat(v, fallback float64) float64 {
	if v == 0 {
		return fallback
	}
	return v
}

// ParseLogLevel maps a level string to a slog.Level. Accepts the four
// standard names case-insensitively.
func ParseLogLevel(s string) (slog.Level, error) {
	switch s {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown log level %q (want debug, info, warn, error)", s)
	}
}
