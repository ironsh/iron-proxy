package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"gopkg.in/yaml.v3"
)

// secretResolver resolves a real secret value from a source configuration.
// Each implementation defines and decodes its own config from the raw YAML node.
type secretResolver interface {
	// Resolve validates the source config and fetches the initial secret value.
	// The returned ResolveResult includes a GetValue function that may lazily
	// refresh the value (e.g., for sources with a TTL).
	Resolve(ctx context.Context, raw yaml.Node) (ResolveResult, error)
}

// ResolveResult holds the resolved secret and a function to get its current value.
type ResolveResult struct {
	Name     string                                    // display name for logging
	GetValue func(ctx context.Context) (string, error) // returns the current secret value
}

// sourceTypeHint is used to peek at the type field before dispatching to a resolver.
type sourceTypeHint struct {
	Type string `yaml:"type"`
}

// resolverRegistry maps source type names to their resolvers.
type resolverRegistry map[string]secretResolver

// --- env resolver ---

// envResolver reads secrets from environment variables.
type envResolver struct {
	getenv func(string) string
}

type envConfig struct {
	Type string `yaml:"type"`
	Var  string `yaml:"var"`
}

func newEnvResolver() *envResolver {
	return &envResolver{getenv: os.Getenv}
}

func (r *envResolver) Resolve(_ context.Context, raw yaml.Node) (ResolveResult, error) {
	var cfg envConfig
	if err := raw.Decode(&cfg); err != nil {
		return ResolveResult{}, fmt.Errorf("parsing env source config: %w", err)
	}
	if cfg.Var == "" {
		return ResolveResult{}, fmt.Errorf("env source requires \"var\" field")
	}
	val := r.getenv(cfg.Var)
	if val == "" {
		return ResolveResult{}, fmt.Errorf("env var %q is not set or empty", cfg.Var)
	}
	return ResolveResult{
		Name:     cfg.Var,
		GetValue: staticValue(val),
	}, nil
}

// staticValue returns a GetValue function that always returns the same value.
func staticValue(val string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) { return val, nil }
}

// --- AWS Secrets Manager resolver ---

// smClient is the subset of the AWS Secrets Manager API used by awsSMResolver.
type smClient interface {
	GetSecretValue(ctx context.Context, input *secretsmanager.GetSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// awsSMResolver reads secrets from AWS Secrets Manager.
type awsSMResolver struct {
	mu        sync.Mutex
	clients   map[string]smClient
	clientFor func(ctx context.Context, region string) (smClient, error)
	logger    *slog.Logger
}

type awsSMConfig struct {
	Type     string `yaml:"type"`
	SecretID string `yaml:"secret_id"`
	Region   string `yaml:"region,omitempty"`
	JSONKey  string `yaml:"json_key,omitempty"`
	TTL      string `yaml:"ttl,omitempty"`
}

func newAWSSMResolver(logger *slog.Logger) *awsSMResolver {
	r := &awsSMResolver{
		clients: make(map[string]smClient),
		logger:  logger,
	}
	r.clientFor = r.defaultClientFor
	return r
}

func (r *awsSMResolver) defaultClientFor(ctx context.Context, region string) (smClient, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.clients[region]; ok {
		return c, nil
	}
	var opts []func(*awsconfig.LoadOptions) error
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	c := secretsmanager.NewFromConfig(cfg)
	r.clients[region] = c
	return c, nil
}

func (r *awsSMResolver) Resolve(ctx context.Context, raw yaml.Node) (ResolveResult, error) {
	var cfg awsSMConfig
	if err := raw.Decode(&cfg); err != nil {
		return ResolveResult{}, fmt.Errorf("parsing aws_sm source config: %w", err)
	}
	if cfg.SecretID == "" {
		return ResolveResult{}, fmt.Errorf("aws_sm source requires \"secret_id\" field")
	}

	// Fetch initial value to validate config eagerly at startup.
	val, err := r.fetchSecret(ctx, cfg)
	if err != nil {
		return ResolveResult{}, err
	}

	var ttl time.Duration
	if cfg.TTL != "" {
		ttl, err = time.ParseDuration(cfg.TTL)
		if err != nil {
			return ResolveResult{}, fmt.Errorf("parsing ttl %q: %w", cfg.TTL, err)
		}
	}

	var getValue func(context.Context) (string, error)
	if ttl > 0 {
		cv := &cachedValue{
			value:     val,
			expiresAt: time.Now().Add(ttl),
			ttl:       ttl,
			logger:    r.logger,
			name:      cfg.SecretID,
			refresh: func(ctx context.Context) (string, error) {
				return r.fetchSecret(ctx, cfg)
			},
		}
		getValue = cv.get
	} else {
		getValue = staticValue(val)
	}

	return ResolveResult{Name: cfg.SecretID, GetValue: getValue}, nil
}

func (r *awsSMResolver) fetchSecret(ctx context.Context, cfg awsSMConfig) (string, error) {
	client, err := r.clientFor(ctx, cfg.Region)
	if err != nil {
		return "", fmt.Errorf("creating AWS SM client: %w", err)
	}
	out, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(cfg.SecretID),
	})
	if err != nil {
		return "", fmt.Errorf("fetching secret %q: %w", cfg.SecretID, err)
	}
	val := aws.ToString(out.SecretString)
	if cfg.JSONKey != "" {
		val, err = extractJSONKey(val, cfg.JSONKey)
		if err != nil {
			return "", fmt.Errorf("extracting json_key %q from secret %q: %w", cfg.JSONKey, cfg.SecretID, err)
		}
	}
	if val == "" {
		return "", fmt.Errorf("secret %q resolved to empty value", cfg.SecretID)
	}
	return val, nil
}

// --- cached value (lazy TTL refresh) ---

// cachedValue wraps a secret value with lazy TTL-based refresh. When get() is
// called and the value has expired, it re-fetches inline. On refresh failure,
// the stale value is returned and the error is logged.
type cachedValue struct {
	mu        sync.Mutex
	value     string
	expiresAt time.Time
	ttl       time.Duration
	logger    *slog.Logger
	name      string
	refresh   func(ctx context.Context) (string, error)
}

func (cv *cachedValue) get(ctx context.Context) (string, error) {
	cv.mu.Lock()
	defer cv.mu.Unlock()

	if time.Now().Before(cv.expiresAt) {
		return cv.value, nil
	}

	val, err := cv.refresh(ctx)
	if err != nil {
		cv.logger.Warn("failed to refresh secret, serving stale value",
			"secret", cv.name,
			"error", err,
		)
		// Retry again after half the TTL to avoid hammering on every request.
		cv.expiresAt = time.Now().Add(cv.ttl / 2)
		return cv.value, nil
	}

	cv.value = val
	cv.expiresAt = time.Now().Add(cv.ttl)
	return cv.value, nil
}

// --- JSON extraction ---

// extractJSONKey parses raw as JSON and returns the string value at key.
func extractJSONKey(raw, key string) (string, error) {
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return "", fmt.Errorf("secret value is not valid JSON: %w", err)
	}
	v, ok := m[key]
	if !ok {
		return "", fmt.Errorf("key %q not found in JSON", key)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("key %q is not a string (type %T)", key, v)
	}
	return s, nil
}
