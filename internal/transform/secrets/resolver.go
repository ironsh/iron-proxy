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
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"gopkg.in/yaml.v3"
)

// secretResolver resolves a real secret value from a source configuration.
// Each implementation defines and decodes its own config from the raw YAML node.
type secretResolver interface {
	// Resolve validates the source config and returns a deferred GetValue
	// that performs the network fetch lazily on first call. Resolve itself
	// performs no I/O — only static config validation.
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

// defaultFailureTTL is the duration to cache an initial-fetch error when the
// source has no TTL configured. Picked to balance recovery latency against
// hammering a struggling backend.
const defaultFailureTTL = 30 * time.Second

// parseTTL parses a duration string. Empty string means "no TTL configured."
func parseTTL(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	return time.ParseDuration(s)
}

// failureTTL returns the duration to cache an initial-fetch error. If the
// source has a successTTL configured, reuse it; otherwise fall back to a
// 30s default.
func failureTTL(successTTL time.Duration) time.Duration {
	if successTTL > 0 {
		return successTTL
	}
	return defaultFailureTTL
}

// newLazyValue returns a GetValue closure backed by cachedValue. successTTL
// of 0 means "cache forever once successfully fetched" (matches the static
// behavior of sources like env). failureTTL controls how long an initial-
// fetch error is cached before retrying.
func newLazyValue(name string, successTTL, failureTTL time.Duration, logger *slog.Logger, fetch func(context.Context) (string, error)) func(context.Context) (string, error) {
	cv := &cachedValue{
		name:       name,
		logger:     logger,
		fetch:      fetch,
		successTTL: successTTL,
		failureTTL: failureTTL,
		now:        time.Now,
	}
	return cv.get
}

// --- env resolver ---

// envResolver reads secrets from environment variables.
type envResolver struct {
	getenv func(string) string
	logger *slog.Logger
}

type envConfig struct {
	Type string `yaml:"type"`
	Var  string `yaml:"var"`
}

func newEnvResolver(logger *slog.Logger) *envResolver {
	return &envResolver{getenv: os.Getenv, logger: logger}
}

func (r *envResolver) Resolve(_ context.Context, raw yaml.Node) (ResolveResult, error) {
	var cfg envConfig
	if err := raw.Decode(&cfg); err != nil {
		return ResolveResult{}, fmt.Errorf("parsing env source config: %w", err)
	}
	if cfg.Var == "" {
		return ResolveResult{}, fmt.Errorf("env source requires \"var\" field")
	}
	fetch := func(context.Context) (string, error) {
		v := r.getenv(cfg.Var)
		if v == "" {
			return "", fmt.Errorf("env var %q is not set or empty", cfg.Var)
		}
		return v, nil
	}
	return ResolveResult{
		Name:     cfg.Var,
		GetValue: newLazyValue(cfg.Var, 0, defaultFailureTTL, r.logger, fetch),
	}, nil
}

// --- shared AWS client cache ---

// awsClientCache provides region-keyed caching for any AWS service client.
type awsClientCache[C any] struct {
	mu        sync.Mutex
	clients   map[string]C
	newClient func(cfg aws.Config) C
}

func (c *awsClientCache[C]) get(ctx context.Context, region string) (C, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if client, ok := c.clients[region]; ok {
		return client, nil
	}
	var opts []func(*awsconfig.LoadOptions) error
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		var zero C
		return zero, fmt.Errorf("loading AWS config: %w", err)
	}
	client := c.newClient(cfg)
	c.clients[region] = client
	return client, nil
}

// --- AWS Secrets Manager resolver ---

// smClient is the subset of the AWS Secrets Manager API used by awsSMResolver.
type smClient interface {
	GetSecretValue(ctx context.Context, input *secretsmanager.GetSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// awsSMResolver reads secrets from AWS Secrets Manager.
type awsSMResolver struct {
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
	cache := &awsClientCache[smClient]{
		clients:   make(map[string]smClient),
		newClient: func(cfg aws.Config) smClient { return secretsmanager.NewFromConfig(cfg) },
	}
	return &awsSMResolver{clientFor: cache.get, logger: logger}
}

func (r *awsSMResolver) Resolve(_ context.Context, raw yaml.Node) (ResolveResult, error) {
	var cfg awsSMConfig
	if err := raw.Decode(&cfg); err != nil {
		return ResolveResult{}, fmt.Errorf("parsing aws_sm source config: %w", err)
	}
	if cfg.SecretID == "" {
		return ResolveResult{}, fmt.Errorf("aws_sm source requires \"secret_id\" field")
	}
	successTTL, err := parseTTL(cfg.TTL)
	if err != nil {
		return ResolveResult{}, fmt.Errorf("parsing ttl %q: %w", cfg.TTL, err)
	}
	fetch := func(ctx context.Context) (string, error) {
		return r.fetchSecret(ctx, cfg)
	}
	return ResolveResult{
		Name:     cfg.SecretID,
		GetValue: newLazyValue(cfg.SecretID, successTTL, failureTTL(successTTL), r.logger, fetch),
	}, nil
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

// --- AWS Systems Manager Parameter Store resolver ---

// ssmClient is the subset of the AWS SSM API used by awsSSMResolver.
type ssmClient interface {
	GetParameter(ctx context.Context, input *ssm.GetParameterInput, opts ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
}

// awsSSMResolver reads secrets from AWS Systems Manager Parameter Store.
type awsSSMResolver struct {
	clientFor func(ctx context.Context, region string) (ssmClient, error)
	logger    *slog.Logger
}

type awsSSMConfig struct {
	Type           string `yaml:"type"`
	Name           string `yaml:"name"`
	Region         string `yaml:"region,omitempty"`
	WithDecryption *bool  `yaml:"with_decryption,omitempty"`
	JSONKey        string `yaml:"json_key,omitempty"`
	TTL            string `yaml:"ttl,omitempty"`
}

func (cfg awsSSMConfig) decryptValue() bool {
	return cfg.WithDecryption == nil || *cfg.WithDecryption
}

func newAWSSSMResolver(logger *slog.Logger) *awsSSMResolver {
	cache := &awsClientCache[ssmClient]{
		clients:   make(map[string]ssmClient),
		newClient: func(cfg aws.Config) ssmClient { return ssm.NewFromConfig(cfg) },
	}
	return &awsSSMResolver{clientFor: cache.get, logger: logger}
}

func (r *awsSSMResolver) Resolve(_ context.Context, raw yaml.Node) (ResolveResult, error) {
	var cfg awsSSMConfig
	if err := raw.Decode(&cfg); err != nil {
		return ResolveResult{}, fmt.Errorf("parsing aws_ssm source config: %w", err)
	}
	if cfg.Name == "" {
		return ResolveResult{}, fmt.Errorf("aws_ssm source requires \"name\" field")
	}
	successTTL, err := parseTTL(cfg.TTL)
	if err != nil {
		return ResolveResult{}, fmt.Errorf("parsing ttl %q: %w", cfg.TTL, err)
	}
	fetch := func(ctx context.Context) (string, error) {
		return r.fetchParameter(ctx, cfg)
	}
	return ResolveResult{
		Name:     cfg.Name,
		GetValue: newLazyValue(cfg.Name, successTTL, failureTTL(successTTL), r.logger, fetch),
	}, nil
}

func (r *awsSSMResolver) fetchParameter(ctx context.Context, cfg awsSSMConfig) (string, error) {
	client, err := r.clientFor(ctx, cfg.Region)
	if err != nil {
		return "", fmt.Errorf("creating AWS SSM client: %w", err)
	}
	out, err := client.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(cfg.Name),
		WithDecryption: aws.Bool(cfg.decryptValue()),
	})
	if err != nil {
		return "", fmt.Errorf("fetching parameter %q: %w", cfg.Name, err)
	}
	if out == nil || out.Parameter == nil {
		return "", fmt.Errorf("parameter %q resolved without a value", cfg.Name)
	}
	val := aws.ToString(out.Parameter.Value)
	if cfg.JSONKey != "" {
		val, err = extractJSONKey(val, cfg.JSONKey)
		if err != nil {
			return "", fmt.Errorf("extracting json_key %q from parameter %q: %w", cfg.JSONKey, cfg.Name, err)
		}
	}
	if val == "" {
		return "", fmt.Errorf("parameter %q resolved to empty value", cfg.Name)
	}
	return val, nil
}

// --- cached value (lazy fetch + TTL refresh + initial-failure caching) ---

// cachedValue wraps a fetch function with TTL-based caching for both success
// and initial-failure outcomes. The first call to get() triggers the fetch.
// On success, the value is cached for successTTL (or forever if successTTL
// is 0). On failure before any successful fetch, the error is cached for
// failureTTL so a struggling backend isn't hammered. After a successful fetch,
// later refresh failures serve the stale value (existing behavior preserved).
type cachedValue struct {
	mu         sync.Mutex
	name       string
	logger     *slog.Logger
	fetch      func(ctx context.Context) (string, error)
	successTTL time.Duration
	failureTTL time.Duration
	now        func() time.Time

	initialized bool
	value       string
	lastErr     error
	expiresAt   time.Time
}

func (cv *cachedValue) get(ctx context.Context) (string, error) {
	cv.mu.Lock()
	defer cv.mu.Unlock()

	if cv.initialized {
		if cv.successTTL == 0 || cv.now().Before(cv.expiresAt) {
			return cv.value, nil
		}
		// successTTL > 0 and expired: fall through to refresh.
	} else if cv.now().Before(cv.expiresAt) {
		return "", cv.lastErr
	}

	val, err := cv.fetch(ctx)
	if err != nil {
		if cv.initialized {
			cv.expiresAt = cv.now().Add(cv.successTTL / 2)
			if cv.logger != nil {
				cv.logger.Warn("failed to refresh secret, serving stale value",
					"secret", cv.name,
					"error", err,
				)
			}
			return cv.value, nil
		}
		cv.lastErr = err
		cv.expiresAt = cv.now().Add(cv.failureTTL)
		if cv.logger != nil {
			cv.logger.Warn("failed to fetch secret, caching error",
				"secret", cv.name,
				"error", err,
				"retry_in", cv.failureTTL,
			)
		}
		return "", err
	}
	cv.value = val
	cv.initialized = true
	cv.lastErr = nil
	if cv.successTTL > 0 {
		cv.expiresAt = cv.now().Add(cv.successTTL)
	}
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
