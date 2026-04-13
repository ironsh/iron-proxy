package secrets

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// yamlNode marshals v to YAML and returns the resulting yaml.Node.
func yamlNode(t *testing.T, v any) yaml.Node {
	t.Helper()
	data, err := yaml.Marshal(v)
	require.NoError(t, err)
	var node yaml.Node
	require.NoError(t, yaml.Unmarshal(data, &node))
	// yaml.Unmarshal wraps in a document node; return the first content node.
	return *node.Content[0]
}

// --- envResolver tests ---

func TestEnvResolver_HappyPath(t *testing.T) {
	r := &envResolver{getenv: func(key string) string {
		if key == "MY_SECRET" {
			return "real-value"
		}
		return ""
	}}
	node := yamlNode(t, map[string]string{"type": "env", "var": "MY_SECRET"})
	result, err := r.Resolve(context.Background(), node)
	require.NoError(t, err)
	require.Equal(t, "MY_SECRET", result.Name)

	val, err := result.GetValue(context.Background())
	require.NoError(t, err)
	require.Equal(t, "real-value", val)
}

func TestEnvResolver_MissingVar(t *testing.T) {
	r := &envResolver{getenv: func(string) string { return "" }}
	node := yamlNode(t, map[string]string{"type": "env"})
	_, err := r.Resolve(context.Background(), node)
	require.Error(t, err)
	require.Contains(t, err.Error(), "\"var\" field")
}

func TestEnvResolver_EmptyValue(t *testing.T) {
	r := &envResolver{getenv: func(string) string { return "" }}
	node := yamlNode(t, map[string]string{"type": "env", "var": "EMPTY_VAR"})
	_, err := r.Resolve(context.Background(), node)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not set or empty")
}

// --- awsSMResolver tests ---

type mockSMClient struct {
	out *secretsmanager.GetSecretValueOutput
	err error
}

func (m *mockSMClient) GetSecretValue(_ context.Context, _ *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	return m.out, m.err
}

func newTestAWSSMResolver(client smClient) *awsSMResolver {
	r := &awsSMResolver{
		clients: make(map[string]smClient),
		logger:  slog.Default(),
	}
	r.clientFor = func(_ context.Context, _ string) (smClient, error) {
		return client, nil
	}
	return r
}

func TestAWSSMResolver_PlainString(t *testing.T) {
	client := &mockSMClient{out: &secretsmanager.GetSecretValueOutput{
		SecretString: aws.String("my-secret-value"),
	}}
	r := newTestAWSSMResolver(client)
	node := yamlNode(t, map[string]string{"type": "aws_sm", "secret_id": "arn:aws:sm:us-east-1:123:secret:foo"})
	result, err := r.Resolve(context.Background(), node)
	require.NoError(t, err)
	require.Equal(t, "arn:aws:sm:us-east-1:123:secret:foo", result.Name)

	val, err := result.GetValue(context.Background())
	require.NoError(t, err)
	require.Equal(t, "my-secret-value", val)
}

func TestAWSSMResolver_JSONKey(t *testing.T) {
	client := &mockSMClient{out: &secretsmanager.GetSecretValueOutput{
		SecretString: aws.String(`{"api_key": "sk-abc123", "other": "val"}`),
	}}
	r := newTestAWSSMResolver(client)
	node := yamlNode(t, map[string]string{
		"type":      "aws_sm",
		"secret_id": "arn:aws:sm:us-east-1:123:secret:foo",
		"json_key":  "api_key",
	})
	result, err := r.Resolve(context.Background(), node)
	require.NoError(t, err)

	val, err := result.GetValue(context.Background())
	require.NoError(t, err)
	require.Equal(t, "sk-abc123", val)
}

func TestAWSSMResolver_TTLReturnsCachedValue(t *testing.T) {
	client := &mockSMClient{out: &secretsmanager.GetSecretValueOutput{
		SecretString: aws.String("value"),
	}}
	r := newTestAWSSMResolver(client)
	node := yamlNode(t, map[string]string{
		"type":      "aws_sm",
		"secret_id": "arn:aws:sm:us-east-1:123:secret:foo",
		"ttl":       "15m",
	})
	result, err := r.Resolve(context.Background(), node)
	require.NoError(t, err)

	// GetValue should return cached value without re-fetching.
	val, err := result.GetValue(context.Background())
	require.NoError(t, err)
	require.Equal(t, "value", val)
}

func TestAWSSMResolver_MissingSecretID(t *testing.T) {
	r := newTestAWSSMResolver(&mockSMClient{})
	node := yamlNode(t, map[string]string{"type": "aws_sm"})
	_, err := r.Resolve(context.Background(), node)
	require.Error(t, err)
	require.Contains(t, err.Error(), "\"secret_id\" field")
}

func TestAWSSMResolver_AWSError(t *testing.T) {
	client := &mockSMClient{err: fmt.Errorf("access denied")}
	r := newTestAWSSMResolver(client)
	node := yamlNode(t, map[string]string{"type": "aws_sm", "secret_id": "arn:foo"})
	_, err := r.Resolve(context.Background(), node)
	require.Error(t, err)
	require.Contains(t, err.Error(), "access denied")
}

func TestAWSSMResolver_EmptySecretValue(t *testing.T) {
	client := &mockSMClient{out: &secretsmanager.GetSecretValueOutput{
		SecretString: aws.String(""),
	}}
	r := newTestAWSSMResolver(client)
	node := yamlNode(t, map[string]string{"type": "aws_sm", "secret_id": "arn:foo"})
	_, err := r.Resolve(context.Background(), node)
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty value")
}

func TestAWSSMResolver_InvalidTTL(t *testing.T) {
	client := &mockSMClient{out: &secretsmanager.GetSecretValueOutput{
		SecretString: aws.String("value"),
	}}
	r := newTestAWSSMResolver(client)
	node := yamlNode(t, map[string]string{
		"type":      "aws_sm",
		"secret_id": "arn:foo",
		"ttl":       "not-a-duration",
	})
	_, err := r.Resolve(context.Background(), node)
	require.Error(t, err)
	require.Contains(t, err.Error(), "parsing ttl")
}

// --- extractJSONKey tests ---

func TestExtractJSONKey_Valid(t *testing.T) {
	val, err := extractJSONKey(`{"key": "value", "other": "data"}`, "key")
	require.NoError(t, err)
	require.Equal(t, "value", val)
}

func TestExtractJSONKey_InvalidJSON(t *testing.T) {
	_, err := extractJSONKey(`not json`, "key")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not valid JSON")
}

func TestExtractJSONKey_MissingKey(t *testing.T) {
	_, err := extractJSONKey(`{"other": "value"}`, "key")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}

func TestExtractJSONKey_NonStringValue(t *testing.T) {
	_, err := extractJSONKey(`{"key": 42}`, "key")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a string")
}

func TestAWSSMResolver_JSONKeyInvalidJSON(t *testing.T) {
	client := &mockSMClient{out: &secretsmanager.GetSecretValueOutput{
		SecretString: aws.String("not-json"),
	}}
	r := newTestAWSSMResolver(client)
	node := yamlNode(t, map[string]string{
		"type":      "aws_sm",
		"secret_id": "arn:foo",
		"json_key":  "api_key",
	})
	_, err := r.Resolve(context.Background(), node)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not valid JSON")
}

func TestAWSSMResolver_JSONKeyMissing(t *testing.T) {
	client := &mockSMClient{out: &secretsmanager.GetSecretValueOutput{
		SecretString: aws.String(`{"other": "value"}`),
	}}
	r := newTestAWSSMResolver(client)
	node := yamlNode(t, map[string]string{
		"type":      "aws_sm",
		"secret_id": "arn:foo",
		"json_key":  "api_key",
	})
	_, err := r.Resolve(context.Background(), node)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}

func TestAWSSMResolver_JSONKeyNonString(t *testing.T) {
	client := &mockSMClient{out: &secretsmanager.GetSecretValueOutput{
		SecretString: aws.String(`{"api_key": 123}`),
	}}
	r := newTestAWSSMResolver(client)
	node := yamlNode(t, map[string]string{
		"type":      "aws_sm",
		"secret_id": "arn:foo",
		"json_key":  "api_key",
	})
	_, err := r.Resolve(context.Background(), node)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a string")
}

// --- cachedValue tests ---

func TestCachedValue_ServesStaleOnError(t *testing.T) {
	calls := 0
	cv := &cachedValue{
		value:     "initial",
		ttl:       1, // expired immediately
		logger:    slog.Default(),
		name:      "test",
		refresh: func(_ context.Context) (string, error) {
			calls++
			return "", fmt.Errorf("aws error")
		},
	}

	val, err := cv.get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "initial", val)
	require.Equal(t, 1, calls)
}
