package secrets

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
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

// mockSMClient is a configurable mock for the AWS Secrets Manager client.
type mockSMClient struct {
	fn func(ctx context.Context, input *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error)
}

func (m *mockSMClient) GetSecretValue(ctx context.Context, input *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	return m.fn(ctx, input)
}

// staticSMClient returns a mockSMClient that always returns the given output/error.
func staticSMClient(out *secretsmanager.GetSecretValueOutput, err error) *mockSMClient {
	return &mockSMClient{fn: func(_ context.Context, _ *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
		return out, err
	}}
}

func newTestAWSSMResolver(client smClient) *awsSMResolver {
	return &awsSMResolver{
		clientFor: func(_ context.Context, _ string) (smClient, error) {
			return client, nil
		},
		logger: slog.Default(),
	}
}

// mockSSMClient is a configurable mock for the AWS SSM client.
type mockSSMClient struct {
	fn func(ctx context.Context, input *ssm.GetParameterInput) (*ssm.GetParameterOutput, error)
}

func (m *mockSSMClient) GetParameter(ctx context.Context, input *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	return m.fn(ctx, input)
}

// staticSSMClient returns a mockSSMClient that always returns the given output/error.
func staticSSMClient(out *ssm.GetParameterOutput, err error) *mockSSMClient {
	return &mockSSMClient{fn: func(_ context.Context, _ *ssm.GetParameterInput) (*ssm.GetParameterOutput, error) {
		return out, err
	}}
}

func newTestAWSSSMResolver(client ssmClient) *awsSSMResolver {
	return &awsSSMResolver{
		clientFor: func(_ context.Context, _ string) (ssmClient, error) {
			return client, nil
		},
		logger: slog.Default(),
	}
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

func TestEnvResolver_Errors(t *testing.T) {
	tests := []struct {
		name   string
		input  map[string]string
		errMsg string
	}{
		{
			name:   "missing var field",
			input:  map[string]string{"type": "env"},
			errMsg: "\"var\" field",
		},
		{
			name:   "empty value",
			input:  map[string]string{"type": "env", "var": "EMPTY_VAR"},
			errMsg: "not set or empty",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &envResolver{getenv: func(string) string { return "" }}
			node := yamlNode(t, tt.input)
			_, err := r.Resolve(context.Background(), node)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

// --- awsSMResolver tests ---

func TestAWSSMResolver_PlainString(t *testing.T) {
	client := staticSMClient(&secretsmanager.GetSecretValueOutput{
		SecretString: aws.String("my-secret-value"),
	}, nil)
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
	client := staticSMClient(&secretsmanager.GetSecretValueOutput{
		SecretString: aws.String(`{"api_key": "sk-abc123", "other": "val"}`),
	}, nil)
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
	client := staticSMClient(&secretsmanager.GetSecretValueOutput{
		SecretString: aws.String("value"),
	}, nil)
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

func TestAWSSMResolver_Errors(t *testing.T) {
	tests := []struct {
		name   string
		client *mockSMClient
		input  map[string]string
		errMsg string
	}{
		{
			name:   "missing secret_id",
			client: staticSMClient(nil, nil),
			input:  map[string]string{"type": "aws_sm"},
			errMsg: "\"secret_id\" field",
		},
		{
			name:   "aws error",
			client: staticSMClient(nil, fmt.Errorf("access denied")),
			input:  map[string]string{"type": "aws_sm", "secret_id": "arn:foo"},
			errMsg: "access denied",
		},
		{
			name: "empty secret value",
			client: staticSMClient(&secretsmanager.GetSecretValueOutput{
				SecretString: aws.String(""),
			}, nil),
			input:  map[string]string{"type": "aws_sm", "secret_id": "arn:foo"},
			errMsg: "empty value",
		},
		{
			name: "invalid TTL",
			client: staticSMClient(&secretsmanager.GetSecretValueOutput{
				SecretString: aws.String("value"),
			}, nil),
			input:  map[string]string{"type": "aws_sm", "secret_id": "arn:foo", "ttl": "not-a-duration"},
			errMsg: "parsing ttl",
		},
		{
			name: "json_key with invalid JSON",
			client: staticSMClient(&secretsmanager.GetSecretValueOutput{
				SecretString: aws.String("not-json"),
			}, nil),
			input:  map[string]string{"type": "aws_sm", "secret_id": "arn:foo", "json_key": "api_key"},
			errMsg: "not valid JSON",
		},
		{
			name: "json_key not found",
			client: staticSMClient(&secretsmanager.GetSecretValueOutput{
				SecretString: aws.String(`{"other": "value"}`),
			}, nil),
			input:  map[string]string{"type": "aws_sm", "secret_id": "arn:foo", "json_key": "api_key"},
			errMsg: "not found",
		},
		{
			name: "json_key non-string value",
			client: staticSMClient(&secretsmanager.GetSecretValueOutput{
				SecretString: aws.String(`{"api_key": 123}`),
			}, nil),
			input:  map[string]string{"type": "aws_sm", "secret_id": "arn:foo", "json_key": "api_key"},
			errMsg: "not a string",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newTestAWSSMResolver(tt.client)
			node := yamlNode(t, tt.input)
			_, err := r.Resolve(context.Background(), node)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

// --- awsSSMResolver tests ---

func TestAWSSSMResolver_PlainString(t *testing.T) {
	client := staticSSMClient(&ssm.GetParameterOutput{
		Parameter: &ssmtypes.Parameter{Value: aws.String("my-param-value")},
	}, nil)
	r := newTestAWSSSMResolver(client)
	node := yamlNode(t, map[string]string{"type": "aws_ssm", "name": "/myapp/api-key"})
	result, err := r.Resolve(context.Background(), node)
	require.NoError(t, err)
	require.Equal(t, "/myapp/api-key", result.Name)

	val, err := result.GetValue(context.Background())
	require.NoError(t, err)
	require.Equal(t, "my-param-value", val)
}

func TestAWSSSMResolver_JSONKey(t *testing.T) {
	client := staticSSMClient(&ssm.GetParameterOutput{
		Parameter: &ssmtypes.Parameter{Value: aws.String(`{"api_key": "sk-abc123", "other": "val"}`)},
	}, nil)
	r := newTestAWSSSMResolver(client)
	node := yamlNode(t, map[string]string{
		"type":     "aws_ssm",
		"name":     "/myapp/config",
		"json_key": "api_key",
	})
	result, err := r.Resolve(context.Background(), node)
	require.NoError(t, err)

	val, err := result.GetValue(context.Background())
	require.NoError(t, err)
	require.Equal(t, "sk-abc123", val)
}

func TestAWSSSMResolver_TTLReturnsCachedValue(t *testing.T) {
	client := staticSSMClient(&ssm.GetParameterOutput{
		Parameter: &ssmtypes.Parameter{Value: aws.String("value")},
	}, nil)
	r := newTestAWSSSMResolver(client)
	node := yamlNode(t, map[string]string{
		"type": "aws_ssm",
		"name": "/myapp/secret",
		"ttl":  "15m",
	})
	result, err := r.Resolve(context.Background(), node)
	require.NoError(t, err)

	val, err := result.GetValue(context.Background())
	require.NoError(t, err)
	require.Equal(t, "value", val)
}

func TestAWSSSMResolver_WithDecryption(t *testing.T) {
	tests := []struct {
		name string
		raw  map[string]any
		want bool
	}{
		{
			name: "defaults to true",
			raw:  map[string]any{"type": "aws_ssm", "name": "/myapp/secret"},
			want: true,
		},
		{
			name: "explicit true",
			raw:  map[string]any{"type": "aws_ssm", "name": "/myapp/secret", "with_decryption": true},
			want: true,
		},
		{
			name: "explicit false",
			raw:  map[string]any{"type": "aws_ssm", "name": "/myapp/secret", "with_decryption": false},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedInput *ssm.GetParameterInput
			client := &mockSSMClient{fn: func(_ context.Context, input *ssm.GetParameterInput) (*ssm.GetParameterOutput, error) {
				capturedInput = input
				return &ssm.GetParameterOutput{
					Parameter: &ssmtypes.Parameter{Value: aws.String("decrypted-value")},
				}, nil
			}}
			r := newTestAWSSSMResolver(client)
			result, err := r.Resolve(context.Background(), yamlNode(t, tt.raw))
			require.NoError(t, err)
			require.Equal(t, tt.want, aws.ToBool(capturedInput.WithDecryption))

			val, err := result.GetValue(context.Background())
			require.NoError(t, err)
			require.Equal(t, "decrypted-value", val)
		})
	}
}

func TestAWSSSMResolver_Region(t *testing.T) {
	client := staticSSMClient(&ssm.GetParameterOutput{
		Parameter: &ssmtypes.Parameter{Value: aws.String("value")},
	}, nil)
	var gotRegion string
	r := &awsSSMResolver{
		clientFor: func(_ context.Context, region string) (ssmClient, error) {
			gotRegion = region
			return client, nil
		},
		logger: slog.Default(),
	}

	_, err := r.Resolve(context.Background(), yamlNode(t, map[string]string{
		"type":   "aws_ssm",
		"name":   "/myapp/secret",
		"region": "us-east-1",
	}))
	require.NoError(t, err)
	require.Equal(t, "us-east-1", gotRegion)
}

func TestAWSSSMResolver_Errors(t *testing.T) {
	tests := []struct {
		name   string
		client *mockSSMClient
		input  map[string]string
		errMsg string
	}{
		{
			name:   "missing name",
			client: staticSSMClient(nil, nil),
			input:  map[string]string{"type": "aws_ssm"},
			errMsg: "\"name\" field",
		},
		{
			name:   "aws error",
			client: staticSSMClient(nil, fmt.Errorf("parameter not found")),
			input:  map[string]string{"type": "aws_ssm", "name": "/myapp/missing"},
			errMsg: "parameter not found",
		},
		{
			name: "empty parameter value",
			client: staticSSMClient(&ssm.GetParameterOutput{
				Parameter: &ssmtypes.Parameter{Value: aws.String("")},
			}, nil),
			input:  map[string]string{"type": "aws_ssm", "name": "/myapp/empty"},
			errMsg: "empty value",
		},
		{
			name:   "missing parameter",
			client: staticSSMClient(&ssm.GetParameterOutput{}, nil),
			input:  map[string]string{"type": "aws_ssm", "name": "/myapp/missing-value"},
			errMsg: "without a value",
		},
		{
			name:   "nil response",
			client: staticSSMClient(nil, nil),
			input:  map[string]string{"type": "aws_ssm", "name": "/myapp/nil-response"},
			errMsg: "without a value",
		},
		{
			name: "invalid TTL",
			client: staticSSMClient(&ssm.GetParameterOutput{
				Parameter: &ssmtypes.Parameter{Value: aws.String("value")},
			}, nil),
			input:  map[string]string{"type": "aws_ssm", "name": "/myapp/key", "ttl": "not-a-duration"},
			errMsg: "parsing ttl",
		},
		{
			name: "json_key with invalid JSON",
			client: staticSSMClient(&ssm.GetParameterOutput{
				Parameter: &ssmtypes.Parameter{Value: aws.String("not-json")},
			}, nil),
			input:  map[string]string{"type": "aws_ssm", "name": "/myapp/key", "json_key": "api_key"},
			errMsg: "not valid JSON",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newTestAWSSSMResolver(tt.client)
			node := yamlNode(t, tt.input)
			_, err := r.Resolve(context.Background(), node)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

// --- extractJSONKey tests ---

func TestExtractJSONKey(t *testing.T) {
	tests := []struct {
		name   string
		json   string
		key    string
		want   string
		errMsg string
	}{
		{
			name: "valid",
			json: `{"key": "value", "other": "data"}`,
			key:  "key",
			want: "value",
		},
		{
			name:   "invalid JSON",
			json:   `not json`,
			key:    "key",
			errMsg: "not valid JSON",
		},
		{
			name:   "missing key",
			json:   `{"other": "value"}`,
			key:    "key",
			errMsg: "not found",
		},
		{
			name:   "non-string value",
			json:   `{"key": 42}`,
			key:    "key",
			errMsg: "not a string",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, err := extractJSONKey(tt.json, tt.key)
			if tt.errMsg != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.want, val)
			}
		})
	}
}

// --- cachedValue tests ---

func TestCachedValue_ServesStaleOnError(t *testing.T) {
	calls := 0
	cv := &cachedValue{
		value:  "initial",
		ttl:    1, // expired immediately
		logger: slog.Default(),
		name:   "test",
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
