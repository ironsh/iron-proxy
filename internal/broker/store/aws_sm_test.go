package store

import (
	"context"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/stretchr/testify/require"
)

// fakeSMClient is an in-memory secretsmanager.Client stand-in keyed by
// secret_id.
type fakeSMClient struct {
	mu     sync.Mutex
	values map[string]string
}

func newFakeSM() *fakeSMClient {
	return &fakeSMClient{values: map[string]string{}}
}

func (f *fakeSMClient) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := aws.ToString(in.SecretId)
	v, ok := f.values[id]
	if !ok {
		return nil, &smtypes.ResourceNotFoundException{Message: aws.String("not found")}
	}
	return &secretsmanager.GetSecretValueOutput{SecretString: aws.String(v)}, nil
}

func (f *fakeSMClient) PutSecretValue(_ context.Context, in *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.values[aws.ToString(in.SecretId)] = aws.ToString(in.SecretString)
	return &secretsmanager.PutSecretValueOutput{}, nil
}

func newSMHandle(t *testing.T, client smClient) *awsSMHandle {
	t.Helper()
	return &awsSMHandle{
		cfg:    awsSMConfig{SecretID: "iron-broker/test"},
		client: client,
	}
}

func TestAWSSMBuilderRequiresSecretID(t *testing.T) {
	_, err := awsSMBuilder{}.Build(mustNode(t, `{type: aws_sm}`), nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "secret_id")
}

func TestAWSSMGetReturnsNotFound(t *testing.T) {
	h := newSMHandle(t, newFakeSM())
	_, err := h.Get(t.Context())
	require.ErrorIs(t, err, ErrNotFound)
}

func TestAWSSMRoundTrip(t *testing.T) {
	h := newSMHandle(t, newFakeSM())

	mustPut(t, h, CredentialBlob{RefreshToken: "rt-1"})
	got, err := h.Get(t.Context())
	require.NoError(t, err)
	require.Equal(t, "rt-1", got.RefreshToken)

	mustPut(t, h, CredentialBlob{RefreshToken: "rt-2"})
	got, err = h.Get(t.Context())
	require.NoError(t, err)
	require.Equal(t, "rt-2", got.RefreshToken)
}
