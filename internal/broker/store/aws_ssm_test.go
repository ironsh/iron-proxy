package store

import (
	"context"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/stretchr/testify/require"
)

type fakeSSMClient struct {
	mu     sync.Mutex
	values map[string]string
}

func newFakeSSM() *fakeSSMClient {
	return &fakeSSMClient{values: map[string]string{}}
}

func (f *fakeSSMClient) GetParameter(_ context.Context, in *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	name := aws.ToString(in.Name)
	v, ok := f.values[name]
	if !ok {
		return nil, &ssmtypes.ParameterNotFound{Message: aws.String("not found")}
	}
	return &ssm.GetParameterOutput{
		Parameter: &ssmtypes.Parameter{
			Name:  aws.String(name),
			Value: aws.String(v),
		},
	}, nil
}

func (f *fakeSSMClient) PutParameter(_ context.Context, in *ssm.PutParameterInput, _ ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.values[aws.ToString(in.Name)] = aws.ToString(in.Value)
	return &ssm.PutParameterOutput{}, nil
}

func newSSMHandle(t *testing.T, client ssmClient) *awsSSMHandle {
	t.Helper()
	return &awsSSMHandle{
		cfg:    awsSSMConfig{Name: "/iron-broker/test"},
		client: client,
	}
}

func TestAWSSSMBuilderRequiresName(t *testing.T) {
	_, err := awsSSMBuilder{}.Build(mustNode(t, `{type: aws_ssm}`), nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "name")
}

func TestAWSSSMRoundTrip(t *testing.T) {
	h := newSSMHandle(t, newFakeSSM())

	mustPut(t, h, CredentialBlob{RefreshToken: "rt-1"})
	got, err := h.Get(t.Context())
	require.NoError(t, err)
	require.Equal(t, "rt-1", got.RefreshToken)

	mustPut(t, h, CredentialBlob{RefreshToken: "rt-2"})
	got, err = h.Get(t.Context())
	require.NoError(t, err)
	require.Equal(t, "rt-2", got.RefreshToken)
}

func TestAWSSSMGetReturnsNotFound(t *testing.T) {
	h := newSSMHandle(t, newFakeSSM())
	_, err := h.Get(t.Context())
	require.ErrorIs(t, err, ErrNotFound)
}
