package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"gopkg.in/yaml.v3"
)

type awsSSMBuilder struct{}

type awsSSMConfig struct {
	Type   string `yaml:"type"`
	Name   string `yaml:"name"`
	Region string `yaml:"region,omitempty"`
}

func (awsSSMBuilder) Build(raw yaml.Node, logger *slog.Logger) (Handle, error) {
	var cfg awsSSMConfig
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing aws_ssm store config: %w", err)
	}
	if cfg.Name == "" {
		return nil, fmt.Errorf("aws_ssm store requires \"name\" field")
	}
	return &awsSSMHandle{cfg: cfg, logger: logger}, nil
}

// ssmClient is the subset of the AWS SSM API used by awsSSMHandle.
type ssmClient interface {
	GetParameter(ctx context.Context, in *ssm.GetParameterInput, opts ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
	PutParameter(ctx context.Context, in *ssm.PutParameterInput, opts ...func(*ssm.Options)) (*ssm.PutParameterOutput, error)
}

// awsSSMHandle persists the credential blob as a SecureString parameter.
type awsSSMHandle struct {
	cfg    awsSSMConfig
	logger *slog.Logger

	mu     sync.Mutex
	client ssmClient
}

func (h *awsSSMHandle) Name() string {
	return "aws_ssm:" + h.cfg.Name
}

func (h *awsSSMHandle) Get(ctx context.Context) (CredentialBlob, error) {
	client, err := h.getClient(ctx)
	if err != nil {
		return CredentialBlob{}, err
	}
	out, err := client.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(h.cfg.Name),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		var notFound *ssmtypes.ParameterNotFound
		if errors.As(err, &notFound) {
			return CredentialBlob{}, ErrNotFound
		}
		return CredentialBlob{}, fmt.Errorf("aws_ssm GetParameter %q: %w", h.cfg.Name, err)
	}
	if out.Parameter == nil {
		return CredentialBlob{}, fmt.Errorf("aws_ssm parameter %q resolved without a value", h.cfg.Name)
	}
	raw := aws.ToString(out.Parameter.Value)
	if raw == "" {
		return CredentialBlob{}, fmt.Errorf("aws_ssm parameter %q has empty value", h.cfg.Name)
	}
	blob, err := unmarshalBlob([]byte(raw))
	if err != nil {
		return CredentialBlob{}, fmt.Errorf("aws_ssm %q: %w", h.cfg.Name, err)
	}
	return blob, nil
}

func (h *awsSSMHandle) Put(ctx context.Context, blob CredentialBlob) error {
	client, err := h.getClient(ctx)
	if err != nil {
		return err
	}
	raw, err := marshalBlob(blob)
	if err != nil {
		return err
	}
	if _, err := client.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(h.cfg.Name),
		Value:     aws.String(string(raw)),
		Type:      ssmtypes.ParameterTypeSecureString,
		Overwrite: aws.Bool(true),
	}); err != nil {
		return fmt.Errorf("aws_ssm PutParameter %q: %w", h.cfg.Name, err)
	}
	return nil
}

func (h *awsSSMHandle) getClient(ctx context.Context) (ssmClient, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.client != nil {
		return h.client, nil
	}
	var opts []func(*awsconfig.LoadOptions) error
	if h.cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(h.cfg.Region))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	h.client = ssm.NewFromConfig(awsCfg)
	return h.client, nil
}
