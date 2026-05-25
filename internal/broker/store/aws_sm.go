package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"gopkg.in/yaml.v3"
)

type awsSMBuilder struct{}

type awsSMConfig struct {
	Type     string `yaml:"type"`
	SecretID string `yaml:"secret_id"`
	Region   string `yaml:"region,omitempty"`
}

func (awsSMBuilder) Build(raw yaml.Node, logger *slog.Logger) (Handle, error) {
	var cfg awsSMConfig
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing aws_sm store config: %w", err)
	}
	if cfg.SecretID == "" {
		return nil, fmt.Errorf("aws_sm store requires \"secret_id\" field")
	}
	return &awsSMHandle{cfg: cfg, logger: logger}, nil
}

// smClient is the subset of the AWS Secrets Manager API used by awsSMHandle,
// narrowed for testability.
type smClient interface {
	GetSecretValue(ctx context.Context, in *secretsmanager.GetSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
	PutSecretValue(ctx context.Context, in *secretsmanager.PutSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error)
}

// awsSMHandle persists the credential blob as the AWSCURRENT version of a
// Secrets Manager secret.
type awsSMHandle struct {
	cfg    awsSMConfig
	logger *slog.Logger

	mu     sync.Mutex
	client smClient
}

func (h *awsSMHandle) Name() string {
	return "aws_sm:" + h.cfg.SecretID
}

func (h *awsSMHandle) Get(ctx context.Context) (CredentialBlob, error) {
	client, err := h.getClient(ctx)
	if err != nil {
		return CredentialBlob{}, err
	}
	out, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(h.cfg.SecretID),
	})
	if err != nil {
		var notFound *smtypes.ResourceNotFoundException
		if errors.As(err, &notFound) {
			return CredentialBlob{}, ErrNotFound
		}
		return CredentialBlob{}, fmt.Errorf("aws_sm GetSecretValue %q: %w", h.cfg.SecretID, err)
	}
	raw := aws.ToString(out.SecretString)
	if raw == "" {
		return CredentialBlob{}, fmt.Errorf("aws_sm secret %q has empty SecretString", h.cfg.SecretID)
	}
	blob, err := unmarshalBlob([]byte(raw))
	if err != nil {
		return CredentialBlob{}, fmt.Errorf("aws_sm %q: %w", h.cfg.SecretID, err)
	}
	return blob, nil
}

func (h *awsSMHandle) Put(ctx context.Context, blob CredentialBlob) error {
	client, err := h.getClient(ctx)
	if err != nil {
		return err
	}
	raw, err := marshalBlob(blob)
	if err != nil {
		return err
	}
	if _, err := client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
		SecretId:     aws.String(h.cfg.SecretID),
		SecretString: aws.String(string(raw)),
	}); err != nil {
		return fmt.Errorf("aws_sm PutSecretValue %q: %w", h.cfg.SecretID, err)
	}
	return nil
}

func (h *awsSMHandle) getClient(ctx context.Context) (smClient, error) {
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
	h.client = secretsmanager.NewFromConfig(awsCfg)
	return h.client, nil
}
