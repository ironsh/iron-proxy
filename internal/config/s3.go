package config

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// parseS3URL parses an S3 URL of the form s3://bucket/key and returns the
// bucket and key. It returns an error if the URL is malformed.
func parseS3URL(url string) (bucket, key string, err error) {
	rest := strings.TrimPrefix(url, "s3://")
	idx := strings.IndexByte(rest, '/')
	if idx <= 0 || idx == len(rest)-1 {
		return "", "", fmt.Errorf("invalid S3 URL %q: expected s3://bucket/key", url)
	}
	return rest[:idx], rest[idx+1:], nil
}

// parseS3 fetches a config file from S3 and parses it without applying defaults
// or validation. It uses the default AWS credential chain.
func parseS3(ctx context.Context, rawURL string) (*Config, error) {
	bucket, key, err := parseS3URL(rawURL)
	if err != nil {
		return nil, err
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg)
	out, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("fetching s3://%s/%s: %w", bucket, key, err)
	}
	defer out.Body.Close()

	return parse(out.Body)
}

// parseFileOrS3 parses a config from a local file path or an S3 URL without
// applying defaults or validation.
func parseFileOrS3(path string) (*Config, error) {
	if strings.HasPrefix(path, "s3://") {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return parseS3(ctx, path)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening config file: %w", err)
	}
	defer f.Close()

	return parse(f)
}
