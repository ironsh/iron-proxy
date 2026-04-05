package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseS3URL(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		wantBucket string
		wantKey    string
		wantErr    string
	}{
		{
			name:       "simple",
			url:        "s3://my-bucket/config.yaml",
			wantBucket: "my-bucket",
			wantKey:    "config.yaml",
		},
		{
			name:       "nested key",
			url:        "s3://my-bucket/path/to/config.yaml",
			wantBucket: "my-bucket",
			wantKey:    "path/to/config.yaml",
		},
		{
			name:    "missing key",
			url:     "s3://my-bucket/",
			wantErr: "invalid S3 URL",
		},
		{
			name:    "missing key no slash",
			url:     "s3://my-bucket",
			wantErr: "invalid S3 URL",
		},
		{
			name:    "empty bucket",
			url:     "s3:///key",
			wantErr: "invalid S3 URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bucket, key, err := parseS3URL(tt.url)
			if tt.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantBucket, bucket)
			require.Equal(t, tt.wantKey, key)
		})
	}
}
