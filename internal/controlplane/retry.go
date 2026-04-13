package controlplane

import (
	"context"
	"time"

	"github.com/cenkalti/backoff/v5"
)

// RetryConfig controls exponential backoff behavior.
type RetryConfig struct {
	MaxAttempts int           // 0 means unlimited
	BaseDelay   time.Duration
	MaxDelay    time.Duration
	Jitter      float64 // randomization factor, e.g. 0.1 = ±10%
}

// DefaultRegisterRetry is the retry config for registration calls.
var DefaultRegisterRetry = RetryConfig{
	MaxAttempts: 5,
	BaseDelay:   1 * time.Second,
	MaxDelay:    30 * time.Second,
	Jitter:      0.1,
}

// DefaultSyncRetry is the retry config for sync calls (unlimited attempts).
var DefaultSyncRetry = RetryConfig{
	MaxAttempts: 0,
	BaseDelay:   1 * time.Second,
	MaxDelay:    30 * time.Second,
	Jitter:      0.1,
}

// Retry executes fn with exponential backoff. It stops when fn returns nil,
// the context is canceled, MaxAttempts is reached, or fn returns a non-retryable APIError.
func Retry(ctx context.Context, cfg RetryConfig, fn func() error) error {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = cfg.BaseDelay
	b.MaxInterval = cfg.MaxDelay
	b.RandomizationFactor = cfg.Jitter
	b.Multiplier = 2

	opts := []backoff.RetryOption{
		backoff.WithBackOff(b),
		backoff.WithMaxElapsedTime(0),
	}
	if cfg.MaxAttempts > 0 {
		opts = append(opts, backoff.WithMaxTries(uint(cfg.MaxAttempts)))
	}

	_, err := backoff.Retry(ctx, func() (struct{}, error) {
		err := fn()
		if err == nil {
			return struct{}{}, nil
		}
		if apiErr, ok := err.(*APIError); ok && !apiErr.IsRetryable() {
			return struct{}{}, backoff.Permanent(err)
		}
		return struct{}{}, err
	}, opts...)

	return err
}
