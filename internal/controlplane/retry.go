package controlplane

import (
	"context"
	"time"

	"github.com/cenkalti/backoff/v5"
)

// WithRetry runs fn with exponential backoff. Non-retryable APIErrors stop
// retries immediately. maxTries of 0 means unlimited.
func WithRetry[T any](ctx context.Context, maxTries uint, fn func() (T, error)) (T, error) {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = 1 * time.Second
	b.MaxInterval = 30 * time.Second
	b.RandomizationFactor = 0.1
	b.Multiplier = 2

	opts := []backoff.RetryOption{
		backoff.WithBackOff(b),
		backoff.WithMaxElapsedTime(0),
	}
	if maxTries > 0 {
		opts = append(opts, backoff.WithMaxTries(maxTries))
	}

	return backoff.Retry(ctx, func() (T, error) {
		val, err := fn()
		if err != nil {
			if apiErr, ok := err.(*APIError); ok && !apiErr.IsRetryable() {
				return val, backoff.Permanent(err)
			}
			return val, err
		}
		return val, nil
	}, opts...)
}
