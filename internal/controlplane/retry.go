package controlplane

import (
	"context"
	"math"
	"math/rand/v2"
	"time"
)

// RetryConfig controls exponential backoff behavior.
type RetryConfig struct {
	MaxAttempts int           // 0 means unlimited
	BaseDelay   time.Duration
	MaxDelay    time.Duration
	Jitter      float64 // fraction of delay to add/subtract, e.g. 0.1 = ±10%
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
	for attempt := 0; ; attempt++ {
		err := fn()
		if err == nil {
			return nil
		}

		if apiErr, ok := err.(*APIError); ok && !apiErr.IsRetryable() {
			return err
		}

		if cfg.MaxAttempts > 0 && attempt+1 >= cfg.MaxAttempts {
			return err
		}

		delay := backoffDelay(cfg, attempt)

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func backoffDelay(cfg RetryConfig, attempt int) time.Duration {
	delay := float64(cfg.BaseDelay) * math.Pow(2, float64(attempt))
	if delay > float64(cfg.MaxDelay) {
		delay = float64(cfg.MaxDelay)
	}

	if cfg.Jitter > 0 {
		jitter := delay * cfg.Jitter
		delay += (rand.Float64()*2 - 1) * jitter
	}

	return time.Duration(delay)
}
