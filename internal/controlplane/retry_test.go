package controlplane

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRetrySuccess(t *testing.T) {
	calls := 0
	err := Retry(context.Background(), RetryConfig{
		MaxAttempts: 5,
		BaseDelay:   1 * time.Millisecond,
		MaxDelay:    10 * time.Millisecond,
		Jitter:      0,
	}, func() error {
		calls++
		if calls < 3 {
			return errors.New("transient")
		}
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 3, calls)
}

func TestRetryMaxAttempts(t *testing.T) {
	calls := 0
	err := Retry(context.Background(), RetryConfig{
		MaxAttempts: 3,
		BaseDelay:   1 * time.Millisecond,
		MaxDelay:    10 * time.Millisecond,
		Jitter:      0,
	}, func() error {
		calls++
		return errors.New("always fails")
	})
	require.Error(t, err)
	require.Equal(t, 3, calls)
}

func TestRetryNonRetryableAPIError(t *testing.T) {
	calls := 0
	err := Retry(context.Background(), RetryConfig{
		MaxAttempts: 5,
		BaseDelay:   1 * time.Millisecond,
		MaxDelay:    10 * time.Millisecond,
		Jitter:      0,
	}, func() error {
		calls++
		return &APIError{StatusCode: 401, Code: ErrInvalidToken}
	})
	require.Error(t, err)
	require.Equal(t, 1, calls, "should not retry non-retryable errors")
}

func TestRetryRetryableAPIError(t *testing.T) {
	calls := 0
	err := Retry(context.Background(), RetryConfig{
		MaxAttempts: 3,
		BaseDelay:   1 * time.Millisecond,
		MaxDelay:    10 * time.Millisecond,
		Jitter:      0,
	}, func() error {
		calls++
		if calls < 3 {
			return &APIError{StatusCode: 429, Code: "rate_limited"}
		}
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 3, calls)
}

func TestRetryContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := Retry(ctx, RetryConfig{
		MaxAttempts: 5,
		BaseDelay:   1 * time.Second,
		MaxDelay:    10 * time.Second,
		Jitter:      0,
	}, func() error {
		return errors.New("fail")
	})
	require.ErrorIs(t, err, context.Canceled)
}

func TestBackoffDelay(t *testing.T) {
	cfg := RetryConfig{
		BaseDelay: 1 * time.Second,
		MaxDelay:  30 * time.Second,
		Jitter:    0,
	}

	require.Equal(t, 1*time.Second, backoffDelay(cfg, 0))
	require.Equal(t, 2*time.Second, backoffDelay(cfg, 1))
	require.Equal(t, 4*time.Second, backoffDelay(cfg, 2))
	require.Equal(t, 8*time.Second, backoffDelay(cfg, 3))
	require.Equal(t, 16*time.Second, backoffDelay(cfg, 4))
	require.Equal(t, 30*time.Second, backoffDelay(cfg, 5)) // capped
}

func TestBackoffDelayWithJitter(t *testing.T) {
	cfg := RetryConfig{
		BaseDelay: 10 * time.Second,
		MaxDelay:  60 * time.Second,
		Jitter:    0.1,
	}

	for i := 0; i < 100; i++ {
		d := backoffDelay(cfg, 0)
		require.InDelta(t, float64(10*time.Second), float64(d), float64(1*time.Second)+1)
	}
}
