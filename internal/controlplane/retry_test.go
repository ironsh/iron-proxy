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
