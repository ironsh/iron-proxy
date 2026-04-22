package judge

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBreaker_OpensAfterThresholdFailures(t *testing.T) {
	b := newCircuitBreaker(breakerConfig{ConsecutiveFailures: 3, Cooldown: time.Second})

	for i := 0; i < 3; i++ {
		permit, ok := b.allow()
		require.True(t, ok, "call %d should be admitted", i)
		permit(false)
	}

	_, ok := b.allow()
	require.False(t, ok, "breaker should be open after threshold failures")
}

func TestBreaker_SuccessResetsFailureCounter(t *testing.T) {
	b := newCircuitBreaker(breakerConfig{ConsecutiveFailures: 3, Cooldown: time.Second})

	for i := 0; i < 2; i++ {
		permit, _ := b.allow()
		permit(false)
	}
	permit, _ := b.allow()
	permit(true) // reset counter

	for i := 0; i < 2; i++ {
		permit, _ := b.allow()
		permit(false)
	}
	// After 2 more failures (counter reset), breaker still closed.
	_, ok := b.allow()
	require.True(t, ok, "breaker should still be closed after counter reset")
}

func TestBreaker_HalfOpenProbeAfterCooldown(t *testing.T) {
	fakeNow := time.Unix(1_700_000_000, 0)
	b := newCircuitBreaker(breakerConfig{ConsecutiveFailures: 2, Cooldown: 10 * time.Second})
	b.now = func() time.Time { return fakeNow }

	// Trip the breaker.
	for i := 0; i < 2; i++ {
		permit, _ := b.allow()
		permit(false)
	}
	_, ok := b.allow()
	require.False(t, ok, "breaker should be open")

	// Advance past cooldown.
	fakeNow = fakeNow.Add(11 * time.Second)

	probe, ok := b.allow()
	require.True(t, ok, "probe should be admitted after cooldown")

	// A concurrent second caller still sees breaker as open (half-open probe in progress).
	_, ok2 := b.allow()
	require.False(t, ok2, "second caller should see breaker as open while probe is in-flight")

	probe(true)
}

func TestBreaker_HalfOpenSuccessCloses(t *testing.T) {
	fakeNow := time.Unix(1_700_000_000, 0)
	b := newCircuitBreaker(breakerConfig{ConsecutiveFailures: 1, Cooldown: 5 * time.Second})
	b.now = func() time.Time { return fakeNow }

	permit, _ := b.allow()
	permit(false)

	fakeNow = fakeNow.Add(6 * time.Second)

	probe, ok := b.allow()
	require.True(t, ok)
	probe(true)

	// Fresh calls should now be admitted freely.
	permit, ok = b.allow()
	require.True(t, ok)
	permit(true)
}

func TestBreaker_HalfOpenFailureReopensWithFreshCooldown(t *testing.T) {
	fakeNow := time.Unix(1_700_000_000, 0)
	b := newCircuitBreaker(breakerConfig{ConsecutiveFailures: 1, Cooldown: 5 * time.Second})
	b.now = func() time.Time { return fakeNow }

	permit, _ := b.allow()
	permit(false)

	fakeNow = fakeNow.Add(6 * time.Second)

	probe, ok := b.allow()
	require.True(t, ok)
	probe(false)

	// Still within the fresh cooldown (just refreshed), should be rejected.
	_, ok = b.allow()
	require.False(t, ok, "probe failure should re-open with fresh cooldown")

	// Advance past fresh cooldown.
	fakeNow = fakeNow.Add(6 * time.Second)
	_, ok = b.allow()
	require.True(t, ok, "breaker should admit a new probe after the fresh cooldown elapses")
}

func TestBreaker_DefaultsApplied(t *testing.T) {
	b := newCircuitBreaker(breakerConfig{})
	require.Equal(t, defaultConsecutiveFailures, b.threshold)
	require.Equal(t, defaultCooldown, b.cooldown)
}
