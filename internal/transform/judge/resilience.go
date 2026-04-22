package judge

import (
	"sync"
	"time"
)

const (
	defaultConsecutiveFailures = 5
	defaultCooldown            = 10 * time.Second
)

// breakerConfig is the YAML-decodable configuration for a per-instance breaker.
type breakerConfig struct {
	ConsecutiveFailures int           `yaml:"consecutive_failures"`
	Cooldown            time.Duration `yaml:"cooldown"`
}

type breakerState int

const (
	stateClosed breakerState = iota
	stateOpen
	stateHalfOpen
)

// circuitBreaker is a minimal consecutive-failure breaker with a single probe
// in the half-open state. One instance per judge transform; no sharing.
type circuitBreaker struct {
	mu            sync.Mutex
	threshold     int
	cooldown      time.Duration
	failures      int
	openedAt      time.Time
	state         breakerState
	halfOpenInUse bool
	now           func() time.Time
}

func newCircuitBreaker(cfg breakerConfig) *circuitBreaker {
	threshold := cfg.ConsecutiveFailures
	if threshold <= 0 {
		threshold = defaultConsecutiveFailures
	}
	cooldown := cfg.Cooldown
	if cooldown <= 0 {
		cooldown = defaultCooldown
	}
	return &circuitBreaker{
		threshold: threshold,
		cooldown:  cooldown,
		now:       time.Now,
	}
}

// allow reports whether the caller may attempt a call. If ok is true, the
// caller MUST invoke permit(success) exactly once after the call completes.
// If ok is false, the breaker rejected the call and permit is nil.
func (b *circuitBreaker) allow() (permit func(success bool), ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	switch b.state {
	case stateClosed:
		return b.makePermit(false), true

	case stateOpen:
		if b.now().Sub(b.openedAt) < b.cooldown {
			return nil, false
		}
		b.state = stateHalfOpen
		b.halfOpenInUse = true
		return b.makePermit(true), true

	case stateHalfOpen:
		if b.halfOpenInUse {
			return nil, false
		}
		b.halfOpenInUse = true
		return b.makePermit(true), true
	}
	return nil, false
}

// makePermit returns a one-shot settle function. When halfOpen is true, the
// call is treated as a probe: success transitions to closed, failure reopens.
func (b *circuitBreaker) makePermit(halfOpen bool) func(success bool) {
	var once sync.Once
	return func(success bool) {
		once.Do(func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			if halfOpen {
				b.halfOpenInUse = false
			}
			if success {
				b.failures = 0
				b.state = stateClosed
				b.openedAt = time.Time{}
				return
			}
			if halfOpen {
				b.state = stateOpen
				b.openedAt = b.now()
				return
			}
			b.failures++
			if b.failures >= b.threshold {
				b.state = stateOpen
				b.openedAt = b.now()
			}
		})
	}
}
