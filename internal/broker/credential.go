package broker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v5"
	"golang.org/x/sync/singleflight"

	"github.com/ironsh/iron-proxy/internal/broker/config"
	"github.com/ironsh/iron-proxy/internal/broker/store"
)

// credentialState is the broker's in-memory view of one credential. The
// store.Handle owns durable state; this struct exists so handlers and the
// refresh loop can share a fast cached copy.
type credentialState struct {
	cfg config.BuiltCredential
	log *slog.Logger
	met *metrics

	now func() time.Time // injectable for tests; defaults to time.Now

	refresh *refreshClient

	mu         sync.RWMutex
	blob       store.CredentialBlob
	haveBlob   bool   // false until the first successful store load
	dead       bool   // true after an unrecoverable error
	deadReason string // metric/HTTP body explanation when dead

	sf singleflight.Group
}

// newCredentialState wires a BuiltCredential into a state machine. The
// HTTP client is shared across credentials to amortize TLS handshakes.
func newCredentialState(cfg config.BuiltCredential, log *slog.Logger, met *metrics, http *http.Client) *credentialState {
	return &credentialState{
		cfg:     cfg,
		log:     log.With(slog.String("credential_id", cfg.ID)),
		met:     met,
		now:     time.Now,
		refresh: newRefreshClient(http),
	}
}

// load fetches the durable blob from the store. Called from Run() at
// startup and never again — subsequent refreshes go through doRefresh
// which writes back through the store and updates the in-memory copy
// atomically.
func (c *credentialState) load(ctx context.Context) error {
	blob, err := c.cfg.Store.Get(ctx)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.blob = blob
	c.haveBlob = true
	c.mu.Unlock()
	c.met.setTokenWindow(c.cfg.ID, blob.LastRefresh, blob.ExpiresAt, c.now())
	return nil
}

// loadWithBackoff retries the initial load against a flaky store. A brief
// AWS/1Password/network outage on boot must not leave the credential
// permanently dead — operators expect process-restart-equivalent recovery
// without an actual process restart. ErrNotFound short-circuits as a
// permanent (operator-bootstrap-required) error.
func (c *credentialState) loadWithBackoff(ctx context.Context) error {
	bo := backoff.NewExponentialBackOff()
	bo.InitialInterval = 2 * time.Second
	bo.RandomizationFactor = 0.3
	bo.Multiplier = 2
	bo.MaxInterval = 1 * time.Minute

	op := func() (struct{}, error) {
		err := c.load(ctx)
		if err == nil {
			return struct{}{}, nil
		}
		if errors.Is(err, store.ErrNotFound) {
			return struct{}{}, backoff.Permanent(err)
		}
		c.log.Warn("store load failed; will retry",
			slog.String("store", c.cfg.Store.Name()),
			slog.String("error", err.Error()),
		)
		return struct{}{}, err
	}
	_, err := backoff.Retry(ctx, op,
		backoff.WithBackOff(bo),
		backoff.WithMaxElapsedTime(15*time.Minute),
	)
	return err
}

// markDead transitions the credential into the dead state. Idempotent;
// subsequent reasons are ignored so the first cause sticks.
func (c *credentialState) markDead(reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dead {
		return
	}
	c.dead = true
	c.deadReason = reason
	c.log.Error("credential marked dead; human re-auth required",
		slog.String("reason", reason),
	)
	c.met.setDead(c.cfg.ID, reason, true)
}

// snapshot returns a copy of the cached blob plus liveness flags. Cheap
// (RLock) — used on every HTTP request to serve the access token.
func (c *credentialState) snapshot() (blob store.CredentialBlob, ready, dead bool, reason string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.blob, c.haveBlob, c.dead, c.deadReason
}

// nextRefreshAt computes the wall-clock time at which the credential's
// loop should perform its next refresh. The result is min(early-refresh,
// max-interval-ceiling). When the blob is uninitialized (no load yet)
// the caller schedules an immediate refresh.
func (c *credentialState) nextRefreshAt() time.Time {
	c.mu.RLock()
	blob := c.blob
	ready := c.haveBlob
	c.mu.RUnlock()
	if !ready {
		return c.now() // refresh immediately on first iteration
	}
	earlySlack := c.cfg.EarlyRefreshSlack
	if frac := c.cfg.EarlyRefreshFraction; frac > 0 && !blob.ExpiresAt.IsZero() {
		ttl := blob.ExpiresAt.Sub(blob.LastRefresh)
		if ttl > 0 {
			fracSlack := time.Duration(float64(ttl) * frac)
			if fracSlack > earlySlack {
				earlySlack = fracSlack
			}
		}
	}
	// Floor: never schedule less than 60s before expiry. For short-lived
	// tokens (e.g. 15-minute Anthropic windows) this keeps the refresh
	// well within the access token's lifetime.
	if earlySlack < 60*time.Second {
		earlySlack = 60 * time.Second
	}
	early := blob.ExpiresAt.Add(-earlySlack)
	ceiling := blob.LastRefresh.Add(c.cfg.MaxRefreshInterval)
	if blob.LastRefresh.IsZero() {
		// Bootstrap blob without a last_refresh: fall back to the early
		// trigger only.
		return early
	}
	if early.Before(ceiling) {
		return early
	}
	return ceiling
}

// doRefresh resolves credentials, calls the IdP, writes the blob back to
// the store, and updates the cached copy. Single-flighted by sf so the
// scheduled wake and an in-band HTTP request don't double-refresh.
//
// Two HTTP requests can join one in-flight refresh: the leader runs the
// closure, every later caller waits on the same result channel. Two
// hazards fall out of that and are both handled here:
//
//  1. Leader cancellation must not poison the waiters. We detach the
//     inner ctx from any specific caller so a single client disconnect
//     can't cancel a refresh other handlers are blocked on. The detached
//     ctx still carries a deadline so a hung IdP can't pin the
//     singleflight forever.
//  2. Waiter cancellation must not block on the leader. We use DoChan
//     and select on the caller's ctx so a slow IdP doesn't pin a
//     handler whose own client has already given up; the leader keeps
//     running for any remaining waiters and updates the cache for the
//     next request.
func (c *credentialState) doRefresh(ctx context.Context) error {
	ch := c.sf.DoChan("refresh", func() (any, error) {
		detached, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.cfg.RefreshTimeout)
		defer cancel()
		return nil, c.refreshOnce(detached)
	})
	select {
	case res := <-ch:
		return res.Err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *credentialState) refreshOnce(ctx context.Context) error {
	// Snapshot the current blob under RLock; the actual refresh and
	// write happens outside the lock so concurrent reads (RLock) can
	// proceed in parallel with the IdP round trip.
	c.mu.RLock()
	prevBlob := c.blob
	hasBlob := c.haveBlob
	c.mu.RUnlock()
	if !hasBlob {
		return errors.New("credential blob not loaded")
	}

	clientID, err := c.cfg.ClientID.Get(ctx)
	if err != nil {
		return fmt.Errorf("resolving client_id from %q: %w", c.cfg.ClientID.Name(), err)
	}
	var clientSecret string
	if c.cfg.ClientSecret != nil {
		clientSecret, err = c.cfg.ClientSecret.Get(ctx)
		if err != nil {
			return fmt.Errorf("resolving client_secret from %q: %w", c.cfg.ClientSecret.Name(), err)
		}
	}
	var headers map[string]string
	if len(c.cfg.TokenEndpointHeaders) > 0 {
		headers = make(map[string]string, len(c.cfg.TokenEndpointHeaders))
		for name, src := range c.cfg.TokenEndpointHeaders {
			v, err := src.Get(ctx)
			if err != nil {
				return fmt.Errorf("resolving token_endpoint_headers[%q] from %q: %w", name, src.Name(), err)
			}
			headers[name] = v
		}
	}

	start := c.now()
	out, err := c.refresh.Refresh(ctx, refreshRequest{
		TokenEndpoint: c.cfg.TokenEndpoint,
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		RefreshToken:  prevBlob.RefreshToken,
		Scopes:        c.cfg.Scopes,
		Headers:       headers,
	})
	elapsed := c.now().Sub(start)
	if err != nil {
		c.recordRefreshFailure(err, elapsed)
		return err
	}

	newBlob := store.CredentialBlob{
		AccessToken:  out.AccessToken,
		RefreshToken: prevBlob.RefreshToken,
		ExpiresAt:    c.now().Add(out.ExpiresIn),
		LastRefresh:  c.now(),
	}
	if out.RefreshToken != "" {
		newBlob.RefreshToken = out.RefreshToken
	}
	if out.ExpiresIn <= 0 {
		// Some IdPs omit expires_in. Pick a conservative default so the
		// loop refreshes before the token quietly stops working: 5
		// minutes is short enough to catch a misconfigured response and
		// long enough not to hammer the IdP.
		newBlob.ExpiresAt = c.now().Add(5 * time.Minute)
	}

	if err := c.cfg.Store.Put(ctx, newBlob); err != nil {
		c.met.recordRefresh(c.cfg.ID, resultTransient, "store_io", elapsed)
		c.log.Warn("store Put failed, refresh did not persist",
			slog.String("store", c.cfg.Store.Name()),
			slog.String("error", err.Error()),
		)
		return err
	}

	c.mu.Lock()
	c.blob = newBlob
	c.mu.Unlock()

	c.met.recordRefresh(c.cfg.ID, resultSuccess, "", elapsed)
	c.met.setTokenWindow(c.cfg.ID, newBlob.LastRefresh, newBlob.ExpiresAt, c.now())
	c.log.Info("credential refreshed",
		slog.Time("expires_at", newBlob.ExpiresAt),
	)
	return nil
}

func (c *credentialState) recordRefreshFailure(err error, elapsed time.Duration) {
	var rErr *refreshError
	if !errors.As(err, &rErr) {
		c.met.recordRefresh(c.cfg.ID, resultTransient, "unknown", elapsed)
		c.log.Warn("refresh failed", slog.String("error", err.Error()))
		return
	}
	code := rErr.Code
	if code == "" {
		code = string(rErr.Stage)
	}
	if rErr.Retryable {
		c.met.recordRefresh(c.cfg.ID, resultTransient, code, elapsed)
		c.log.Warn("refresh failed (retryable)",
			slog.String("stage", string(rErr.Stage)),
			slog.String("code", rErr.Code),
			slog.Int("status", rErr.StatusCode),
			slog.String("error", rErr.Error()),
		)
		return
	}
	c.met.recordRefresh(c.cfg.ID, resultUnrecoverable, code, elapsed)
	c.markDead(code)
}

// Run drives the credential's refresh loop until ctx is cancelled. The
// loop is best-effort: a transient failure schedules a backoff retry,
// and an unrecoverable failure leaves the credential in the dead state
// (which doesn't terminate the goroutine — the loop continues to wait so
// operators can re-bootstrap the credential and a future SIGHUP can pick
// it back up; today the operator must restart the broker, but the loop
// shape leaves the door open).
func (c *credentialState) Run(ctx context.Context) {
	if err := c.loadWithBackoff(ctx); err != nil {
		// ErrNotFound is operator-action-required: the bootstrap blob
		// hasn't been populated. Other errors only land here after the
		// backoff loop has exhausted, which by then is either a sustained
		// store outage (operator visible via metrics + logs) or
		// ctx-cancellation during shutdown.
		if errors.Is(err, store.ErrNotFound) {
			c.markDead("blob_not_bootstrapped")
		} else if ctx.Err() == nil {
			c.markDead("blob_load_failed")
			c.log.Error("loading credential blob failed after retries",
				slog.String("store", c.cfg.Store.Name()),
				slog.String("error", err.Error()),
			)
		}
		c.waitForCancel(ctx)
		return
	}

	for {
		if isDead := c.isDead(); isDead {
			c.waitForCancel(ctx)
			return
		}

		when := c.nextRefreshAt()
		delay := when.Sub(c.now())
		if delay < 0 {
			delay = 0
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		if err := c.refreshWithBackoff(ctx, scheduledBackoffMax); err != nil {
			// refreshWithBackoff already classified and recorded the
			// error; loop continues so the next scheduled wake can try
			// again unless we were marked dead.
			if !c.isDead() && ctx.Err() == nil {
				c.log.Warn("refresh round abandoned after backoff exhaustion",
					slog.String("error", err.Error()),
				)
			}
		}
	}
}

func (c *credentialState) isDead() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.dead
}

func (c *credentialState) waitForCancel(ctx context.Context) {
	<-ctx.Done()
}

// refreshWithBackoff retries doRefresh until either success, an
// unrecoverable error (which marks the credential dead), the context is
// cancelled, or maxElapsed has passed. doRefresh itself bounds each
// attempt by RefreshTimeout on its detached inner context, so the loop
// here only owns the retry cadence.
//
// maxElapsed governs how long the *whole* retry loop is allowed to
// take. The scheduled loop uses a long ceiling (hours) because retrying
// matters; the in-band HTTP path uses a short one (seconds) so a stale
// token doesn't make iron-proxy clients hang during an IdP outage.
func (c *credentialState) refreshWithBackoff(ctx context.Context, maxElapsed time.Duration) error {
	bo := backoff.NewExponentialBackOff()
	bo.InitialInterval = 5 * time.Second
	bo.RandomizationFactor = 0.3
	bo.Multiplier = 2
	bo.MaxInterval = 5 * time.Minute

	op := func() (struct{}, error) {
		err := c.doRefresh(ctx)
		if err == nil {
			return struct{}{}, nil
		}
		if c.isDead() {
			return struct{}{}, backoff.Permanent(err)
		}
		var rErr *refreshError
		if errors.As(err, &rErr) && !rErr.Retryable {
			return struct{}{}, backoff.Permanent(err)
		}
		return struct{}{}, err
	}
	_, err := backoff.Retry(ctx, op,
		backoff.WithBackOff(bo),
		backoff.WithMaxElapsedTime(maxElapsed),
	)
	return err
}

// Backoff windows. The scheduled loop tolerates hours of IdP downtime;
// the HTTP handler must not — an iron-proxy client request would block
// for the full window otherwise.
const (
	scheduledBackoffMax = 5 * time.Hour
	inBandBackoffMax    = 30 * time.Second
)

// AccessToken returns the cached access token, single-flighting a
// refresh if the token is stale. Used by the HTTP handler.
func (c *credentialState) AccessToken(ctx context.Context) (string, time.Time, error) {
	blob, ready, dead, reason := c.snapshot()
	if dead {
		return "", time.Time{}, &deadError{reason: reason}
	}
	if !ready {
		return "", time.Time{}, errNotReady
	}
	if blob.AccessToken != "" && c.now().Before(blob.ExpiresAt) {
		return blob.AccessToken, blob.ExpiresAt, nil
	}
	// Stale or empty cached token. Drive an in-band refresh through the
	// single-flight gate so concurrent handlers share one round trip.
	if err := c.refreshWithBackoff(ctx, inBandBackoffMax); err != nil {
		if c.isDead() {
			_, _, _, reason := c.snapshot()
			return "", time.Time{}, &deadError{reason: reason}
		}
		return "", time.Time{}, err
	}
	blob, _, dead, reason = c.snapshot()
	if dead {
		return "", time.Time{}, &deadError{reason: reason}
	}
	return blob.AccessToken, blob.ExpiresAt, nil
}

// deadError signals to HTTP handlers that the credential is in the dead
// state. Carries the operator-facing reason so it can land in the 422
// response body.
type deadError struct{ reason string }

func (e *deadError) Error() string { return "credential dead: " + e.reason }

// errNotReady is returned when AccessToken is called before the first
// store load completes — the bootstrap window. HTTP responds with 503
// + Retry-After.
var errNotReady = errors.New("credential not ready (bootstrapping)")
