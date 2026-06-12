package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"
)

// PollInterval is the base interval between sync calls.
const PollInterval = 5 * time.Second

// SyncUpdate is the slice of a SyncResponse passed to the poller's update
// callback. Fields are nil or JSON null when the control plane did not include
// them in this sync.
type SyncUpdate struct {
	Rules      json.RawMessage
	Secrets    json.RawMessage
	Transforms json.RawMessage
	MCP        json.RawMessage
	Postgres   json.RawMessage
}

// Status is a snapshot of the poller's applied control-plane state. The
// management API serves it so an operator (or the sandbox control plane)
// can verify which principal's config this proxy is actually enforcing
// before routing traffic through it.
type Status struct {
	ConfigHash      string    `json:"config_hash"`
	PrincipalID     string    `json:"principal_id"`
	PrincipalStatus string    `json:"principal_status"`
	SyncedOnce      bool      `json:"synced_once"`
	LastSyncAt      time.Time `json:"last_sync_at"`
}

// Poller periodically calls Sync and applies config updates.
type Poller struct {
	client     *Client
	configHash string
	onUpdate   func(SyncUpdate) error
	logger     *slog.Logger

	mu     sync.RWMutex
	status Status
	poke   chan struct{}
}

// NewPoller creates a new sync poller.
func NewPoller(client *Client, initialConfigHash string, onUpdate func(SyncUpdate) error, logger *slog.Logger) *Poller {
	return &Poller{
		client:     client,
		configHash: initialConfigHash,
		onUpdate:   onUpdate,
		logger:     logger,
		poke:       make(chan struct{}, 1),
	}
}

// Poke requests an immediate out-of-band sync. It never blocks: at most one
// poke is queued, and a poke arriving while a sync is in flight coalesces
// into the next loop iteration.
func (p *Poller) Poke() {
	select {
	case p.poke <- struct{}{}:
	default:
	}
}

// Status returns a snapshot of the applied control-plane state.
func (p *Poller) Status() Status {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.status
}

// SeedStatus records the result of a sync performed outside the poller (the
// startup sync in managed mode) so Status reflects it before Run's first
// iteration.
func (p *Poller) SeedStatus(resp *SyncResponse) {
	if resp == nil {
		return
	}
	p.recordSync(resp)
}

func (p *Poller) recordSync(resp *SyncResponse) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.status.ConfigHash = resp.ConfigHash
	p.status.SyncedOnce = true
	p.status.LastSyncAt = time.Now().UTC()
	// Hash-match responses omit the assignment fields; keep the last known
	// values so Status stays meaningful between config changes.
	if resp.Status != "" {
		p.status.PrincipalStatus = resp.Status
	}
	if resp.PrincipalID != "" {
		p.status.PrincipalID = resp.PrincipalID
	}
}

// Run starts the polling loop. It performs an initial sync immediately, then
// polls on PollInterval with ±10% jitter; a Poke wakes it early. Returns when
// ctx is canceled or a revocation error is received.
func (p *Poller) Run(ctx context.Context) error {
	if err := p.sync(ctx); err != nil {
		if isRevocationError(err) {
			return err
		}
		p.logger.Warn("initial sync failed, will retry", slog.String("error", err.Error()))
	}

	for {
		delay := jitteredInterval(PollInterval, 0.1)
		timer := time.NewTimer(delay)

		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		case <-p.poke:
			timer.Stop()
		}

		if err := p.sync(ctx); err != nil {
			if isRevocationError(err) {
				return err
			}
			p.logger.Warn("sync failed", slog.String("error", err.Error()))
			continue
		}
	}
}

func (p *Poller) sync(ctx context.Context) error {
	resp, err := p.client.Sync(ctx, p.configHash)
	if err != nil {
		return err
	}

	hasRules := isNonNullJSON(resp.Rules)
	hasSecrets := isNonNullJSON(resp.Secrets)
	hasTransforms := isNonNullJSON(resp.Transforms)
	hasMCP := isNonNullJSON(resp.MCP)
	hasPostgres := isNonNullJSON(resp.Postgres)

	if hasRules || hasSecrets || hasTransforms || hasMCP || hasPostgres {
		p.logger.Info("config update received from control plane",
			slog.String("config_hash", resp.ConfigHash),
			slog.Bool("has_rules", hasRules),
			slog.Bool("has_secrets", hasSecrets),
			slog.Bool("has_transforms", hasTransforms),
			slog.Bool("has_mcp", hasMCP),
			slog.Bool("has_postgres", hasPostgres),
		)
		if p.onUpdate != nil {
			if err := p.onUpdate(SyncUpdate{
				Rules:      resp.Rules,
				Secrets:    resp.Secrets,
				Transforms: resp.Transforms,
				MCP:        resp.MCP,
				Postgres:   resp.Postgres,
			}); err != nil {
				p.logger.Error("applying config update", slog.String("error", err.Error()))
			}
		}
	}

	p.configHash = resp.ConfigHash
	p.recordSync(resp)
	return nil
}

func isRevocationError(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Code == ErrProxyRevoked
	}
	return false
}

func jitteredInterval(base time.Duration, jitter float64) time.Duration {
	d := float64(base)
	d += (rand.Float64()*2 - 1) * d * jitter
	return time.Duration(d)
}

func isNonNullJSON(data json.RawMessage) bool {
	return len(data) > 0 && string(data) != "null"
}
