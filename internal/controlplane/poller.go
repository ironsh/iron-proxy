package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math/rand/v2"
	"time"
)

// PollInterval is the base interval between sync calls.
const PollInterval = 5 * time.Second

// Poller periodically calls Sync and applies config updates.
type Poller struct {
	client     *Client
	configHash string
	onUpdate   func(rules json.RawMessage, secrets json.RawMessage) error
	logger     *slog.Logger
}

// NewPoller creates a new sync poller.
func NewPoller(client *Client, initialConfigHash string, onUpdate func(json.RawMessage, json.RawMessage) error, logger *slog.Logger) *Poller {
	return &Poller{
		client:     client,
		configHash: initialConfigHash,
		onUpdate:   onUpdate,
		logger:     logger,
	}
}

// Run starts the polling loop. It performs an initial sync immediately, then
// polls on PollInterval with ±10% jitter. Returns when ctx is canceled or
// a revocation error is received.
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

	if hasRules || hasSecrets {
		p.logger.Info("config update received from control plane",
			slog.String("config_hash", resp.ConfigHash),
			slog.Bool("has_rules", hasRules),
			slog.Bool("has_secrets", hasSecrets),
		)
		if p.onUpdate != nil {
			if err := p.onUpdate(resp.Rules, resp.Secrets); err != nil {
				p.logger.Error("applying config update", slog.String("error", err.Error()))
			}
		}
	}

	p.configHash = resp.ConfigHash
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
