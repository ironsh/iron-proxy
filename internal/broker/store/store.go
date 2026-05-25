// Package store defines the persistent backing for an iron-token-broker
// credential blob. Each credential gets its own store.Handle whose Get and
// Put move a single JSON document — the rotated access_token, refresh_token,
// expires_at, and last_refresh — to and from one of the configured backends
// (file, 1Password, 1Password Connect, AWS Secrets Manager, AWS SSM
// Parameter Store).
//
// The blob shape is uniform across every backend so operators learn a
// single schema. The store is intentionally dumb: it has no
// optimistic-concurrency primitive. Single-writer-per-credential is the
// operator's responsibility (documented in the README), and the IdP's own
// refresh-token reuse detection is a louder, more reliable signal than any
// version check the broker could synthesize.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// CredentialBlob is the JSON document persisted per credential. The broker
// owns every field: the access_token and refresh_token are minted by the
// IdP, expires_at is derived from the token endpoint's expires_in, and
// last_refresh records the wall-clock time at which the rotation completed.
type CredentialBlob struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	LastRefresh  time.Time `json:"last_refresh"`
}

// Handle is one credential's slot in a backend.
type Handle interface {
	// Name returns a stable display name for logs and metrics. It must not
	// contain secret material.
	Name() string

	// Get returns the current blob. Returns ErrNotFound when no blob has
	// been bootstrapped yet.
	Get(ctx context.Context) (CredentialBlob, error)

	// Put writes blob atomically. Partial writes are not allowed.
	Put(ctx context.Context, blob CredentialBlob) error
}

// ErrNotFound is returned by Get when the backend has no blob for this
// credential. The broker treats this as "needs human bootstrap" and refuses
// to mint tokens until the operator populates the blob.
var ErrNotFound = errors.New("credential blob not found in store")

// marshalBlob serializes blob as the canonical JSON document the broker
// writes to every backend. Indented for human inspection in the file and
// 1Password backends.
func marshalBlob(blob CredentialBlob) ([]byte, error) {
	out, err := json.MarshalIndent(blob, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshalling credential blob: %w", err)
	}
	return out, nil
}

// unmarshalBlob parses a JSON blob produced by marshalBlob or hand-edited
// by an operator during bootstrap. The expiry must be RFC 3339; an
// access_token is not required (the broker will mint one on first refresh)
// but the refresh_token is — without it the broker cannot rotate.
func unmarshalBlob(raw []byte) (CredentialBlob, error) {
	var blob CredentialBlob
	if err := json.Unmarshal(raw, &blob); err != nil {
		return CredentialBlob{}, fmt.Errorf("parsing credential blob: %w", err)
	}
	if blob.RefreshToken == "" {
		return CredentialBlob{}, errors.New("credential blob is missing refresh_token")
	}
	return blob, nil
}
