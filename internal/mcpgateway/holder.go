package mcpgateway

import "sync/atomic"

// Holder holds an atomically swappable Gateway pointer.
type Holder struct {
	g atomic.Pointer[Gateway]
}

// NewHolder creates a Holder with the given initial gateway.
func NewHolder(initial *Gateway) *Holder {
	h := &Holder{}
	h.g.Store(initial)
	return h
}

// Load returns the current gateway snapshot, or nil if none is configured.
func (h *Holder) Load() *Gateway {
	if h == nil {
		return nil
	}
	return h.g.Load()
}

// Store atomically replaces the current gateway with next.
func (h *Holder) Store(next *Gateway) {
	h.g.Store(next)
}
