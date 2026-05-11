package mcp

import "sync/atomic"

// PolicyHolder holds an atomically swappable Policy pointer. It is safe for
// concurrent use: readers call Load to get a snapshot, and a single writer
// calls Store to swap the policy. Policy is immutable after Compile, so no
// per-request locking is needed.
//
// A nil holder, or a holder whose value is nil, both mean "no MCP policy
// configured" — the receiver methods on *Policy already handle nil safely.
type PolicyHolder struct {
	p atomic.Pointer[Policy]
}

// NewPolicyHolder creates a PolicyHolder with the given initial policy.
// Passing nil is valid and means the policy starts disabled.
func NewPolicyHolder(initial *Policy) *PolicyHolder {
	h := &PolicyHolder{}
	h.p.Store(initial)
	return h
}

// Load returns the current policy snapshot, or nil if none is configured.
// Callers should capture the returned pointer once per request.
func (h *PolicyHolder) Load() *Policy {
	if h == nil {
		return nil
	}
	return h.p.Load()
}

// Store atomically replaces the current policy with next.
func (h *PolicyHolder) Store(next *Policy) {
	h.p.Store(next)
}
