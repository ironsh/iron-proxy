package mcp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPolicyHolder_LoadStore(t *testing.T) {
	h := NewPolicyHolder(nil)
	require.Nil(t, h.Load())

	p := &Policy{}
	h.Store(p)
	require.Same(t, p, h.Load())

	h.Store(nil)
	require.Nil(t, h.Load())
}

func TestPolicyHolder_NilReceiverLoadsNil(t *testing.T) {
	var h *PolicyHolder
	require.Nil(t, h.Load())
}
