package transform

import (
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPipelineHolder_LoadStore(t *testing.T) {
	logger := slog.Default()
	p1 := NewPipeline(nil, BodyLimits{}, logger)
	h := NewPipelineHolder(p1)

	require.Same(t, p1, h.Load())

	p2 := NewPipeline(nil, BodyLimits{MaxRequestBodyBytes: 42}, logger)
	h.Store(p2)
	require.Same(t, p2, h.Load())
}

func TestPipelineHolder_ConcurrentAccess(t *testing.T) {
	logger := slog.Default()
	p1 := NewPipeline(nil, BodyLimits{}, logger)
	h := NewPipelineHolder(p1)

	var wg sync.WaitGroup
	const readers = 100

	// Spawn many concurrent readers.
	wg.Add(readers)
	for range readers {
		go func() {
			defer wg.Done()
			for range 1000 {
				pl := h.Load()
				require.NotNil(t, pl)
			}
		}()
	}

	// Swap a few times while readers are active.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 100 {
			h.Store(NewPipeline(nil, BodyLimits{}, logger))
		}
	}()

	wg.Wait()
}
