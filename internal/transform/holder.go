package transform

import "sync/atomic"

// PipelineHolder holds an atomically swappable Pipeline pointer. It is safe
// for concurrent use: readers call Load to get a snapshot, and a single writer
// calls Store to swap the pipeline. Because Pipeline is immutable after
// construction, no additional synchronization is needed per-request.
type PipelineHolder struct {
	p atomic.Pointer[Pipeline]
}

// NewPipelineHolder creates a PipelineHolder with the given initial pipeline.
func NewPipelineHolder(initial *Pipeline) *PipelineHolder {
	h := &PipelineHolder{}
	h.p.Store(initial)
	return h
}

// Load returns the current pipeline. Callers should capture the returned
// pointer once per request to get snapshot semantics.
func (h *PipelineHolder) Load() *Pipeline {
	return h.p.Load()
}

// Store atomically replaces the current pipeline with next.
func (h *PipelineHolder) Store(next *Pipeline) {
	h.p.Store(next)
}
