package transform

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// AuditFunc is called after every request completes with the full pipeline result.
type AuditFunc func(result *PipelineResult)

// BodyLimits holds the global max body sizes for request and response buffering.
type BodyLimits struct {
	MaxRequestBodyBytes  int64
	MaxResponseBodyBytes int64
}

// Pipeline executes a sequence of transforms on requests and responses.
type Pipeline struct {
	transforms []Transformer
	bodyLimits BodyLimits
	onComplete AuditFunc
	logger     *slog.Logger
}

// NewPipeline creates a Pipeline from the given transforms.
func NewPipeline(transforms []Transformer, bodyLimits BodyLimits, logger *slog.Logger) *Pipeline {
	return &Pipeline{
		transforms: transforms,
		bodyLimits: bodyLimits,
		logger:     logger,
	}
}

// SetAuditFunc registers a callback that fires after every request completes.
func (p *Pipeline) SetAuditFunc(f AuditFunc) {
	p.onComplete = f
}

// ProcessRequest runs all request transforms in order. Returns a non-nil
// *http.Response if the pipeline rejects the request (short-circuit).
// Returns an error if any transform fails, which the caller should treat as 502.
// The traces slice is appended to with each transform's result.
func (p *Pipeline) ProcessRequest(ctx context.Context, tctx *TransformContext, req *http.Request, traces *[]TransformTrace) (*http.Response, error) {
	for _, t := range p.transforms {
		start := time.Now()
		result, err := t.TransformRequest(ctx, tctx, req)
		dur := time.Since(start)

		// Reset body for the next transform.
		if r, ok := req.Body.(Bufferable); ok {
			r.Reset()
		}

		trace := TransformTrace{
			Name:        t.Name(),
			Duration:    dur,
			Annotations: tctx.DrainAnnotations(),
		}

		if err != nil {
			trace.Err = err
			*traces = append(*traces, trace)
			return nil, fmt.Errorf("transform %s request: %w", t.Name(), err)
		}

		trace.Action = result.Action
		*traces = append(*traces, trace)

		if result.Action == ActionReject {
			if result.Response != nil {
				return result.Response, nil
			}
			return forbiddenResponse(req), nil
		}
	}
	return nil, nil
}

// ProcessResponse runs all response transforms in order (same order as request).
// Returns a replacement *http.Response if any transform rejects.
// Returns an error if any transform fails.
func (p *Pipeline) ProcessResponse(ctx context.Context, tctx *TransformContext, req *http.Request, resp *http.Response, traces *[]TransformTrace) (*http.Response, error) {
	for _, t := range p.transforms {
		start := time.Now()
		result, err := t.TransformResponse(ctx, tctx, req, resp)
		dur := time.Since(start)

		// Reset bodies for the next transform.
		if r, ok := req.Body.(Bufferable); ok {
			r.Reset()
		}
		if r, ok := resp.Body.(Bufferable); ok {
			r.Reset()
		}

		trace := TransformTrace{
			Name:        t.Name(),
			Duration:    dur,
			Annotations: tctx.DrainAnnotations(),
		}

		if err != nil {
			trace.Err = err
			*traces = append(*traces, trace)
			return nil, fmt.Errorf("transform %s response: %w", t.Name(), err)
		}

		trace.Action = result.Action
		*traces = append(*traces, trace)

		if result.Action == ActionReject {
			if result.Response != nil {
				return result.Response, nil
			}
			return forbiddenResponse(req), nil
		}
	}
	return resp, nil
}

// EmitAudit calls the registered audit callback if one is set.
func (p *Pipeline) EmitAudit(result *PipelineResult) {
	if p.onComplete != nil {
		p.onComplete(result)
	}
}

func forbiddenResponse(req *http.Request) *http.Response {
	return &http.Response{
		StatusCode:    http.StatusForbidden,
		Status:        "403 Forbidden",
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"text/plain"}},
		Body:          http.NoBody,
		Request:       req,
		ContentLength: 0,
	}
}

// BodyLimits returns the global body size limits.
func (p *Pipeline) BodyLimits() BodyLimits {
	return p.bodyLimits
}

// Empty returns true if the pipeline has no transforms.
func (p *Pipeline) Empty() bool {
	return len(p.transforms) == 0
}

// Names returns the names of all transforms in the pipeline, for logging.
func (p *Pipeline) Names() string {
	names := make([]string, len(p.transforms))
	for i, t := range p.transforms {
		names[i] = t.Name()
	}
	return strings.Join(names, " → ")
}
