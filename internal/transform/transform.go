// Package transform defines the Transformer interface and pipeline execution
// for iron-proxy's request/response transform system.
package transform

import (
	"context"
	"crypto/x509"
	"log/slog"
	"net/http"
	"time"
)

// TransformAction controls what happens after a transform runs.
type TransformAction int

const (
	// ActionContinue passes the request to the next transform (or upstream).
	ActionContinue TransformAction = iota

	// ActionReject stops the pipeline and returns TransformResult.Response to the client.
	// If Response is nil, the proxy returns a default 403 Forbidden.
	ActionReject
)

// Mode identifies how the proxy obtained the request being transformed.
type Mode int

const (
	// ModeMITM means the request was parsed from a terminated TLS connection
	// (or plaintext HTTP) and has full method, path, headers, and body.
	ModeMITM Mode = iota

	// ModeSNIOnly means the request is a synthetic host-only stand-in built
	// from a peeked TLS ClientHello SNI. Method, path, headers, and body are
	// all empty; transforms that depend on them cannot function.
	ModeSNIOnly
)

// String returns the canonical string form of the mode.
func (m Mode) String() string {
	switch m {
	case ModeMITM:
		return "mitm"
	case ModeSNIOnly:
		return "sni-only"
	default:
		return "unknown"
	}
}

// TransformContext carries metadata about the connection and request.
type TransformContext struct {
	SNI        string
	ClientCert *x509.Certificate
	Logger     *slog.Logger
	Mode       Mode
	Tunnel     *TunnelInfo

	// annotations is written by transforms via Annotate and read by the pipeline
	// to build TransformTrace. Not exported — transforms use the Annotate method.
	annotations map[string]any
}

// TunnelInfo carries metadata from the CONNECT/SOCKS5 tunnel that established
// an inner request.
type TunnelInfo struct {
	// Target is the host:port from the CONNECT request or SOCKS5 target.
	Target string

	// RequestTransforms are the traces from the CONNECT/SOCKS5 request
	// pipeline, in the order the transforms ran. Inner request transforms and
	// audit consume this to attribute tunnel-level annotations to the
	// transform that produced them.
	RequestTransforms []TransformTrace
}

// Annotate attaches audit metadata to the current transform's trace.
// Values must be JSON-serializable. Never put actual secret values here.
func (tctx *TransformContext) Annotate(key string, value any) {
	if tctx.annotations == nil {
		tctx.annotations = make(map[string]any)
	}
	tctx.annotations[key] = value
}

// drainAnnotations returns and clears the current annotations.
func (tctx *TransformContext) DrainAnnotations() map[string]any {
	a := tctx.annotations
	tctx.annotations = nil
	return a
}

// PipelineResult captures the full outcome of a request passing through the pipeline.
type PipelineResult struct {
	Host       string
	Method     string
	Path       string
	RemoteAddr string
	SNI        string
	Mode       Mode

	StartedAt time.Time
	Duration  time.Duration

	Action     TransformAction
	StatusCode int

	Tunnel *TunnelInfo

	RequestTransforms  []TransformTrace
	ResponseTransforms []TransformTrace

	Err error
}

// TransformTrace records what a single transform did.
type TransformTrace struct {
	Name        string
	Action      TransformAction
	Duration    time.Duration
	Err         error
	Annotations map[string]any
}

// TransformResult controls what happens after a transform runs.
type TransformResult struct {
	Action   TransformAction
	Response *http.Response
}

// Transformer processes HTTP requests and responses.
// A single Transformer instance may be called concurrently from multiple goroutines.
type Transformer interface {
	// Name returns a human-readable name for logging and metrics.
	Name() string

	// TransformRequest is called before the request is sent upstream.
	// The transform may modify the request in place.
	// Returning ActionReject stops the pipeline.
	TransformRequest(ctx context.Context, tctx *TransformContext, req *http.Request) (*TransformResult, error)

	// TransformResponse is called after the response is received from upstream.
	// The transform may modify the response in place.
	// Returning ActionReject replaces the upstream response with TransformResult.Response.
	TransformResponse(ctx context.Context, tctx *TransformContext, req *http.Request, resp *http.Response) (*TransformResult, error)
}
