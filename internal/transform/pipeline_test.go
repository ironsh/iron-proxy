package transform

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// stubTransform is a configurable test transformer.
type stubTransform struct {
	name      string
	reqResult *TransformResult
	reqErr    error
	resResult *TransformResult
	resErr    error
	reqCalls  int
	resCalls  int
}

func (s *stubTransform) Name() string { return s.name }

func (s *stubTransform) TransformRequest(_ context.Context, _ *TransformContext, _ *http.Request) (*TransformResult, error) {
	s.reqCalls++
	if s.reqErr != nil {
		return nil, s.reqErr
	}
	if s.reqResult != nil {
		return s.reqResult, nil
	}
	return &TransformResult{Action: ActionContinue}, nil
}

func (s *stubTransform) TransformResponse(_ context.Context, _ *TransformContext, _ *http.Request, _ *http.Response) (*TransformResult, error) {
	s.resCalls++
	if s.resErr != nil {
		return nil, s.resErr
	}
	if s.resResult != nil {
		return s.resResult, nil
	}
	return &TransformResult{Action: ActionContinue}, nil
}

func TestPipeline_AllContinue(t *testing.T) {
	t1 := &stubTransform{name: "t1"}
	t2 := &stubTransform{name: "t2"}
	p := NewPipeline([]Transformer{t1, t2}, BodyLimits{}, testLogger())

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	var traces []TransformTrace
	resp, err := p.ProcessRequest(context.Background(), &TransformContext{}, req, &traces)
	require.NoError(t, err)
	require.Nil(t, resp)
	require.Equal(t, 1, t1.reqCalls)
	require.Equal(t, 1, t2.reqCalls)
	require.Len(t, traces, 2)
}

func TestPipeline_RequestRejectShortCircuits(t *testing.T) {
	t1 := &stubTransform{
		name:      "blocker",
		reqResult: &TransformResult{Action: ActionReject},
	}
	t2 := &stubTransform{name: "never-called"}
	p := NewPipeline([]Transformer{t1, t2}, BodyLimits{}, testLogger())

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	var traces []TransformTrace
	resp, err := p.ProcessRequest(context.Background(), &TransformContext{}, req, &traces)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	require.Equal(t, 0, t2.reqCalls)
	require.Len(t, traces, 1)
	require.Equal(t, ActionReject, traces[0].Action)
}

func TestPipeline_RequestRejectCustomResponse(t *testing.T) {
	customResp := &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Status:     "429 Too Many Requests",
		Header:     http.Header{},
		Body:       http.NoBody,
	}
	t1 := &stubTransform{
		name:      "rate-limiter",
		reqResult: &TransformResult{Action: ActionReject, Response: customResp},
	}
	p := NewPipeline([]Transformer{t1}, BodyLimits{}, testLogger())

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	var traces []TransformTrace
	resp, err := p.ProcessRequest(context.Background(), &TransformContext{}, req, &traces)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
}

func TestPipeline_RequestError(t *testing.T) {
	t1 := &stubTransform{
		name:   "broken",
		reqErr: errors.New("something broke"),
	}
	p := NewPipeline([]Transformer{t1}, BodyLimits{}, testLogger())

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	var traces []TransformTrace
	_, err := p.ProcessRequest(context.Background(), &TransformContext{}, req, &traces)
	require.Error(t, err)
	require.Contains(t, err.Error(), "broken")
	require.Len(t, traces, 1)
	require.NotNil(t, traces[0].Err)
}

func TestPipeline_ResponseReject(t *testing.T) {
	t1 := &stubTransform{
		name:      "response-blocker",
		resResult: &TransformResult{Action: ActionReject},
	}
	p := NewPipeline([]Transformer{t1}, BodyLimits{}, testLogger())

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	upstreamResp := &http.Response{StatusCode: http.StatusOK}

	var traces []TransformTrace
	resp, err := p.ProcessResponse(context.Background(), &TransformContext{}, req, upstreamResp, &traces)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestPipeline_ResponseContinuePassesThrough(t *testing.T) {
	t1 := &stubTransform{name: "passthrough"}
	p := NewPipeline([]Transformer{t1}, BodyLimits{}, testLogger())

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	upstreamResp := &http.Response{StatusCode: http.StatusOK}

	var traces []TransformTrace
	resp, err := p.ProcessResponse(context.Background(), &TransformContext{}, req, upstreamResp, &traces)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Same(t, upstreamResp, resp)
}

func TestPipeline_EmptyPipeline(t *testing.T) {
	p := NewPipeline(nil, BodyLimits{}, testLogger())

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	var traces []TransformTrace
	resp, err := p.ProcessRequest(context.Background(), &TransformContext{}, req, &traces)
	require.NoError(t, err)
	require.Nil(t, resp)

	upstreamResp := &http.Response{StatusCode: http.StatusOK}
	resp, err = p.ProcessResponse(context.Background(), &TransformContext{}, req, upstreamResp, &traces)
	require.NoError(t, err)
	require.Same(t, upstreamResp, resp)
}

func TestPipeline_Names(t *testing.T) {
	t1 := &stubTransform{name: "allowlist"}
	t2 := &stubTransform{name: "logger"}
	p := NewPipeline([]Transformer{t1, t2}, BodyLimits{}, testLogger())
	require.Equal(t, "allowlist → logger", p.Names())
}

func TestPipeline_RequestRejectStopsAtSecond(t *testing.T) {
	t1 := &stubTransform{name: "first"}
	t2 := &stubTransform{
		name:      "second",
		reqResult: &TransformResult{Action: ActionReject},
	}
	t3 := &stubTransform{name: "third"}
	p := NewPipeline([]Transformer{t1, t2, t3}, BodyLimits{}, testLogger())

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	var traces []TransformTrace
	resp, err := p.ProcessRequest(context.Background(), &TransformContext{}, req, &traces)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	require.Equal(t, 1, t1.reqCalls)
	require.Equal(t, 1, t2.reqCalls)
	require.Equal(t, 0, t3.reqCalls)
	require.Len(t, traces, 2)
}

func TestPipeline_TraceCapturesTiming(t *testing.T) {
	t1 := &stubTransform{name: "t1"}
	p := NewPipeline([]Transformer{t1}, BodyLimits{}, testLogger())

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	var traces []TransformTrace
	_, err := p.ProcessRequest(context.Background(), &TransformContext{}, req, &traces)
	require.NoError(t, err)
	require.Len(t, traces, 1)
	require.Equal(t, "t1", traces[0].Name)
	require.Equal(t, ActionContinue, traces[0].Action)
	require.GreaterOrEqual(t, traces[0].Duration.Nanoseconds(), int64(0))
}

func TestPipeline_AnnotationsInTrace(t *testing.T) {
	// Custom transform that annotates
	annotator := &annotatingTransform{name: "annotator"}
	p := NewPipeline([]Transformer{annotator}, BodyLimits{}, testLogger())

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	var traces []TransformTrace
	_, err := p.ProcessRequest(context.Background(), &TransformContext{}, req, &traces)
	require.NoError(t, err)
	require.Len(t, traces, 1)
	require.Equal(t, "test-value", traces[0].Annotations["test-key"])
}

// annotatingTransform calls Annotate during TransformRequest.
type annotatingTransform struct {
	name string
}

func (a *annotatingTransform) Name() string { return a.name }

func (a *annotatingTransform) TransformRequest(_ context.Context, tctx *TransformContext, _ *http.Request) (*TransformResult, error) {
	tctx.Annotate("test-key", "test-value")
	return &TransformResult{Action: ActionContinue}, nil
}

func (a *annotatingTransform) TransformResponse(_ context.Context, _ *TransformContext, _ *http.Request, _ *http.Response) (*TransformResult, error) {
	return &TransformResult{Action: ActionContinue}, nil
}
