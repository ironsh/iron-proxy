package usage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// Recorder creates per-request observations and pushes finalized events.
type Recorder struct {
	adapters []adapter
	sink     Sink
	logger   *slog.Logger
}

func NewRecorder(sink Sink, logger *slog.Logger) *Recorder {
	return &Recorder{
		adapters: defaultAdapters(),
		sink:     sink,
		logger:   logger,
	}
}

func (r *Recorder) Observe(req *http.Request) *Observation {
	if r == nil || r.sink == nil {
		return nil
	}
	for _, a := range r.adapters {
		if a.Matches(req.Host, req.URL.Path) {
			return &Observation{
				recorder:  r,
				parser:    a.NewParser(req),
				provider:  a.Provider(),
				requestID: newRequestID(),
				host:      req.Host,
				method:    req.Method,
				path:      req.URL.Path,
			}
		}
	}
	return nil
}

func (r *Recorder) Close(ctx context.Context) error {
	if r == nil || r.sink == nil {
		return nil
	}
	return r.sink.Close(ctx)
}

type Observation struct {
	recorder  *Recorder
	parser    parser
	requestID string
	provider  string
	host      string
	method    string
	path      string
}

func (o *Observation) WrapRequest(reader io.Reader) io.Reader {
	if o == nil || o.parser == nil {
		return reader
	}
	return &tapReader{
		reader: reader,
		feed:   o.parser.FeedRequest,
	}
}

func (o *Observation) WrapRequestReadCloser(rc io.ReadCloser) io.ReadCloser {
	if o == nil || o.parser == nil {
		return rc
	}
	return &tapReadCloser{
		ReadCloser: rc,
		reader:     o.WrapRequest(rc),
	}
}

func (o *Observation) WrapResponse(reader io.Reader) io.Reader {
	if o == nil || o.parser == nil {
		return reader
	}
	return &tapReader{
		reader: reader,
		feed:   o.parser.FeedResponse,
	}
}

func (o *Observation) Finish(startedAt time.Time, statusCode int, copyErr error) {
	if o == nil || o.recorder == nil || o.parser == nil {
		return
	}

	parsed := o.parser.Finalize()
	event := Event{
		SchemaVersion:            1,
		RequestID:                o.requestID,
		TS:                       startedAt.UTC(),
		Provider:                 o.provider,
		Host:                     o.host,
		Method:                   o.method,
		Path:                     o.path,
		Model:                    parsed.Model,
		StatusCode:               statusCode,
		DurationMS:               float64(time.Since(startedAt).Microseconds()) / 1000.0,
		InputTokens:              parsed.InputTokens,
		OutputTokens:             parsed.OutputTokens,
		CacheCreationInputTokens: parsed.CacheCreationInputTokens,
		CacheReadInputTokens:     parsed.CacheReadInputTokens,
		UsageUnavailableReason:   parsed.UnavailableReason,
	}
	event.ErrorClass = classifyError(statusCode, copyErr, parsed.UnavailableReason)

	if ok := o.recorder.sink.TryEnqueue(event); !ok && o.recorder.logger != nil {
		o.recorder.logger.Warn("usage event queue full; dropping event",
			slog.String("provider", event.Provider),
			slog.String("host", event.Host),
			slog.Int("status_code", event.StatusCode),
		)
	}
}

type tapReader struct {
	reader io.Reader
	feed   func([]byte)
}

func (r *tapReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		r.feed(p[:n])
	}
	return n, err
}

type tapReadCloser struct {
	io.ReadCloser
	reader io.Reader
}

func (r *tapReadCloser) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}

func classifyError(statusCode int, copyErr error, unavailable string) string {
	if copyErr != nil {
		return "stream_interrupted"
	}
	if unavailable == "usage_parse_failed" {
		return "usage_parse_failed"
	}
	if statusCode >= 500 {
		return "provider_5xx"
	}
	if statusCode >= 400 {
		return "provider_4xx"
	}
	return ""
}

func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return time.Now().UTC().Format("20060102150405.000000000")
	}
	return hex.EncodeToString(b[:])
}
