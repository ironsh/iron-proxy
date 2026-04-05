package transform

import (
	"bytes"
	"io"
	"sync"
)

// BufferedBody wraps an io.ReadCloser with lazy, all-or-nothing buffering.
//
// When a transform calls Read(), the entire underlying reader is consumed into
// memory on the first call. Subsequent reads and Reset() calls operate on the
// buffer. When no transform reads the body, StreamingReader() returns the
// original reader directly — avoiding buffering for the final response write
// or upstream send.
//
// A maxBytes of 0 means unlimited; when the limit is exceeded the body is
// truncated silently.
type BufferedBody struct {
	mu       sync.Mutex
	original io.ReadCloser // nil once buffered or when created from bytes
	data     []byte        // nil until buffered
	pos      int
	maxBytes int64
	buffered bool
}

// NewBufferedBody wraps an io.ReadCloser for lazy buffering. maxBytes caps
// the buffer size; 0 means unlimited.
func NewBufferedBody(body io.ReadCloser, maxBytes int64) *BufferedBody {
	if body == nil {
		body = io.NopCloser(bytes.NewReader(nil))
	}
	return &BufferedBody{original: body, maxBytes: maxBytes}
}

// NewBufferedBodyFromBytes creates a pre-buffered body from a byte slice.
// Use this when a transform replaces the body with new content.
func NewBufferedBodyFromBytes(data []byte) *BufferedBody {
	return &BufferedBody{data: data, buffered: true}
}

// Read implements io.Reader. On the first call, the entire underlying reader
// is eagerly consumed into an internal buffer. All reads serve from the buffer.
func (b *BufferedBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.buffered {
		b.bufferLocked()
	}

	if b.pos >= len(b.data) {
		return 0, io.EOF
	}
	n := copy(p, b.data[b.pos:])
	b.pos += n
	return n, nil
}

// bufferLocked eagerly reads the entire original body into memory.
// Must be called with b.mu held.
func (b *BufferedBody) bufferLocked() {
	var r io.Reader = b.original
	if b.maxBytes > 0 {
		r = io.LimitReader(r, b.maxBytes)
	}
	b.data, _ = io.ReadAll(r)
	b.buffered = true
	b.original.Close()
	b.original = nil
}

// Reset rewinds the read position to the beginning so the body can be
// re-read by the next transform in the pipeline.
func (b *BufferedBody) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pos = 0
}

// StreamingReader returns a reader for the final output (response write or
// upstream send). If the body was never read by a transform, this returns the
// original reader directly — no buffering occurs. If the body was buffered,
// returns a reader over the buffer from the current position.
func (b *BufferedBody) StreamingReader() io.Reader {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.buffered {
		r := b.original
		b.original = nil
		return r
	}
	return bytes.NewReader(b.data[b.pos:])
}

// Len returns the total size of the buffered body, or -1 if the body has not
// been buffered yet.
func (b *BufferedBody) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.buffered {
		return -1
	}
	return len(b.data)
}

// Close closes the underlying reader if it has not been consumed.
func (b *BufferedBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.original != nil {
		err := b.original.Close()
		b.original = nil
		return err
	}
	return nil
}
