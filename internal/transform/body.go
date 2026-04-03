package transform

import (
	"bytes"
	"io"
	"sync"
)

// Bufferable is implemented by body types that support rewinding for replay
// between pipeline transforms, and streaming for final output without
// unnecessary buffering.
type Bufferable interface {
	Reset()
	StreamingReader() io.Reader
}

// ReplayableBody wraps an io.ReadCloser with incremental buffering and rewind
// support. Data is buffered as it is read from the underlying reader. After
// calling Reset(), subsequent reads replay from the buffer. A maxBytes of 0
// means unlimited; when the limit is reached reads return EOF.
type ReplayableBody struct {
	mu       sync.Mutex
	original io.ReadCloser
	buf      []byte
	pos      int   // read position within buf
	maxBytes int64 // 0 = unlimited
	eof      bool  // original has been fully consumed (or capped)
}

// NewReplayableBody wraps an existing body. maxBytes caps total buffer size;
// 0 means unlimited. When the cap is reached, reads return EOF.
func NewReplayableBody(body io.ReadCloser, maxBytes int64) *ReplayableBody {
	if body == nil {
		body = io.NopCloser(bytes.NewReader(nil))
	}
	return &ReplayableBody{original: body, maxBytes: maxBytes}
}

// Read implements io.Reader. On the first pass, data is read from the
// underlying reader and appended to an internal buffer. After Reset(),
// reads are served from the buffer.
func (b *ReplayableBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Serve from buffer if we have unread buffered data.
	if b.pos < len(b.buf) {
		n := copy(p, b.buf[b.pos:])
		b.pos += n
		if b.pos == len(b.buf) && b.eof {
			return n, io.EOF
		}
		return n, nil
	}

	// Buffer is exhausted and original is done.
	if b.eof {
		return 0, io.EOF
	}

	// Read from original, append to buffer.
	n, err := b.original.Read(p)
	if n > 0 {
		if b.maxBytes > 0 && int64(len(b.buf)+n) > b.maxBytes {
			// Cap: take only what fits, then treat as EOF.
			room := int(b.maxBytes) - len(b.buf)
			if room > 0 {
				b.buf = append(b.buf, p[:room]...)
				b.pos = len(b.buf)
			}
			b.eof = true
			b.original.Close()
			return room, io.EOF
		}
		b.buf = append(b.buf, p[:n]...)
		b.pos = len(b.buf)
	}
	if err == io.EOF {
		b.eof = true
		b.original.Close()
	}
	return n, err
}

// Reset rewinds the read position to the beginning so the body can be
// re-read by the next transform in the pipeline.
func (b *ReplayableBody) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pos = 0
}

// StreamingReader returns a reader that drains the buffered data from the
// current position, then streams directly from the underlying reader without
// appending to the buffer. Use this for final output (e.g. writing the HTTP
// response) to avoid buffering the entire body into memory.
func (b *ReplayableBody) StreamingReader() io.Reader {
	b.mu.Lock()
	defer b.mu.Unlock()

	var readers []io.Reader

	// Any buffered data from the current position.
	if b.pos < len(b.buf) {
		readers = append(readers, bytes.NewReader(b.buf[b.pos:]))
	}

	// Remaining unbuffered data from the original, if not fully consumed.
	if !b.eof {
		readers = append(readers, b.original)
	}

	if len(readers) == 0 {
		return bytes.NewReader(nil)
	}
	return io.MultiReader(readers...)
}

// Close is a no-op if the original has already been consumed; otherwise
// closes the underlying reader.
func (b *ReplayableBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.eof {
		return nil
	}
	b.eof = true
	return b.original.Close()
}

// BufferedBody is a read-resettable body backed by a fixed byte slice.
// Use this when a transform replaces the body with new content.
type BufferedBody struct {
	data []byte
	pos  int
}

// NewBufferedBody creates a BufferedBody from a byte slice.
func NewBufferedBody(data []byte) *BufferedBody {
	return &BufferedBody{data: data}
}

// Read implements io.Reader.
func (b *BufferedBody) Read(p []byte) (int, error) {
	if b.pos >= len(b.data) {
		return 0, io.EOF
	}
	n := copy(p, b.data[b.pos:])
	b.pos += n
	return n, nil
}

// Reset rewinds to the beginning.
func (b *BufferedBody) Reset() {
	b.pos = 0
}

// StreamingReader returns a reader over the remaining data.
func (b *BufferedBody) StreamingReader() io.Reader {
	return bytes.NewReader(b.data[b.pos:])
}

// Close is a no-op.
func (b *BufferedBody) Close() error {
	return nil
}
