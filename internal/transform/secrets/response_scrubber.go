package secrets

import (
	"bytes"
	"io"
	"sort"
)

// replacingReadCloser rewrites secret values while preserving streaming
// responses. It retains only enough input to recognize a value split across
// read boundaries.
type replacingReadCloser struct {
	source       io.ReadCloser
	replacements []byteReplacement
	maxOldLen    int
	pending      []byte
	ready        []byte
	terminalErr  error
}

type byteReplacement struct {
	old []byte
	new []byte
}

func newReplacingReadCloser(source io.ReadCloser, replacements []responseReplacement) *replacingReadCloser {
	byteReplacements := make([]byteReplacement, 0, len(replacements))
	maxOldLen := 0
	for _, replacement := range replacements {
		if replacement.upstream == "" || replacement.upstream == replacement.client {
			continue
		}
		old := []byte(replacement.upstream)
		byteReplacements = append(byteReplacements, byteReplacement{old: old, new: []byte(replacement.client)})
		if len(old) > maxOldLen {
			maxOldLen = len(old)
		}
	}
	sort.SliceStable(byteReplacements, func(i, j int) bool {
		return len(byteReplacements[i].old) > len(byteReplacements[j].old)
	})
	return &replacingReadCloser{source: source, replacements: byteReplacements, maxOldLen: maxOldLen}
}

func (r *replacingReadCloser) Read(p []byte) (int, error) {
	for len(r.ready) == 0 {
		if r.terminalErr != nil {
			r.processPending(true)
			if len(r.ready) == 0 {
				err := r.terminalErr
				r.terminalErr = io.EOF
				return 0, err
			}
			break
		}

		buf := make([]byte, 32*1024)
		n, err := r.source.Read(buf)
		if n > 0 {
			r.pending = append(r.pending, buf[:n]...)
		}
		if err != nil {
			r.terminalErr = err
		}
		r.processPending(err != nil)
		if n == 0 && err == nil && len(r.ready) == 0 {
			return 0, nil
		}
	}

	n := copy(p, r.ready)
	r.ready = r.ready[n:]
	return n, nil
}

func (r *replacingReadCloser) Close() error {
	return r.source.Close()
}

func (r *replacingReadCloser) processPending(final bool) {
	if len(r.pending) == 0 {
		return
	}

	safeStartLimit := len(r.pending)
	if !final {
		if len(r.pending) < r.maxOldLen {
			return
		}
		safeStartLimit = len(r.pending) - r.maxOldLen + 1
	}

	for len(r.pending) > 0 {
		matchAt, replacement := r.earliestMatch()
		if replacement != nil && matchAt < safeStartLimit {
			r.ready = append(r.ready, r.pending[:matchAt]...)
			r.ready = append(r.ready, replacement.new...)
			consumed := matchAt + len(replacement.old)
			r.pending = r.pending[consumed:]
			safeStartLimit -= consumed
			if safeStartLimit < 0 {
				safeStartLimit = 0
			}
			continue
		}

		if safeStartLimit > 0 {
			r.ready = append(r.ready, r.pending[:safeStartLimit]...)
			r.pending = r.pending[safeStartLimit:]
		}
		return
	}
}

func (r *replacingReadCloser) earliestMatch() (int, *byteReplacement) {
	matchAt := -1
	var matched *byteReplacement
	for i := range r.replacements {
		at := bytes.Index(r.pending, r.replacements[i].old)
		if at >= 0 && (matchAt == -1 || at < matchAt) {
			matchAt = at
			matched = &r.replacements[i]
		}
	}
	return matchAt, matched
}
