package mcp

import (
	"bufio"
	"bytes"
	"io"
)

// sseEvent is one parsed SSE event. Lines other than data:/event:/id:/retry:
// are preserved verbatim under "extra" so re-emission produces a structurally
// identical event when the data payload is unchanged.
type sseEvent struct {
	// raw is the original event bytes (including the trailing blank-line
	// terminator) as read from the upstream. Preserved so events whose data
	// payload we do not rewrite can be passed through byte-for-byte.
	raw []byte

	// dataLines are the values of the "data:" fields, in order. Per the SSE
	// spec, multi-line data is concatenated with a single newline between
	// lines. dataLines is nil when the event has no data (e.g. a comment-only
	// keepalive).
	dataLines [][]byte

	// other holds the verbatim non-data lines (event:, id:, retry:, comments,
	// blank lines aside from the terminator) so we can re-emit them around a
	// rewritten data payload.
	other [][]byte
}

// readSSEEvent reads a single SSE event terminated by a blank line from r.
// Returns io.EOF when no more events are available. Lines that are not in
// "key:value" form (e.g. malformed) are preserved under other.
func readSSEEvent(r *bufio.Reader) (*sseEvent, error) {
	var raw bytes.Buffer
	ev := &sseEvent{}
	gotAny := false
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			gotAny = true
			raw.Write(line)
		}
		if err != nil {
			if err == io.EOF {
				if gotAny {
					ev.raw = raw.Bytes()
					return ev, nil
				}
				return nil, io.EOF
			}
			return nil, err
		}

		trimmed := stripCRLF(line)
		// Blank line terminates an event.
		if len(trimmed) == 0 {
			ev.raw = raw.Bytes()
			return ev, nil
		}
		if len(trimmed) > 0 && trimmed[0] == ':' {
			// Comment line: preserve verbatim under other.
			ev.other = append(ev.other, append([]byte(nil), line...))
			continue
		}
		key, value := splitField(trimmed)
		if key == "data" {
			ev.dataLines = append(ev.dataLines, append([]byte(nil), value...))
			continue
		}
		ev.other = append(ev.other, append([]byte(nil), line...))
	}
}

// dataPayload returns the concatenated SSE data payload (lines joined with \n
// per the spec). Returns nil when the event has no data lines.
func (e *sseEvent) dataPayload() []byte {
	if len(e.dataLines) == 0 {
		return nil
	}
	if len(e.dataLines) == 1 {
		return e.dataLines[0]
	}
	return bytes.Join(e.dataLines, []byte{'\n'})
}

// rewriteData returns the bytes for the event with data: lines replaced by
// payload (split on newlines) while preserving non-data lines.
func (e *sseEvent) rewriteData(payload []byte) []byte {
	var buf bytes.Buffer
	for _, ln := range e.other {
		buf.Write(ln)
		if !bytes.HasSuffix(ln, []byte{'\n'}) {
			buf.WriteByte('\n')
		}
	}
	if len(payload) > 0 {
		for _, ln := range bytes.Split(payload, []byte{'\n'}) {
			buf.WriteString("data: ")
			buf.Write(ln)
			buf.WriteByte('\n')
		}
	}
	buf.WriteByte('\n')
	return buf.Bytes()
}

func splitField(line []byte) (string, []byte) {
	idx := bytes.IndexByte(line, ':')
	if idx < 0 {
		return string(line), nil
	}
	key := string(line[:idx])
	value := line[idx+1:]
	if len(value) > 0 && value[0] == ' ' {
		value = value[1:]
	}
	return key, value
}

func stripCRLF(line []byte) []byte {
	for len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
		line = line[:len(line)-1]
	}
	return line
}
