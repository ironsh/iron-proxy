package mcp

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadSSEEventSingle(t *testing.T) {
	stream := "event: message\ndata: hello\n\n"
	br := bufio.NewReader(strings.NewReader(stream))

	ev, err := readSSEEvent(br)
	require.NoError(t, err)
	require.NotNil(t, ev)
	require.Equal(t, "hello", string(ev.dataPayload()))

	_, err = readSSEEvent(br)
	require.ErrorIs(t, err, io.EOF)
}

func TestReadSSEEventMultiline(t *testing.T) {
	stream := "data: line1\ndata: line2\n\n"
	br := bufio.NewReader(strings.NewReader(stream))

	ev, err := readSSEEvent(br)
	require.NoError(t, err)
	require.Equal(t, "line1\nline2", string(ev.dataPayload()))
}

func TestReadSSEEventComment(t *testing.T) {
	stream := ": keepalive\n\ndata: payload\n\n"
	br := bufio.NewReader(strings.NewReader(stream))

	ev1, err := readSSEEvent(br)
	require.NoError(t, err)
	require.Empty(t, ev1.dataLines)

	ev2, err := readSSEEvent(br)
	require.NoError(t, err)
	require.Equal(t, "payload", string(ev2.dataPayload()))
}

func TestRewriteData(t *testing.T) {
	stream := "id: 1\nevent: message\ndata: original\n\n"
	br := bufio.NewReader(strings.NewReader(stream))

	ev, err := readSSEEvent(br)
	require.NoError(t, err)

	out := ev.rewriteData([]byte("rewritten"))
	require.Contains(t, string(out), "id: 1\n")
	require.Contains(t, string(out), "event: message\n")
	require.Contains(t, string(out), "data: rewritten\n")
	require.True(t, bytes.HasSuffix(out, []byte("\n\n")))
}

func TestRewriteDataMultiline(t *testing.T) {
	stream := "data: x\n\n"
	br := bufio.NewReader(strings.NewReader(stream))

	ev, err := readSSEEvent(br)
	require.NoError(t, err)

	out := ev.rewriteData([]byte("a\nb\nc"))
	lines := strings.Split(strings.TrimSuffix(string(out), "\n\n"), "\n")
	require.Equal(t, []string{"data: a", "data: b", "data: c"}, lines)
}
