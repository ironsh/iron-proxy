package transform

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReplayableBody_Read(t *testing.T) {
	body := NewReplayableBody(io.NopCloser(strings.NewReader("hello")), 1024)

	data, err := io.ReadAll(body)
	require.NoError(t, err)
	require.Equal(t, "hello", string(data))
}

func TestReplayableBody_ResetAndReread(t *testing.T) {
	body := NewReplayableBody(io.NopCloser(strings.NewReader("hello")), 1024)

	data, err := io.ReadAll(body)
	require.NoError(t, err)
	require.Equal(t, "hello", string(data))

	body.Reset()

	data, err = io.ReadAll(body)
	require.NoError(t, err)
	require.Equal(t, "hello", string(data))
}

func TestReplayableBody_MultipleResets(t *testing.T) {
	body := NewReplayableBody(io.NopCloser(strings.NewReader("abc")), 1024)

	for i := 0; i < 5; i++ {
		data, err := io.ReadAll(body)
		require.NoError(t, err)
		require.Equal(t, "abc", string(data))
		body.Reset()
	}
}

func TestReplayableBody_IncrementalRead(t *testing.T) {
	body := NewReplayableBody(io.NopCloser(strings.NewReader("hello world")), 1024)

	// Read in small chunks.
	buf := make([]byte, 3)
	n, err := body.Read(buf)
	require.NoError(t, err)
	require.Equal(t, 3, n)
	require.Equal(t, "hel", string(buf[:n]))

	// Read more.
	n, err = body.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "lo ", string(buf[:n]))

	// Reset and re-read from the start — should get buffered data.
	body.Reset()
	data, err := io.ReadAll(body)
	require.NoError(t, err)
	require.Equal(t, "hello world", string(data))
}

func TestReplayableBody_MaxBytesTruncates(t *testing.T) {
	body := NewReplayableBody(io.NopCloser(strings.NewReader("hello world")), 5)

	data, err := io.ReadAll(body)
	require.NoError(t, err)
	require.Equal(t, "hello", string(data))

	// Reset and re-read: same truncated data.
	body.Reset()
	data, err = io.ReadAll(body)
	require.NoError(t, err)
	require.Equal(t, "hello", string(data))
}

func TestReplayableBody_Unlimited(t *testing.T) {
	body := NewReplayableBody(io.NopCloser(strings.NewReader("hello world")), 0)

	data, err := io.ReadAll(body)
	require.NoError(t, err)
	require.Equal(t, "hello world", string(data))
}

func TestReplayableBody_NilBody(t *testing.T) {
	body := NewReplayableBody(nil, 1024)

	data, err := io.ReadAll(body)
	require.NoError(t, err)
	require.Empty(t, data)
}

func TestReplayableBody_Close(t *testing.T) {
	body := NewReplayableBody(io.NopCloser(strings.NewReader("hello")), 1024)
	require.NoError(t, body.Close())

	// After consuming, close is a no-op.
	body2 := NewReplayableBody(io.NopCloser(strings.NewReader("hello")), 1024)
	_, _ = io.ReadAll(body2)
	require.NoError(t, body2.Close())
}
