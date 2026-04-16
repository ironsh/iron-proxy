package proxy

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// dialClientHello runs a real tls.Client handshake against the given conn.
// The handshake will fail (peekSNI aborts) but the client will have sent a
// valid ClientHello. Returns when the client handshake errors.
func dialClientHello(t *testing.T, conn net.Conn, cfg *tls.Config) {
	t.Helper()
	go func() {
		client := tls.Client(conn, cfg)
		_ = client.Handshake()
		_ = client.Close()
	}()
}

func TestPeekSNI_WithSNI(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	dialClientHello(t, clientConn, &tls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})

	sni, peeked, err := peekSNI(serverConn, 2*time.Second)
	require.NoError(t, err)
	require.Equal(t, "example.com", sni)
	require.NotEmpty(t, peeked)
	// First byte of a TLS handshake record is 0x16.
	require.Equal(t, byte(0x16), peeked[0])
}

func TestPeekSNI_TLS13(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	dialClientHello(t, clientConn, &tls.Config{
		ServerName:         "tls13.example.com",
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	})

	sni, peeked, err := peekSNI(serverConn, 2*time.Second)
	require.NoError(t, err)
	require.Equal(t, "tls13.example.com", sni)
	require.NotEmpty(t, peeked)
}

func TestPeekSNI_NoSNI(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	// A tls.Client with no ServerName still sends a ClientHello, just without
	// the SNI extension populated (ServerName field on ClientHelloInfo is "").
	dialClientHello(t, clientConn, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})

	sni, peeked, err := peekSNI(serverConn, 2*time.Second)
	require.NoError(t, err)
	require.Equal(t, "", sni)
	require.NotEmpty(t, peeked)
}

func TestPeekSNI_Malformed(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	// Write garbage that doesn't look like a TLS handshake.
	go func() {
		_, _ = clientConn.Write([]byte("HTTP/1.1 GET / garbage"))
		_ = clientConn.Close()
	}()

	sni, peeked, err := peekSNI(serverConn, 500*time.Millisecond)
	require.Error(t, err)
	require.Equal(t, "", sni)
	require.Empty(t, peeked)
}

func TestPeekSNI_Timeout(t *testing.T) {
	_, serverConn := net.Pipe()
	// No client writes anything; peekSNI should time out waiting.

	start := time.Now()
	_, _, err := peekSNI(serverConn, 200*time.Millisecond)
	elapsed := time.Since(start)
	require.Error(t, err)
	require.Less(t, elapsed, 2*time.Second)
}

func TestPeekSNI_ReplayableBytes(t *testing.T) {
	// Verify the peeked bytes can be used to re-drive a TLS parse on a fresh
	// reader, confirming they form a complete ClientHello record.
	clientConn, serverConn := net.Pipe()

	dialClientHello(t, clientConn, &tls.Config{
		ServerName:         "replay.example",
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})

	_, peeked, err := peekSNI(serverConn, 2*time.Second)
	require.NoError(t, err)

	// First 5 bytes are the TLS record header: type(1) + version(2) + length(2).
	require.Equal(t, byte(0x16), peeked[0]) // handshake
	require.Equal(t, byte(0x03), peeked[1]) // TLS major
	recordLen := int(peeked[3])<<8 | int(peeked[4])
	require.GreaterOrEqual(t, len(peeked), 5+recordLen)

	// Record starting at byte 5 is a handshake message. First byte of the
	// handshake message is 0x01 (ClientHello).
	require.Equal(t, byte(0x01), peeked[5])
}

func TestRecordingConn_DiscardsWrites(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	rec := &recordingConn{Conn: c2}

	// Write to rec should return success without actually sending anything.
	n, err := rec.Write([]byte("hello"))
	require.NoError(t, err)
	require.Equal(t, 5, n)

	// Confirm nothing was sent by doing a non-blocking-ish read on c1 with
	// a short deadline.
	_ = c1.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 16)
	_, err = c1.Read(buf)
	require.Error(t, err)
}

func TestRecordingConn_RecordsReads(t *testing.T) {
	// Feed a bytes.Reader through recordingConn.
	src := &readOnlyConn{r: bytes.NewReader([]byte("abcdef"))}
	rec := &recordingConn{Conn: src}

	buf := make([]byte, 3)
	n, err := rec.Read(buf)
	require.NoError(t, err)
	require.Equal(t, 3, n)
	require.Equal(t, "abc", string(buf[:n]))

	n, err = rec.Read(buf)
	require.NoError(t, err)
	require.Equal(t, 3, n)
	require.Equal(t, "def", string(buf[:n]))

	require.Equal(t, "abcdef", rec.buf.String())
}

// readOnlyConn adapts an io.Reader to net.Conn for recordingConn tests.
type readOnlyConn struct {
	r io.Reader
}

func (c *readOnlyConn) Read(p []byte) (int, error)         { return c.r.Read(p) }
func (c *readOnlyConn) Write(p []byte) (int, error)        { return 0, io.ErrClosedPipe }
func (c *readOnlyConn) Close() error                       { return nil }
func (c *readOnlyConn) LocalAddr() net.Addr                { return dummyAddr{} }
func (c *readOnlyConn) RemoteAddr() net.Addr               { return dummyAddr{} }
func (c *readOnlyConn) SetDeadline(t time.Time) error      { return nil }
func (c *readOnlyConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *readOnlyConn) SetWriteDeadline(t time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "dummy" }
func (dummyAddr) String() string  { return "dummy" }

// Sanity: ensure the package's errSNIPeekDone is the sentinel we expect.
func TestErrSentinel(t *testing.T) {
	require.True(t, strings.Contains(errSNIPeekDone.Error(), "sni peek"))
}
