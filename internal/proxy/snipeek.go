package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"
)

// errSNIPeekDone is returned from GetConfigForClient to abort the TLS handshake
// after the ClientHello has been parsed and the SNI captured.
var errSNIPeekDone = errors.New("sni peek complete")

// peekSNI reads a TLS ClientHello from conn, parses it via crypto/tls, and
// returns the SNI hostname plus the raw bytes consumed from conn so the caller
// can replay them to an upstream server.
//
// The approach: wrap conn so all Reads are teed into a buffer, call tls.Server
// with a GetConfigForClient callback that captures SNI and aborts the handshake,
// and swallow writes (the abort triggers an alert that we don't want to send to
// the client). Any post-handshake bytes remain in the underlying conn for the
// caller to io.Copy normally.
func peekSNI(conn net.Conn, timeout time.Duration) (sni string, peeked []byte, err error) {
	deadline := time.Now().Add(timeout)
	if err := conn.SetReadDeadline(deadline); err != nil {
		return "", nil, fmt.Errorf("set read deadline: %w", err)
	}
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	rec := &recordingConn{Conn: conn}
	var captured string
	var called bool

	tlsCfg := &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			captured = hello.ServerName
			called = true
			return nil, errSNIPeekDone
		},
	}

	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	tlsConn := tls.Server(rec, tlsCfg)
	handshakeErr := tlsConn.HandshakeContext(ctx)

	if !called {
		if handshakeErr == nil {
			return "", nil, fmt.Errorf("tls handshake completed unexpectedly during sni peek")
		}
		return "", nil, fmt.Errorf("tls handshake failed before client hello parsed: %w", handshakeErr)
	}
	return captured, rec.buf.Bytes(), nil
}

// recordingConn wraps a net.Conn so that all bytes read from it are also
// buffered for later replay, and all writes are silently discarded. This lets
// us drive crypto/tls far enough to parse the ClientHello without sending a
// handshake response (or an abort alert) back to the peer.
type recordingConn struct {
	net.Conn
	buf bytes.Buffer
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.buf.Write(p[:n])
	}
	return n, err
}

func (c *recordingConn) Write(p []byte) (int, error) {
	return len(p), nil
}
