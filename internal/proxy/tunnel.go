package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/ironsh/iron-proxy/internal/transform"
)

// listenTunnel starts the CONNECT/SOCKS5 tunnel listener.
func (p *Proxy) listenTunnel() error {
	ln, err := net.Listen("tcp", p.tunnelAddr)
	if err != nil {
		return fmt.Errorf("tunnel listen: %w", err)
	}
	p.tunnelListener = ln
	p.logger.Info("tunnel proxy starting", slog.String("addr", ln.Addr().String()))

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-p.tunnelDone:
				return nil
			default:
			}
			p.logger.Warn("tunnel accept error", slog.String("error", err.Error()))
			continue
		}
		go p.handleTunnel(conn)
	}
}

// handleTunnel peeks at the first byte to dispatch to CONNECT or SOCKS5.
func (p *Proxy) handleTunnel(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			p.logger.Error("tunnel panic", slog.Any("panic", r))
		}
	}()

	br := bufio.NewReader(conn)
	first, err := br.Peek(1)
	if err != nil {
		p.logger.Debug("tunnel peek error", slog.String("error", err.Error()))
		conn.Close()
		return
	}

	// SOCKS5 starts with version byte 0x05
	if first[0] == 0x05 {
		p.handleSOCKS5(conn, br)
		return
	}

	// Otherwise assume HTTP CONNECT
	p.handleCONNECT(conn, br)
}

// handleCONNECT handles HTTP CONNECT tunnel requests.
func (p *Proxy) handleCONNECT(conn net.Conn, br *bufio.Reader) {
	defer conn.Close()

	req, err := http.ReadRequest(br)
	if err != nil {
		p.logger.Debug("tunnel CONNECT read error", slog.String("error", err.Error()))
		return
	}

	if req.Method != http.MethodConnect {
		if _, err := fmt.Fprintf(conn, "HTTP/1.1 405 Method Not Allowed\r\n\r\n"); err != nil {
			p.logger.Debug("tunnel write 405 error", slog.String("error", err.Error()))
		}
		return
	}

	host := req.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "443")
	}

	p.logger.Debug("tunnel CONNECT", slog.String("target", host))

	if !p.tunnelTransformCheck(conn.RemoteAddr().String(), host) {
		if _, err := fmt.Fprintf(conn, "HTTP/1.1 403 Forbidden\r\n\r\n"); err != nil {
			p.logger.Debug("tunnel write 403 error", slog.String("error", err.Error()))
		}
		return
	}

	// Send 200 to signal tunnel established
	if _, err := fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		p.logger.Warn("tunnel write 200 error", slog.String("target", host), slog.String("error", err.Error()))
		return
	}

	p.serveTunnel(conn, host)
}

// handleSOCKS5 handles SOCKS5 tunnel requests.
func (p *Proxy) handleSOCKS5(conn net.Conn, br *bufio.Reader) {
	defer conn.Close()

	// --- Auth negotiation ---
	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     | 1 to 255 |
	// +----+----------+----------+
	ver, err := br.ReadByte()
	if err != nil || ver != 0x05 {
		p.logger.Debug("socks5 bad version", slog.Any("ver", ver))
		return
	}

	nmethods, err := br.ReadByte()
	if err != nil {
		return
	}
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}

	// We only support no-auth (0x00)
	hasNoAuth := false
	for _, m := range methods {
		if m == 0x00 {
			hasNoAuth = true
			break
		}
	}
	if !hasNoAuth {
		// Reply with 0xFF = no acceptable methods
		if _, err := conn.Write([]byte{0x05, 0xFF}); err != nil {
			p.logger.Debug("socks5 write no-acceptable-methods error", slog.String("error", err.Error()))
		}
		return
	}
	// Reply: use no-auth
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		p.logger.Debug("socks5 write auth reply error", slog.String("error", err.Error()))
		return
	}

	// --- Connect request ---
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	header := make([]byte, 4)
	if _, err := io.ReadFull(br, header); err != nil {
		return
	}
	if header[0] != 0x05 {
		return
	}
	if header[1] != 0x01 { // only CONNECT supported
		p.socks5Reply(conn, 0x07) // command not supported
		return
	}

	var targetHost string
	atyp := header[3]
	switch atyp {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(br, addr); err != nil {
			return
		}
		targetHost = net.IP(addr).String()
	case 0x03: // Domain name
		domainLen, err := br.ReadByte()
		if err != nil {
			return
		}
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(br, domain); err != nil {
			return
		}
		targetHost = string(domain)
	case 0x04: // IPv6
		addr := make([]byte, 16)
		if _, err := io.ReadFull(br, addr); err != nil {
			return
		}
		targetHost = net.IP(addr).String()
	default:
		p.socks5Reply(conn, 0x08) // address type not supported
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(br, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)
	target := net.JoinHostPort(targetHost, strconv.Itoa(int(port)))

	p.logger.Debug("tunnel SOCKS5 CONNECT", slog.String("target", target))

	if !p.tunnelTransformCheck(conn.RemoteAddr().String(), target) {
		p.socks5Reply(conn, 0x02) // connection not allowed by ruleset
		return
	}

	// Success reply
	// +----+-----+-------+------+----------+----------+
	// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +----+-----+-------+------+----------+----------+
	reply := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(reply); err != nil {
		p.logger.Warn("socks5 write success reply error", slog.String("target", target), slog.String("error", err.Error()))
		return
	}

	p.serveTunnel(conn, target)
}

// socks5Reply sends a SOCKS5 reply with the given status code.
func (p *Proxy) socks5Reply(conn net.Conn, status byte) {
	reply := []byte{0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(reply); err != nil {
		p.logger.Debug("socks5 write reply error", slog.Int("status", int(status)), slog.String("error", err.Error()))
	}
}

// tunnelTransformCheck runs a synthetic CONNECT request through the transform
// pipeline to decide whether the tunnel should be allowed.
func (p *Proxy) tunnelTransformCheck(remoteAddr, target string) bool {
	host, _, _ := net.SplitHostPort(target)

	req := &http.Request{
		Method:     http.MethodConnect,
		Host:       target,
		URL:        &url.URL{Host: target},
		Header:     http.Header{},
		RemoteAddr: remoteAddr,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	req.Body = transform.NewBufferedBody(http.NoBody, 0)

	startedAt := time.Now()
	tctx := &transform.TransformContext{
		Logger: p.logger,
		SNI:    host,
	}

	var reqTraces []transform.TransformTrace
	result := &transform.PipelineResult{
		Host:       target,
		Method:     http.MethodConnect,
		Path:       "",
		RemoteAddr: remoteAddr,
		SNI:        host,
		StartedAt:  startedAt,
	}
	defer func() {
		result.Duration = time.Since(startedAt)
		result.RequestTransforms = reqTraces
		p.pipeline.EmitAudit(result)
	}()

	rejectResp, err := p.pipeline.ProcessRequest(req.Context(), tctx, req, &reqTraces)
	if err != nil {
		result.Action = transform.ActionContinue
		result.StatusCode = http.StatusBadGateway
		result.Err = err
		p.logger.Warn("tunnel transform error",
			slog.String("target", target),
			slog.String("error", err.Error()),
		)
		return false
	}
	if rejectResp != nil {
		result.Action = transform.ActionReject
		result.StatusCode = rejectResp.StatusCode
		p.logger.Info("tunnel rejected by transform",
			slog.String("target", target),
			slog.Int("status", rejectResp.StatusCode),
		)
		return false
	}

	result.Action = transform.ActionContinue
	result.StatusCode = http.StatusOK
	return true
}

// serveTunnel peeks at the client's first byte after the CONNECT/SOCKS5
// handshake to detect TLS (0x16) vs plain HTTP. TLS connections get MITM'd;
// plain HTTP is served directly through handleHTTP. Anything else is rejected.
func (p *Proxy) serveTunnel(clientConn net.Conn, target string) {
	br := bufio.NewReader(clientConn)
	first, err := br.Peek(1)
	if err != nil {
		p.logger.Debug("tunnel client peek error",
			slog.String("target", target),
			slog.String("error", err.Error()),
		)
		return
	}

	// Wrap the conn so the peeked byte is not lost.
	peekedConn := newPeekedConn(clientConn, br)

	if first[0] == 0x16 {
		// TLS ClientHello: MITM
		p.serveTunnelTLS(peekedConn, target)
		return
	}

	if isHTTPMethodByte(first[0]) {
		// Plain HTTP request
		p.serveTunnelHTTP(peekedConn, target)
		return
	}

	p.logger.Warn("tunnel unsupported protocol",
		slog.String("target", target),
		slog.Int("first_byte", int(first[0])),
	)
}

// serveTunnelTLS performs TLS MITM on the client connection, then serves
// HTTP requests through the normal handleHTTP handler.
func (p *Proxy) serveTunnelTLS(clientConn net.Conn, target string) {
	tlsConn := tls.Server(clientConn, &tls.Config{
		GetCertificate: p.getCertificate,
	})
	defer func() { _ = tlsConn.Close() }()

	if err := tlsConn.HandshakeContext(context.Background()); err != nil {
		p.logger.Debug("tunnel MITM TLS handshake failed",
			slog.String("target", target),
			slog.String("error", err.Error()),
		)
		return
	}

	ln := newOneConnListener(tlsConn)
	srv := &http.Server{
		Handler: http.HandlerFunc(p.handleHTTP),
	}
	_ = srv.Serve(ln)
}

// serveTunnelHTTP serves plain HTTP requests through the normal handleHTTP handler.
func (p *Proxy) serveTunnelHTTP(clientConn net.Conn, target string) {
	defer clientConn.Close()

	ln := newOneConnListener(clientConn)
	srv := &http.Server{
		Handler: http.HandlerFunc(p.handleHTTP),
	}
	_ = srv.Serve(ln)
}

// isHTTPMethodByte returns true if b could be the first byte of an HTTP method.
func isHTTPMethodByte(b byte) bool {
	// HTTP methods start with uppercase ASCII: GET, HEAD, POST, PUT, DELETE,
	// CONNECT, OPTIONS, TRACE, PATCH
	return b >= 'A' && b <= 'Z'
}

// oneConnListener is a net.Listener that returns a single connection, then
// blocks until Close is called. This lets us serve a single hijacked
// connection using http.Server.Serve.
type oneConnListener struct {
	conn net.Conn
	once sync.Once
	done chan struct{}
}

func newOneConnListener(conn net.Conn) *oneConnListener {
	return &oneConnListener{
		conn: conn,
		done: make(chan struct{}),
	}
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneConnListener) Close() error {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return nil
}

func (l *oneConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

// peekedConn wraps a net.Conn with a bufio.Reader so that bytes consumed
// by Peek are still available for subsequent reads.
type peekedConn struct {
	net.Conn
	r *bufio.Reader
}

func newPeekedConn(conn net.Conn, r *bufio.Reader) *peekedConn {
	return &peekedConn{Conn: conn, r: r}
}

func (c *peekedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

