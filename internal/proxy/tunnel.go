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

	"github.com/ironsh/iron-proxy/internal/config"
	"github.com/ironsh/iron-proxy/internal/transform"
)

// tunnelAnnotationsKey is the context key for CONNECT transform annotations
// propagated to inner HTTP requests within the same tunnel.
type tunnelAnnotationsKeyType struct{}

var tunnelAnnotationsKey = tunnelAnnotationsKeyType{}

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
// This is the single logging point for tunnel connection errors.
func (p *Proxy) handleTunnel(conn net.Conn) {
	br := bufio.NewReader(conn)
	first, err := br.Peek(1)
	if err != nil {
		p.logger.Debug("tunnel peek error", slog.String("error", err.Error()))
		conn.Close()
		return
	}

	// SOCKS5 starts with version byte 0x05
	if first[0] == 0x05 {
		if err := p.handleSOCKS5(conn, br); err != nil {
			p.logger.Debug("tunnel socks5 error", slog.String("error", err.Error()))
		}
		return
	}

	// Otherwise assume HTTP CONNECT
	if err := p.handleCONNECT(conn, br); err != nil {
		p.logger.Debug("tunnel connect error", slog.String("error", err.Error()))
	}
}

// handleCONNECT handles HTTP CONNECT tunnel requests.
func (p *Proxy) handleCONNECT(conn net.Conn, br *bufio.Reader) error {
	defer conn.Close()

	req, err := http.ReadRequest(br)
	if err != nil {
		return fmt.Errorf("read request: %w", err)
	}

	if req.Method != http.MethodConnect {
		if _, err := fmt.Fprintf(conn, "HTTP/1.1 405 Method Not Allowed\r\n\r\n"); err != nil {
			return fmt.Errorf("write 405: %w", err)
		}
		return nil
	}

	host := req.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "443")
	}

	p.logger.Debug("tunnel CONNECT", slog.String("target", host))

	ok, rejectResp, connectAnnotations := p.tunnelTransformCheck(conn.RemoteAddr().String(), host, req.Header)
	if !ok {
		status := 403
		var headerLines string
		if rejectResp != nil {
			status = rejectResp.StatusCode
			for k, vals := range rejectResp.Header {
				for _, v := range vals {
					headerLines += fmt.Sprintf("%s: %s\r\n", k, v)
				}
			}
		}
		if _, err := fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\n%s\r\n", status, http.StatusText(status), headerLines); err != nil {
			return fmt.Errorf("write %d: %w", status, err)
		}
		return nil
	}

	// Send 200 to signal tunnel established
	if _, err := fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return fmt.Errorf("write 200: %w", err)
	}

	return p.serveTunnel(conn, host, connectAnnotations)
}

// handleSOCKS5 handles SOCKS5 tunnel requests.
func (p *Proxy) handleSOCKS5(conn net.Conn, br *bufio.Reader) error {
	defer conn.Close()

	// --- Auth negotiation ---
	ver, err := br.ReadByte()
	if err != nil {
		return fmt.Errorf("read version: %w", err)
	}
	if ver != 0x05 {
		return fmt.Errorf("unsupported socks version: %d", ver)
	}

	nmethods, err := br.ReadByte()
	if err != nil {
		return fmt.Errorf("read nmethods: %w", err)
	}
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(br, methods); err != nil {
		return fmt.Errorf("read methods: %w", err)
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
		if err := p.socks5Reply(conn, 0xFF); err != nil {
			return fmt.Errorf("write no-acceptable-methods: %w", err)
		}
		return nil
	}
	// Reply: use no-auth
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return fmt.Errorf("write auth reply: %w", err)
	}

	// --- Connect request ---
	header := make([]byte, 4)
	if _, err := io.ReadFull(br, header); err != nil {
		return fmt.Errorf("read connect header: %w", err)
	}
	if header[0] != 0x05 {
		return fmt.Errorf("unexpected socks version in connect: %d", header[0])
	}
	if header[1] != 0x01 { // only CONNECT supported
		if err := p.socks5Reply(conn, 0x07); err != nil {
			return fmt.Errorf("write command-not-supported: %w", err)
		}
		return nil
	}

	var targetHost string
	atyp := header[3]
	switch atyp {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(br, addr); err != nil {
			return fmt.Errorf("read ipv4 addr: %w", err)
		}
		targetHost = net.IP(addr).String()
	case 0x03: // Domain name
		domainLen, err := br.ReadByte()
		if err != nil {
			return fmt.Errorf("read domain length: %w", err)
		}
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(br, domain); err != nil {
			return fmt.Errorf("read domain: %w", err)
		}
		targetHost = string(domain)
	case 0x04: // IPv6
		addr := make([]byte, 16)
		if _, err := io.ReadFull(br, addr); err != nil {
			return fmt.Errorf("read ipv6 addr: %w", err)
		}
		targetHost = net.IP(addr).String()
	default:
		if err := p.socks5Reply(conn, 0x08); err != nil {
			return fmt.Errorf("write address-type-not-supported: %w", err)
		}
		return nil
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(br, portBuf); err != nil {
		return fmt.Errorf("read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf)
	target := net.JoinHostPort(targetHost, strconv.Itoa(int(port)))

	p.logger.Debug("tunnel SOCKS5 CONNECT", slog.String("target", target))

	ok, _, connectAnnotations := p.tunnelTransformCheck(conn.RemoteAddr().String(), target, nil)
	if !ok {
		if err := p.socks5Reply(conn, 0x02); err != nil {
			return fmt.Errorf("write connection-not-allowed: %w", err)
		}
		return nil
	}

	// Success reply
	reply := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(reply); err != nil {
		return fmt.Errorf("write success reply: %w", err)
	}

	return p.serveTunnel(conn, target, connectAnnotations)
}

// socks5Reply sends a SOCKS5 reply with the given status code.
func (p *Proxy) socks5Reply(conn net.Conn, status byte) error {
	reply := []byte{0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	_, err := conn.Write(reply)
	return err
}

// tunnelTransformCheck runs a synthetic CONNECT request through the transform
// pipeline to decide whether the tunnel should be allowed. When connectHeaders
// is non-nil the headers from the original CONNECT request (e.g.
// Proxy-Authorization) are forwarded to transforms so they can make
// authentication and policy decisions at the tunnel level.
func (p *Proxy) tunnelTransformCheck(remoteAddr, target string, connectHeaders http.Header) (bool, *http.Response, map[string]any) {
	host, _, _ := net.SplitHostPort(target)

	hdr := http.Header{}
	if connectHeaders != nil {
		hdr = connectHeaders.Clone()
	}

	req := &http.Request{
		Method:     http.MethodConnect,
		Host:       target,
		URL:        &url.URL{Host: target},
		Header:     hdr,
		RemoteAddr: remoteAddr,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	req.Body = transform.NewBufferedBody(http.NoBody, 0)

	mode := transform.ModeMITM
	if p.tlsMode == config.TLSModeSNIOnly {
		mode = transform.ModeSNIOnly
	}

	tctx := &transform.TransformContext{
		Logger: p.logger,
		SNI:    host,
		Mode:   mode,
	}

	result := &transform.PipelineResult{
		Host:       target,
		Method:     http.MethodConnect,
		Path:       "",
		RemoteAddr: remoteAddr,
		SNI:        host,
		Mode:       mode,
	}
	pl, finish := p.beginPipelineRun(result)
	defer finish()

	rejectResp, err := pl.ProcessRequest(req.Context(), tctx, req, &result.RequestTransforms)
	if err != nil {
		result.Action = transform.ActionContinue
		result.StatusCode = http.StatusBadGateway
		result.Err = err
		p.logger.Warn("tunnel transform error",
			slog.String("target", target),
			slog.String("error", err.Error()),
		)
		return false, nil, nil
	}
	if rejectResp != nil {
		result.Action = transform.ActionReject
		result.StatusCode = rejectResp.StatusCode
		p.logger.Info("tunnel rejected by transform",
			slog.String("target", target),
			slog.Int("status", rejectResp.StatusCode),
		)
		return false, rejectResp, nil
	}

	// Collect annotations from all CONNECT transforms
	annotations := make(map[string]any)
	for _, tr := range result.RequestTransforms {
		for k, v := range tr.Annotations {
			annotations[k] = v
		}
	}

	result.Action = transform.ActionContinue
	result.StatusCode = http.StatusOK
	return true, nil, annotations
}

// serveTunnel peeks at the client's first byte after the CONNECT/SOCKS5
// handshake to detect TLS (0x16) vs plain HTTP. TLS connections get MITM'd;
// plain HTTP is served directly through handleHTTP. Anything else is rejected.
func (p *Proxy) serveTunnel(clientConn net.Conn, target string, connectAnnotations map[string]any) error {
	br := bufio.NewReader(clientConn)
	first, err := br.Peek(1)
	if err != nil {
		return fmt.Errorf("peek client protocol: %w", err)
	}

	// Wrap the conn so the peeked byte is not lost.
	peekedConn := newPeekedConn(clientConn, br)

	if first[0] == 0x16 {
		// TLS ClientHello: MITM
		return p.serveTunnelTLS(peekedConn, target, connectAnnotations)
	}

	if isHTTPMethodByte(first[0]) {
		// Plain HTTP request
		return p.serveTunnelHTTP(peekedConn, target, connectAnnotations)
	}

	return fmt.Errorf("unsupported protocol (first byte 0x%02x) for target %s", first[0], target)
}

// serveTunnelTLS handles the TLS branch of a tunnel connection. In MITM mode
// it terminates TLS and serves HTTP via handleHTTP; in sni-only mode it
// peeks SNI and TCP-passthroughs to the SNI host on port 443 (the CONNECT
// port is ignored to prevent port-pivot attacks).
func (p *Proxy) serveTunnelTLS(clientConn net.Conn, target string, connectAnnotations map[string]any) error {
	if p.tlsMode == config.TLSModeSNIOnly {
		return p.serveSNIPassthrough(clientConn)
	}

	tlsConn := tls.Server(clientConn, &tls.Config{
		GetCertificate: p.getCertificate,
	})
	defer func() { _ = tlsConn.Close() }()

	if err := tlsConn.HandshakeContext(context.Background()); err != nil {
		return fmt.Errorf("TLS handshake for %s: %w", target, err)
	}

	ln := newOneConnListener(tlsConn)
	srv := &http.Server{
		Handler: p.withTunnelAnnotations(connectAnnotations),
	}
	return srv.Serve(ln)
}

// serveTunnelHTTP serves plain HTTP requests through the normal handleHTTP handler.
func (p *Proxy) serveTunnelHTTP(clientConn net.Conn, target string, connectAnnotations map[string]any) error {
	defer clientConn.Close()

	ln := newOneConnListener(clientConn)
	srv := &http.Server{
		Handler: p.withTunnelAnnotations(connectAnnotations),
	}
	return srv.Serve(ln)
}

// withTunnelAnnotations wraps handleHTTP to inject CONNECT annotations into
// the request context so inner requests inherit the tunnel's identity.
func (p *Proxy) withTunnelAnnotations(annotations map[string]any) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(annotations) > 0 {
			r = r.WithContext(context.WithValue(r.Context(), tunnelAnnotationsKey, annotations))
		}
		p.handleHTTP(w, r)
	})
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
