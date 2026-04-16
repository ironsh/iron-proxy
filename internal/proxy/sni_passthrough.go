package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/ironsh/iron-proxy/internal/transform"
)

const (
	sniPeekTimeout  = 5 * time.Second
	sniUpstreamDial = 30 * time.Second
)

// handleSNIPassthrough is the connection handler used by the HTTPS listener
// when tls.mode is "sni-only". It peeks the SNI from the ClientHello, runs
// the transform pipeline with a host-only synthetic request, and on accept
// TCP-passthroughs the connection to the upstream server.
func (p *Proxy) handleSNIPassthrough(clientConn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			p.logger.Error("sni passthrough panic", slog.Any("panic", r))
		}
	}()

	target := net.JoinHostPort("", "443")
	if err := p.serveSNIPassthrough(clientConn, target); err != nil {
		p.logger.Debug("sni passthrough error", slog.String("error", err.Error()))
	}
}

// serveSNIPassthrough peeks SNI, runs the pipeline, and TCP-passthroughs the
// connection if allowed. targetPort is "host:port" whose port is used as the
// upstream port (host is filled in from the peeked SNI). Used by both the
// HTTPS listener and the CONNECT/SOCKS5 tunnel TLS branch in sni-only mode.
func (p *Proxy) serveSNIPassthrough(clientConn net.Conn, targetPort string) error {
	defer clientConn.Close()

	sni, peeked, err := peekSNI(clientConn, sniPeekTimeout)
	if err != nil {
		return fmt.Errorf("peek sni: %w", err)
	}

	// Determine the upstream port: prefer the port in targetPort (from CONNECT
	// target), fall back to 443 for the raw HTTPS listener which passes an
	// empty host.
	port := "443"
	if targetPort != "" {
		if _, p, splitErr := net.SplitHostPort(targetPort); splitErr == nil && p != "" {
			port = p
		}
	}

	// Run the pipeline with a host-only synthetic request.
	tctx := &transform.TransformContext{
		Logger: p.logger,
		SNI:    sni,
		Mode:   transform.ModeSNIOnly,
	}

	result := &transform.PipelineResult{
		Host:       sni,
		RemoteAddr: clientConn.RemoteAddr().String(),
		SNI:        sni,
		Mode:       transform.ModeSNIOnly,
	}
	pl, finish := p.beginPipelineRun(result)
	defer finish()

	req := &http.Request{
		Host:       sni,
		URL:        &url.URL{Scheme: "https", Host: sni},
		Header:     http.Header{},
		RemoteAddr: clientConn.RemoteAddr().String(),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	req.Body = transform.NewBufferedBody(http.NoBody, 0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rejectResp, pipelineErr := pl.ProcessRequest(ctx, tctx, req, &result.RequestTransforms)
	if pipelineErr != nil {
		result.Action = transform.ActionContinue
		result.StatusCode = http.StatusBadGateway
		result.Err = pipelineErr
		return fmt.Errorf("pipeline error for %q: %w", sni, pipelineErr)
	}
	if rejectResp != nil {
		result.Action = transform.ActionReject
		result.StatusCode = rejectResp.StatusCode
		p.logger.Info("sni passthrough rejected by transform",
			slog.String("sni", sni),
			slog.Int("status", rejectResp.StatusCode),
		)
		return nil
	}

	if sni == "" {
		result.Action = transform.ActionReject
		result.StatusCode = http.StatusBadRequest
		result.Err = fmt.Errorf("client hello missing sni")
		return fmt.Errorf("client hello missing sni")
	}

	// Dial upstream using the proxy's resolver so SNI → IP lookup goes via
	// the configured upstream DNS (not the proxy's own intercepting server).
	dialer := &net.Dialer{
		Timeout:  sniUpstreamDial,
		Resolver: p.resolver,
	}
	upstream, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(sni, port))
	if err != nil {
		result.Action = transform.ActionContinue
		result.StatusCode = http.StatusBadGateway
		result.Err = err
		return fmt.Errorf("dial upstream %s: %w", sni, err)
	}
	defer upstream.Close()

	// Replay the peeked ClientHello bytes to upstream.
	if _, err := upstream.Write(peeked); err != nil {
		result.Action = transform.ActionContinue
		result.StatusCode = http.StatusBadGateway
		result.Err = err
		return fmt.Errorf("replay client hello to %s: %w", sni, err)
	}

	result.Action = transform.ActionContinue
	result.StatusCode = http.StatusOK

	// Proxy bidirectionally until either side closes.
	proxyBidi(clientConn, upstream, p.logger)
	return nil
}

// proxyBidi copies bytes between two connections in both directions, closing
// write halves on EOF and logging copy errors at debug level.
func proxyBidi(a, b net.Conn, logger *slog.Logger) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if _, err := io.Copy(b, a); err != nil {
			logger.Debug("sni passthrough a->b copy error", slog.String("error", err.Error()))
		}
		if tc, ok := b.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		if _, err := io.Copy(a, b); err != nil {
			logger.Debug("sni passthrough b->a copy error", slog.String("error", err.Error()))
		}
		if tc, ok := a.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	wg.Wait()
}
