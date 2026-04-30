// Package proxy implements the iron-proxy HTTP/HTTPS proxy. The HTTPS
// listener supports two modes: MITM (default), which terminates TLS using a
// CA-signed leaf cert, and SNI-only, which peeks the ClientHello SNI and
// TCP-passthroughs to the upstream without terminating TLS.
package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ironsh/iron-proxy/internal/certcache"
	"github.com/ironsh/iron-proxy/internal/config"
	"github.com/ironsh/iron-proxy/internal/dnsguard"
	"github.com/ironsh/iron-proxy/internal/transform"
)

// Proxy is the HTTP/HTTPS proxy server. When Mode is TLSModeMITM, the HTTPS
// listener terminates TLS using certCache; when Mode is TLSModeSNIOnly, the
// listener peeks the SNI from the ClientHello and TCP-passthroughs to the
// upstream without terminating TLS.
type Proxy struct {
	httpServer     *http.Server
	httpsServer    *http.Server
	httpsAddr      string
	tlsMode        string
	tlsListener    net.Listener
	tunnelAddr     string
	tunnelListener net.Listener
	tunnelDone     chan struct{}
	certCache      *certcache.Cache
	pipeline       *transform.PipelineHolder
	transport      *http.Transport
	resolver       *net.Resolver
	guard          *dnsguard.Guard
	logger         *slog.Logger

	// shutdownCtx is canceled by Shutdown to unblock in-flight TCP-passthrough
	// connections that would otherwise sit on blocking Reads.
	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc

	// sniUpstreamPort is the port dialed for SNI-only passthrough. Fixed at
	// 443 in production so a client-supplied CONNECT port cannot pivot an
	// allowlisted hostname onto a different port. Overridable in tests.
	sniUpstreamPort string
}

// Options configures Proxy construction.
type Options struct {
	HTTPAddr   string
	HTTPSAddr  string
	TunnelAddr string
	TLSMode    string
	CertCache  *certcache.Cache // required when TLSMode == config.TLSModeMITM
	Pipeline   *transform.PipelineHolder
	Resolver   *net.Resolver
	Guard      *dnsguard.Guard // nil is treated as an empty (no-op) guard
	Logger     *slog.Logger
	// UpstreamResponseHeaderTimeout overrides the upstream HTTP transport's
	// ResponseHeaderTimeout. Zero falls back to
	// config.DefaultUpstreamResponseHeaderTimeout.
	UpstreamResponseHeaderTimeout time.Duration
}

// New creates a new Proxy. In TLSModeMITM, certCache must be non-nil. In
// TLSModeSNIOnly, certCache is unused and may be nil.
func New(opts Options) *Proxy {
	if opts.TLSMode == "" {
		opts.TLSMode = config.TLSModeMITM
	}
	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
	guard := opts.Guard
	if guard == nil {
		guard, _ = dnsguard.New(nil)
	}
	p := &Proxy{
		httpsAddr:      opts.HTTPSAddr,
		tlsMode:        opts.TLSMode,
		tunnelAddr:     opts.TunnelAddr,
		tunnelDone:     make(chan struct{}),
		certCache:      opts.CertCache,
		pipeline:       opts.Pipeline,
		transport:      buildTransport(opts.Resolver, guard, opts.UpstreamResponseHeaderTimeout),
		resolver:       opts.Resolver,
		guard:          guard,
		logger:         opts.Logger,
		shutdownCtx:    shutdownCtx,
		shutdownCancel: shutdownCancel,
	}

	p.httpServer = &http.Server{
		Addr:    opts.HTTPAddr,
		Handler: http.HandlerFunc(p.handleHTTP),
	}

	p.httpsServer = &http.Server{
		Addr:    opts.HTTPSAddr,
		Handler: http.HandlerFunc(p.handleHTTP),
		TLSConfig: &tls.Config{
			GetCertificate: p.getCertificate,
		},
	}

	return p
}

// ListenAndServe starts the HTTP, HTTPS, and (optionally) tunnel listeners.
// It blocks until any server has stopped.
func (p *Proxy) ListenAndServe() error {
	n := 2
	if p.tunnelAddr != "" {
		n = 3
	}
	errc := make(chan error, n)

	go func() {
		ln, err := net.Listen("tcp", p.httpServer.Addr)
		if err != nil {
			errc <- fmt.Errorf("http listen: %w", err)
			return
		}
		p.logger.Info("http proxy starting", slog.String("addr", ln.Addr().String()))
		errc <- fmt.Errorf("http: %w", p.httpServer.Serve(ln))
	}()

	go func() {
		if p.tlsMode == config.TLSModeSNIOnly {
			errc <- p.serveHTTPSSNI()
		} else {
			errc <- p.serveHTTPSMITM()
		}
	}()

	if p.tunnelAddr != "" {
		go func() {
			errc <- fmt.Errorf("tunnel: %w", p.listenTunnel())
		}()
	}

	return <-errc
}

// serveHTTPSMITM terminates TLS on the HTTPS listener and serves requests
// through handleHTTP with leaf certs minted by the configured CA.
func (p *Proxy) serveHTTPSMITM() error {
	ln, err := net.Listen("tcp", p.httpsAddr)
	if err != nil {
		return fmt.Errorf("https listen: %w", err)
	}
	tlsLn := tls.NewListener(ln, p.httpsServer.TLSConfig)
	p.tlsListener = tlsLn
	p.logger.Info("https proxy starting", slog.String("addr", ln.Addr().String()))
	return fmt.Errorf("https: %w", p.httpsServer.Serve(tlsLn))
}

// serveHTTPSSNI runs the HTTPS listener in sni-only mode: accepts raw TCP
// connections, peeks the ClientHello SNI, and TCP-passthroughs to upstream
// without terminating TLS.
func (p *Proxy) serveHTTPSSNI() error {
	ln, err := net.Listen("tcp", p.httpsAddr)
	if err != nil {
		return fmt.Errorf("https listen: %w", err)
	}
	p.tlsListener = ln
	p.logger.Info("https proxy starting (sni-only)", slog.String("addr", ln.Addr().String()))
	for {
		conn, err := ln.Accept()
		if err != nil {
			if p.shutdownCtx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			p.logger.Warn("https accept error", slog.String("error", err.Error()))
			continue
		}
		go p.handleSNIPassthrough(conn)
	}
}

// Shutdown gracefully stops all servers.
func (p *Proxy) Shutdown(ctx context.Context) error {
	// Cancel shutdownCtx first so any in-flight TCP-passthrough proxyBidi
	// goroutines close their connections and unblock their blocking Reads.
	p.shutdownCancel()

	errHTTP := p.httpServer.Shutdown(ctx)

	var errHTTPS error
	if p.tlsMode == config.TLSModeSNIOnly {
		if p.tlsListener != nil {
			_ = p.tlsListener.Close()
		}
	} else {
		errHTTPS = p.httpsServer.Shutdown(ctx)
	}

	// Signal tunnel accept loop to stop, then close the listener.
	close(p.tunnelDone)
	if p.tunnelListener != nil {
		p.tunnelListener.Close()
	}

	if errHTTP != nil {
		return errHTTP
	}
	return errHTTPS
}

func (p *Proxy) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if p.certCache == nil {
		return nil, fmt.Errorf("cert cache not configured")
	}
	if hello.ServerName == "" {
		return nil, fmt.Errorf("no SNI provided")
	}
	return p.certCache.GetOrCreate(hello.ServerName)
}

// beginPipelineRun snapshots the current pipeline and returns a finish
// function that computes Duration and emits the audit record. The caller is
// responsible for populating result.Action, StatusCode, traces, and Err
// before finish runs — typically via defer. StartedAt is set here.
func (p *Proxy) beginPipelineRun(result *transform.PipelineResult) (*transform.Pipeline, func()) {
	pl := p.pipeline.Load()
	result.StartedAt = time.Now()
	return pl, func() {
		result.Duration = time.Since(result.StartedAt)
		pl.EmitAudit(result)
	}
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	host := r.Host
	if host == "" {
		http.Error(w, "missing Host header", http.StatusBadRequest)
		return
	}

	// Validate SNI matches Host header on TLS connections
	if r.TLS != nil {
		hostOnly := r.Host
		if h, _, err := net.SplitHostPort(hostOnly); err == nil {
			hostOnly = h
		}
		if r.TLS.ServerName != hostOnly {
			p.logger.Warn("SNI/Host mismatch",
				slog.String("sni", r.TLS.ServerName),
				slog.String("host", r.Host),
			)
			http.Error(w, "SNI and Host header mismatch", http.StatusBadRequest)
			return
		}
	}

	// Build transform context and audit state
	tctx := &transform.TransformContext{
		Logger: p.logger,
		Mode:   transform.ModeMITM,
	}
	if r.TLS != nil {
		tctx.SNI = r.TLS.ServerName
	}

	result := &transform.PipelineResult{
		Host:       r.Host,
		Method:     r.Method,
		Path:       r.URL.Path,
		RemoteAddr: r.RemoteAddr,
		SNI:        tctx.SNI,
		Mode:       transform.ModeMITM,
	}
	pl, finish := p.beginPipelineRun(result)
	defer finish()

	bodyLimits := pl.BodyLimits()
	// Wrap request body for lazy buffering by transforms.
	r.Body = transform.NewBufferedBody(r.Body, bodyLimits.MaxRequestBodyBytes)

	// Run request transforms
	if rejectResp, err := pl.ProcessRequest(r.Context(), tctx, r, &result.RequestTransforms); err != nil {
		result.Action = transform.ActionContinue // error, not reject
		result.StatusCode = http.StatusBadGateway
		result.Err = err
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	} else if rejectResp != nil {
		result.Action = transform.ActionReject
		result.StatusCode = rejectResp.StatusCode
		p.writeResponse(w, rejectResp)
		return
	}

	// WebSocket upgrade: hijack and proxy bidirectionally
	if isWebSocketUpgrade(r) {
		result.Action = transform.ActionContinue
		result.StatusCode = http.StatusSwitchingProtocols
		p.handleWebSocket(w, r, scheme, host)
		return
	}

	// Build upstream request. Use r.URL (which transforms may have modified)
	// rather than r.RequestURI (which is immutable).
	path := r.URL.Path
	if r.URL.RawQuery != "" {
		path = path + "?" + r.URL.RawQuery
	}
	upstreamURL := fmt.Sprintf("%s://%s%s", scheme, host, path)

	reqBody := transform.RequireBufferedBody(r.Body)
	// Check Len() before StreamingReader(), which clears the original reader.
	reqBodyLen := reqBody.Len()
	upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, io.NopCloser(reqBody.StreamingReader()))
	if err != nil {
		result.Action = transform.ActionContinue
		result.StatusCode = http.StatusBadGateway
		result.Err = err
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	copyHeaders(upstreamReq.Header, r.Header)
	// If a transform buffered the request body, set ContentLength so the
	// upstream receives a Content-Length header instead of chunked encoding.
	// Otherwise, preserve the original Content-Length from the client.
	if reqBodyLen >= 0 {
		upstreamReq.ContentLength = int64(reqBodyLen)
	} else {
		upstreamReq.ContentLength = r.ContentLength
	}

	resp, err := p.doUpstream(upstreamReq)
	if err != nil {
		result.Action = transform.ActionContinue
		result.StatusCode = http.StatusBadGateway
		result.Err = err
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Wrap response body for lazy buffering by transforms.
	resp.Body = transform.NewBufferedBody(resp.Body, bodyLimits.MaxResponseBodyBytes)

	// Run response transforms
	finalResp, err := pl.ProcessResponse(r.Context(), tctx, r, resp, &result.ResponseTransforms)
	if err != nil {
		result.Action = transform.ActionContinue
		result.StatusCode = http.StatusBadGateway
		result.Err = err
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}

	result.Action = transform.ActionContinue
	result.StatusCode = finalResp.StatusCode

	// SSE: stream with flushing
	if isSSE(finalResp) {
		p.streamSSE(w, finalResp)
		return
	}

	p.writeResponse(w, finalResp)
}

// isWebSocketUpgrade detects a WebSocket upgrade request.
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// handleWebSocket hijacks the client connection and proxies raw bytes
// bidirectionally to the upstream WebSocket server.
func (p *Proxy) handleWebSocket(w http.ResponseWriter, r *http.Request, scheme, host string) {
	// Dial the upstream
	upstreamScheme := "ws"
	if scheme == "https" {
		upstreamScheme = "wss"
	}

	var upstreamConn net.Conn
	var err error

	upstreamHost := host
	if _, _, splitErr := net.SplitHostPort(host); splitErr != nil {
		if upstreamScheme == "wss" {
			upstreamHost = host + ":443"
		} else {
			upstreamHost = host + ":80"
		}
	}

	dialer := &net.Dialer{
		Timeout:  30 * time.Second,
		Resolver: p.resolver,
		Control:  p.guard.DialControl,
	}
	if upstreamScheme == "wss" {
		upstreamConn, err = tls.DialWithDialer(
			dialer,
			"tcp", upstreamHost,
			&tls.Config{MinVersion: tls.VersionTLS12},
		)
	} else {
		upstreamConn, err = dialer.DialContext(r.Context(), "tcp", upstreamHost)
	}
	if err != nil {
		p.logger.Error("websocket upstream dial failed",
			slog.String("host", host),
			slog.String("error", err.Error()),
		)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}

	// Write the original HTTP upgrade request to upstream
	if writeErr := r.Write(upstreamConn); writeErr != nil {
		p.logger.Error("websocket upstream write failed", slog.String("error", writeErr.Error()))
		upstreamConn.Close()
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}

	// Hijack the client connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		p.logger.Error("websocket hijack not supported")
		upstreamConn.Close()
		http.Error(w, "websocket not supported", http.StatusInternalServerError)
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		p.logger.Error("websocket hijack failed", slog.String("error", err.Error()))
		upstreamConn.Close()
		return
	}

	// Proxy bidirectionally
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if _, err := io.Copy(upstreamConn, clientBuf); err != nil {
			p.logger.Debug("websocket client->upstream copy error", slog.String("error", err.Error()))
		}
		// Signal upstream we're done writing
		if tc, ok := upstreamConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		if _, err := io.Copy(clientConn, upstreamConn); err != nil {
			p.logger.Debug("websocket upstream->client copy error", slog.String("error", err.Error()))
		}
		// Signal client we're done writing
		if tc, ok := clientConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
	clientConn.Close()
	upstreamConn.Close()

	p.logger.Debug("websocket connection closed", slog.String("host", host))
}

// isSSE detects a Server-Sent Events response.
func isSSE(resp *http.Response) bool {
	ct := resp.Header.Get("Content-Type")
	return strings.HasPrefix(ct, "text/event-stream")
}

// streamSSE writes an SSE response with per-chunk flushing.
func (p *Proxy) streamSSE(w http.ResponseWriter, resp *http.Response) {
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	reader := transform.RequireBufferedBody(resp.Body).StreamingReader()

	flusher, ok := w.(http.Flusher)
	if !ok {
		if _, err := io.Copy(w, reader); err != nil {
			p.logger.Warn("SSE copy error", slog.String("error", err.Error()))
		}
		return
	}

	buf := make([]byte, 32*1024)
	for {
		n, readErr := reader.Read(buf)
		if n > 0 {
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				p.logger.Warn("SSE write error", slog.String("error", writeErr.Error()))
				break
			}
			flusher.Flush()
		}
		if readErr != nil {
			if readErr != io.EOF {
				p.logger.Warn("SSE read error", slog.String("error", readErr.Error()))
			}
			break
		}
	}
}

func (p *Proxy) writeResponse(w http.ResponseWriter, resp *http.Response) {
	copyHeaders(w.Header(), resp.Header)
	if buf, ok := resp.Body.(*transform.BufferedBody); ok {
		// If a transform buffered the response body, set Content-Length
		// from the buffered data. Otherwise preserve the upstream header
		// as-is so clients that require Content-Length (e.g. Docker)
		// work correctly.
		if n := buf.Len(); n >= 0 {
			w.Header().Set("Content-Length", strconv.FormatInt(int64(n), 10))
		}
		w.WriteHeader(resp.StatusCode)
		if _, err := io.Copy(w, buf.StreamingReader()); err != nil {
			p.logger.Warn("response body copy error", slog.String("error", err.Error()))
		}
	} else {
		// Synthetic responses (e.g. reject) with plain bodies.
		w.WriteHeader(resp.StatusCode)
		if resp.Body != nil {
			if _, err := io.Copy(w, resp.Body); err != nil {
				p.logger.Warn("response body copy error", slog.String("error", err.Error()))
			}
		}
	}
}

// buildTransport creates the HTTP transport used for upstream requests.
// If resolver is non-nil, the transport's dialer uses it instead of the OS
// default — this prevents resolution loops when iron-proxy owns the system DNS.
// guard's DialControl is wired in so a hostname that resolves to a denied IP
// is rejected before the TCP connect.
// responseHeaderTimeout overrides the default 30-second
// ResponseHeaderTimeout when greater than zero; pass 0 to keep the default.
func buildTransport(resolver *net.Resolver, guard *dnsguard.Guard, responseHeaderTimeout time.Duration) *http.Transport {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver:  resolver,
		Control:   guard.DialControl,
	}
	if responseHeaderTimeout <= 0 {
		responseHeaderTimeout = config.DefaultUpstreamResponseHeaderTimeout
	}
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		DialContext:           dialer.DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: responseHeaderTimeout,
	}
}

func (p *Proxy) doUpstream(req *http.Request) (*http.Response, error) {
	return p.transport.RoundTrip(req)
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}
