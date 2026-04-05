// Package proxy implements the iron-proxy HTTP/HTTPS MITM proxy.
package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ironsh/iron-proxy/internal/certcache"
	"github.com/ironsh/iron-proxy/internal/transform"
)

// Proxy is the HTTP/HTTPS MITM proxy server.
type Proxy struct {
	httpServer  *http.Server
	httpsServer *http.Server
	tlsListener net.Listener
	certCache   *certcache.Cache
	pipeline    *transform.Pipeline
	transport   *http.Transport
	logger      *slog.Logger
}

// New creates a new Proxy. If resolver is non-nil, it is used to resolve
// upstream hostnames instead of the OS default resolver.
func New(httpAddr, httpsAddr string, certCache *certcache.Cache, pipeline *transform.Pipeline, resolver *net.Resolver, logger *slog.Logger) *Proxy {
	p := &Proxy{
		certCache: certCache,
		pipeline:  pipeline,
		transport: buildTransport(resolver),
		logger:    logger,
	}

	p.httpServer = &http.Server{
		Addr:    httpAddr,
		Handler: http.HandlerFunc(p.handleHTTP),
	}

	p.httpsServer = &http.Server{
		Addr:    httpsAddr,
		Handler: http.HandlerFunc(p.handleHTTP),
		TLSConfig: &tls.Config{
			GetCertificate: p.getCertificate,
		},
	}

	return p
}

// ListenAndServe starts both HTTP and HTTPS listeners. It blocks until
// both servers have stopped.
func (p *Proxy) ListenAndServe() error {
	errc := make(chan error, 2)

	go func() {
		p.logger.Info("http proxy starting", slog.String("addr", p.httpServer.Addr))
		errc <- fmt.Errorf("http: %w", p.httpServer.ListenAndServe())
	}()

	go func() {
		ln, err := net.Listen("tcp", p.httpsServer.Addr)
		if err != nil {
			errc <- fmt.Errorf("https listen: %w", err)
			return
		}
		tlsLn := tls.NewListener(ln, p.httpsServer.TLSConfig)
		p.tlsListener = tlsLn
		p.logger.Info("https proxy starting", slog.String("addr", ln.Addr().String()))
		errc <- fmt.Errorf("https: %w", p.httpsServer.Serve(tlsLn))
	}()

	return <-errc
}

// Shutdown gracefully stops both servers.
func (p *Proxy) Shutdown(ctx context.Context) error {
	errHTTP := p.httpServer.Shutdown(ctx)
	errHTTPS := p.httpsServer.Shutdown(ctx)
	if errHTTP != nil {
		return errHTTP
	}
	return errHTTPS
}

func (p *Proxy) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello.ServerName == "" {
		return nil, fmt.Errorf("no SNI provided")
	}
	return p.certCache.GetOrCreate(hello.ServerName)
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
	startedAt := time.Now()
	bodyLimits := p.pipeline.BodyLimits()
	tctx := &transform.TransformContext{
		Logger: p.logger,
	}
	if r.TLS != nil {
		tctx.SNI = r.TLS.ServerName
	}

	var reqTraces, respTraces []transform.TransformTrace
	result := &transform.PipelineResult{
		Host:       r.Host,
		Method:     r.Method,
		Path:       r.URL.Path,
		RemoteAddr: r.RemoteAddr,
		SNI:        tctx.SNI,
		StartedAt:  startedAt,
	}
	defer func() {
		result.Duration = time.Since(startedAt)
		result.RequestTransforms = reqTraces
		result.ResponseTransforms = respTraces
		p.pipeline.EmitAudit(result)
	}()

	// Wrap request body for lazy buffering by transforms.
	r.Body = transform.NewBufferedBody(r.Body, bodyLimits.MaxRequestBodyBytes)

	// Run request transforms
	if rejectResp, err := p.pipeline.ProcessRequest(r.Context(), tctx, r, &reqTraces); err != nil {
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
	if n := reqBody.Len(); n >= 0 {
		upstreamReq.ContentLength = int64(n)
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
	finalResp, err := p.pipeline.ProcessResponse(r.Context(), tctx, r, resp, &respTraces)
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

	if upstreamScheme == "wss" {
		upstreamConn, err = tls.DialWithDialer(
			&net.Dialer{Timeout: 30 * time.Second},
			"tcp", upstreamHost,
			&tls.Config{MinVersion: tls.VersionTLS12},
		)
	} else {
		upstreamConn, err = net.DialTimeout("tcp", upstreamHost, 30*time.Second)
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
func buildTransport(resolver *net.Resolver) *http.Transport {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver:  resolver,
	}
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		DialContext:           dialer.DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:  10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
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
