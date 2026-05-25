// Package broker implements iron-token-broker: a coordinator process that
// owns the OAuth refresh-token state machine for one or more credentials.
// iron-proxy instances fetch current access tokens from the broker over
// HTTP so the refresh family is never touched concurrently by multiple
// proxies. See cmd/iron-token-broker for the binary entry point.
//
// SECURITY: the broker handles refresh tokens and access tokens on every
// hot path. Logging is restricted to credential IDs, OAuth error codes,
// and timestamps — never the tokens themselves or the raw token-endpoint
// response bodies.
package broker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/ironsh/iron-proxy/internal/broker/config"
)

// Broker is the top-level orchestrator. It owns the per-credential state
// machines, the HTTP API server, and the metrics endpoint.
type Broker struct {
	log     *slog.Logger
	met     *metrics
	api     *httpServer
	metrics *metricsServer
	creds   map[string]*credentialState

	wg sync.WaitGroup
}

// Options configures a Broker.
type Options struct {
	Config      *config.Config
	Credentials []config.BuiltCredential
	Logger      *slog.Logger
	BearerToken string // captured value of cfg.BearerAuthEnv; empty disables auth
	HTTPClient  *http.Client // shared across credentials; nil = default
}

// New wires a Broker but does not start any goroutines or open any
// listeners. Call Start to begin the per-credential loops, then
// ListenAndServe (or the binary's main goroutine) to serve HTTP.
func New(opts Options) (*Broker, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	met := newMetrics()
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = newSharedHTTPClient(time.Duration(opts.Config.Defaults.RefreshTimeout))
	}

	creds := make(map[string]*credentialState, len(opts.Credentials))
	for _, c := range opts.Credentials {
		creds[c.ID] = newCredentialState(c, opts.Logger, met, httpClient)
	}

	api := newHTTPServer(httpOptions{
		Addr:          opts.Config.Listen,
		Credentials:   creds,
		BearerAuthEnv: opts.Config.BearerAuthEnv,
		BearerToken:   opts.BearerToken,
		Logger:        opts.Logger,
		Metrics:       met,
	})

	metricsSrv := newMetricsServer(opts.Config.MetricsListen, met.Handler(), opts.Logger)

	return &Broker{
		log:     opts.Logger,
		met:     met,
		api:     api,
		metrics: metricsSrv,
		creds:   creds,
	}, nil
}

// Start launches one goroutine per credential. Returns immediately; the
// goroutines run until ctx is cancelled. Wait blocks until they exit.
func (b *Broker) Start(ctx context.Context) {
	for id, c := range b.creds {
		b.wg.Add(1)
		go func(id string, c *credentialState) {
			defer b.wg.Done()
			c.Run(ctx)
		}(id, c)
	}
}

// Wait blocks until every credential goroutine has exited. Use after
// cancelling the Start context to drain.
func (b *Broker) Wait() {
	b.wg.Wait()
}

// ListenAndServe starts the HTTP API server. Blocks until Shutdown is
// called or the server errors. Errors after ListenAndServe returns are
// non-nil only on a true failure (http.ErrServerClosed is filtered).
func (b *Broker) ListenAndServe() error {
	b.log.Info("broker HTTP API starting",
		slog.String("addr", b.api.Addr()),
		slog.Int("credentials", len(b.creds)),
	)
	if err := b.api.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("broker http: %w", err)
	}
	return nil
}

// ListenAndServeMetrics starts the metrics HTTP server. Same semantics
// as ListenAndServe for the API.
func (b *Broker) ListenAndServeMetrics() error {
	b.log.Info("metrics server starting", slog.String("addr", b.metrics.Addr()))
	if err := b.metrics.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("broker metrics: %w", err)
	}
	return nil
}

// Shutdown gracefully stops the HTTP servers. Cancellation of the Start
// context is the caller's responsibility — Shutdown doesn't touch the
// per-credential goroutines.
func (b *Broker) Shutdown(ctx context.Context) error {
	apiErr := b.api.Shutdown(ctx)
	metricsErr := b.metrics.Shutdown(ctx)
	if apiErr != nil {
		return apiErr
	}
	return metricsErr
}

// newSharedHTTPClient returns the *http.Client used by every credential's
// refresh loop. A single client lets every refresh share the TLS session
// cache and connection pool against the IdP, which matters for IdPs that
// throttle TLS handshakes.
func newSharedHTTPClient(refreshTimeout time.Duration) *http.Client {
	transport := &http.Transport{
		MaxIdleConns:          50,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		// Don't follow redirects automatically — the token endpoint
		// is a single canonical URL, and a redirect there is a sign
		// of misconfiguration.
		Proxy: http.ProxyFromEnvironment,
	}
	if refreshTimeout > 0 && refreshTimeout < 30*time.Second {
		transport.ResponseHeaderTimeout = refreshTimeout
	}
	return &http.Client{
		Transport:     transport,
		Timeout:       refreshTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// metricsServer is a tiny HTTP server that exposes the Prometheus /metrics
// scrape endpoint and /healthz. Lives in its own struct because the API
// server has additional concerns (path patterns, bearer auth) and merging
// them in a single mux would muddy both.
type metricsServer struct {
	server *http.Server
	addr   string
	log    *slog.Logger
}

func newMetricsServer(addr string, metricsHandler http.Handler, log *slog.Logger) *metricsServer {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", metricsHandler)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	return &metricsServer{
		addr: addr,
		log:  log,
		server: &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		},
	}
}

func (s *metricsServer) Addr() string { return s.addr }

func (s *metricsServer) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.addr = ln.Addr().String()
	return s.server.Serve(ln)
}

func (s *metricsServer) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}
