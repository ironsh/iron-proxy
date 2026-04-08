// Command iron-proxy runs the MITM HTTP/HTTPS proxy with built-in DNS server.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ironsh/iron-proxy/internal/certcache"
	"github.com/ironsh/iron-proxy/internal/config"
	idns "github.com/ironsh/iron-proxy/internal/dns"
	"github.com/ironsh/iron-proxy/internal/metrics"
	iotel "github.com/ironsh/iron-proxy/internal/otel"
	"github.com/ironsh/iron-proxy/internal/proxy"
	"github.com/ironsh/iron-proxy/internal/transform"

	// Register built-in transforms.
	_ "github.com/ironsh/iron-proxy/internal/transform/allowlist"
	_ "github.com/ironsh/iron-proxy/internal/transform/annotate"
	_ "github.com/ironsh/iron-proxy/internal/transform/grpc"
	_ "github.com/ironsh/iron-proxy/internal/transform/secrets"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "generate-ca":
			runGenerateCA(os.Args[2:])
			return
		}
	}

	configPath := flag.String("config", "", "path to iron-proxy YAML config file")
	flag.Parse()

	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "error: -config flag is required")
		flag.Usage()
		os.Exit(1)
	}

	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	logger, err := config.NewLogger(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Initialize cert cache
	leafExpiry := time.Duration(cfg.TLS.LeafCertExpiryHours) * time.Hour
	certCache, err := certcache.New(cfg.TLS.CACert, cfg.TLS.CAKey, cfg.TLS.CertCacheSize, leafExpiry)
	if err != nil {
		logger.Error("initializing cert cache", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Build transform pipeline
	var transformers []transform.Transformer
	for _, tc := range cfg.Transforms {
		factory, err := transform.Lookup(tc.Name)
		if err != nil {
			logger.Error("unknown transform", slog.String("name", tc.Name))
			os.Exit(1)
		}
		t, err := factory(tc.Config)
		if err != nil {
			logger.Error("initializing transform",
				slog.String("name", tc.Name),
				slog.String("error", err.Error()),
			)
			os.Exit(1)
		}
		transformers = append(transformers, t)
	}
	pipeline := transform.NewPipeline(transformers, transform.BodyLimits{
		MaxRequestBodyBytes:  cfg.Proxy.MaxRequestBodyBytes,
		MaxResponseBodyBytes: cfg.Proxy.MaxResponseBodyBytes,
	}, logger)
	auditFunc := transform.AuditFunc(transform.NewAuditLogger(logger))
	if iotel.Enabled() {
		otelProvider, err := iotel.NewLoggerProvider(context.Background())
		if err != nil {
			logger.Error("initializing OTEL log provider", slog.String("error", err.Error()))
			os.Exit(1)
		}
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := otelProvider.Shutdown(ctx); err != nil {
				logger.Error("shutting down OTEL log provider", slog.String("error", err.Error()))
			}
		}()
		auditFunc = transform.ChainAuditFuncs(auditFunc, transform.NewOTELAuditFunc(otelProvider))
		logger.Info("OTEL audit export enabled")
	}
	pipeline.SetAuditFunc(auditFunc)

	// Build upstream resolver
	resolver := net.DefaultResolver
	if cfg.DNS.UpstreamResolver != "" {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, "udp", cfg.DNS.UpstreamResolver)
			},
		}
		logger.Info("using upstream resolver", slog.String("addr", cfg.DNS.UpstreamResolver))
	}

	// Initialize DNS server
	dnsServer, err := idns.New(cfg.DNS, resolver, logger)
	if err != nil {
		logger.Error("initializing DNS server", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Initialize proxy
	p := proxy.New(cfg.Proxy.HTTPListen, cfg.Proxy.HTTPSListen, certCache, pipeline, resolver, logger)

	// Initialize metrics server
	metricsServer := metrics.New(cfg.Metrics.Listen, logger)

	// Start services
	errc := make(chan error, 3)

	go func() { errc <- fmt.Errorf("dns: %w", dnsServer.ListenAndServe()) }()
	go func() { errc <- fmt.Errorf("proxy: %w", p.ListenAndServe()) }()
	go func() { errc <- fmt.Errorf("metrics: %w", metricsServer.ListenAndServe()) }()

	logger.Info("iron-proxy starting",
		slog.String("dns_listen", cfg.DNS.Listen),
		slog.String("http_listen", cfg.Proxy.HTTPListen),
		slog.String("https_listen", cfg.Proxy.HTTPSListen),
		slog.String("metrics_listen", cfg.Metrics.Listen),
	)
	if !pipeline.Empty() {
		logger.Info("transform pipeline", slog.String("transforms", pipeline.Names()))
	}

	// Wait for shutdown signal or fatal error
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigc:
		logger.Info("received signal, shutting down", slog.String("signal", sig.String()))
	case err := <-errc:
		logger.Error("service error", slog.String("error", err.Error()))
	}

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := dnsServer.Shutdown(ctx); err != nil {
		logger.Error("dns shutdown error", slog.String("error", err.Error()))
	}
	if err := p.Shutdown(ctx); err != nil {
		logger.Error("proxy shutdown error", slog.String("error", err.Error()))
	}
	if err := metricsServer.Shutdown(ctx); err != nil {
		logger.Error("metrics server shutdown error", slog.String("error", err.Error()))
	}

	logger.Info("iron-proxy stopped")
}
