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
	"github.com/ironsh/iron-proxy/internal/proxy"
	"github.com/ironsh/iron-proxy/internal/transform"

	// Register built-in transforms.
	_ "github.com/ironsh/iron-proxy/internal/transform/allowlist"
	_ "github.com/ironsh/iron-proxy/internal/transform/grpc"
	_ "github.com/ironsh/iron-proxy/internal/transform/secrets"
)

func main() {
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
	pipeline.SetAuditFunc(transform.NewAuditLogger(logger))

	// Build upstream resolver
	var resolver *net.Resolver
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
	dnsResolver := net.DefaultResolver
	if resolver != nil {
		dnsResolver = resolver
	}
	dnsServer, err := idns.New(cfg.DNS, dnsResolver, logger)
	if err != nil {
		logger.Error("initializing DNS server", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Initialize proxy
	p := proxy.New(cfg.Proxy.HTTPListen, cfg.Proxy.HTTPSListen, certCache, pipeline, resolver, logger)

	// Start services
	errc := make(chan error, 2)

	go func() { errc <- fmt.Errorf("dns: %w", dnsServer.ListenAndServe()) }()
	go func() { errc <- fmt.Errorf("proxy: %w", p.ListenAndServe()) }()

	logger.Info("iron-proxy starting",
		slog.String("dns_listen", cfg.DNS.Listen),
		slog.String("http_listen", cfg.Proxy.HTTPListen),
		slog.String("https_listen", cfg.Proxy.HTTPSListen),
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

	logger.Info("iron-proxy stopped")
}
