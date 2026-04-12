// Command iron-proxy runs the MITM HTTP/HTTPS proxy with built-in DNS server.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ironsh/iron-proxy/internal/certcache"
	"github.com/ironsh/iron-proxy/internal/config"
	"github.com/ironsh/iron-proxy/internal/controlplane"
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

// version is set at build time via -ldflags.
var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "generate-ca":
			runGenerateCA(os.Args[2:])
			return
		}
	}

	stateStore := envOrDefault("IRON_STATE_STORE", "/etc/iron-proxy/state")
	bootstrapToken := os.Getenv("IRON_BOOTSTRAP_TOKEN")

	cred, _ := controlplane.LoadCredential(stateStore)
	managed := cred != nil || bootstrapToken != ""

	if managed {
		runManaged(stateStore, bootstrapToken, cred)
	} else {
		runStandalone()
	}
}

func runManaged(stateStore, bootstrapToken string, cred *controlplane.Credential) {
	cpURL := envOrDefault("IRON_CONTROL_PLANE_URL", "https://api.iron.sh")
	tags := parseTags(os.Getenv("IRON_TAGS"))

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	logger.Info("starting in managed mode", slog.String("control_plane_url", cpURL))

	client := controlplane.NewClient(cpURL, logger)

	// Register if we don't have a credential yet.
	if cred == nil {
		logger.Info("registering with control plane")
		var err error
		err = controlplane.Retry(context.Background(), controlplane.DefaultRegisterRetry, func() error {
			cred, err = client.Register(context.Background(), bootstrapToken, controlplane.RegisterMetadata{
				Tags:    tags,
				Version: version,
			})
			return err
		})
		if err != nil {
			logger.Error("registration failed", slog.String("error", err.Error()))
			os.Exit(1)
		}
		logger.Info("registered successfully", slog.String("proxy_id", cred.ProxyID))

		if err := controlplane.SaveCredential(stateStore, cred); err != nil {
			logger.Error("saving credential", slog.String("error", err.Error()))
			os.Exit(1)
		}
	} else {
		logger.Info("loaded existing credential", slog.String("proxy_id", cred.ProxyID))
	}

	client.SetCredential(cred)

	// Initial sync.
	syncResp, err := client.Sync(context.Background(), "")
	if err != nil {
		var apiErr *controlplane.APIError
		if errors.As(err, &apiErr) && apiErr.Code == controlplane.ErrProxyRevoked {
			logger.Error("proxy has been revoked, deleting credential and exiting")
			controlplane.DeleteCredential(stateStore)
			os.Exit(1)
		}
		logger.Warn("initial sync failed, will retry in background", slog.String("error", err.Error()))
	}

	configHash := ""
	if syncResp != nil {
		configHash = syncResp.ConfigHash
		if syncResp.Rules != nil || syncResp.Secrets != nil {
			logger.Info("received initial config from control plane",
				slog.String("config_hash", syncResp.ConfigHash),
				slog.Bool("has_rules", syncResp.Rules != nil),
				slog.Bool("has_secrets", syncResp.Secrets != nil),
			)
		}
	}

	// Start poller in background.
	pollerCtx, pollerCancel := context.WithCancel(context.Background())
	defer pollerCancel()

	poller := controlplane.NewPoller(client, configHash, func(rules json.RawMessage, secrets json.RawMessage) error {
		logger.Info("config update callback invoked (wiring not yet implemented)")
		return nil
	}, logger)

	pollerErrC := make(chan error, 1)
	go func() {
		pollerErrC <- poller.Run(pollerCtx)
	}()

	// Wait for shutdown signal or poller fatal error.
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigc:
		logger.Info("received signal, shutting down", slog.String("signal", sig.String()))
	case err := <-pollerErrC:
		if err != nil {
			logger.Error("poller stopped with error", slog.String("error", err.Error()))
		}
	}

	pollerCancel()
	logger.Info("iron-proxy stopped")
}

func runStandalone() {
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
	p := proxy.New(cfg.Proxy.HTTPListen, cfg.Proxy.HTTPSListen, cfg.Proxy.TunnelListen, certCache, pipeline, resolver, logger)

	// Initialize metrics server
	metricsServer := metrics.New(cfg.Metrics.Listen, logger)

	// Start services
	errc := make(chan error, 3)

	go func() { errc <- fmt.Errorf("dns: %w", dnsServer.ListenAndServe()) }()
	go func() { errc <- fmt.Errorf("proxy: %w", p.ListenAndServe()) }()
	go func() { errc <- fmt.Errorf("metrics: %w", metricsServer.ListenAndServe()) }()

	startAttrs := []any{
		slog.String("dns_listen", cfg.DNS.Listen),
		slog.String("http_listen", cfg.Proxy.HTTPListen),
		slog.String("https_listen", cfg.Proxy.HTTPSListen),
		slog.String("metrics_listen", cfg.Metrics.Listen),
	}
	if cfg.Proxy.TunnelListen != "" {
		startAttrs = append(startAttrs, slog.String("tunnel_listen", cfg.Proxy.TunnelListen))
	}
	logger.Info("iron-proxy starting", startAttrs...)
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

func parseTags(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	tags := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			tags = append(tags, p)
		}
	}
	return tags
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
