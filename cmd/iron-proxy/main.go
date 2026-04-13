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
	"path/filepath"
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

	configPath := flag.String("config", "", "path to iron-proxy YAML config file")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Mode is determined exclusively by how config is provided:
	//   -config flag  → standalone (YAML file)
	//   no flag       → managed (env vars + control plane)
	managed := *configPath == ""

	var cfg *config.Config
	var err error
	if managed {
		cfg, err = config.FromEnv()
	} else {
		cfg, err = config.LoadFile(*configPath)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	stateStore, err := resolveStateStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	logger, err := config.NewLogger(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Both modes produce a pipeline holder. Managed mode populates the
	// initial transforms from the control plane and starts a poller that
	// hot-reloads the pipeline.
	bodyLimits := transform.BodyLimits{
		MaxRequestBodyBytes:  cfg.Proxy.MaxRequestBodyBytes,
		MaxResponseBodyBytes: cfg.Proxy.MaxResponseBodyBytes,
	}

	// errc collects fatal errors from all background goroutines: servers
	// and (in managed mode) the config poller.
	errc := make(chan error, 4)
	var holder *transform.PipelineHolder

	if managed {
		holder = initManaged(ctx, cfg, bodyLimits, errc, stateStore, logger)
	} else {
		holder = initStandalone(cfg, bodyLimits, logger)
	}

	// Set up audit function.
	auditFunc := transform.AuditFunc(transform.NewAuditLogger(logger))
	var otelShutdown func(context.Context) error
	if iotel.Enabled() {
		otelProvider, otelErr := iotel.NewLoggerProvider(ctx)
		if otelErr != nil {
			logger.Error("initializing OTEL log provider", slog.String("error", otelErr.Error()))
			os.Exit(1)
		}
		otelShutdown = otelProvider.Shutdown
		auditFunc = transform.ChainAuditFuncs(auditFunc, transform.NewOTELAuditFunc(otelProvider))
		logger.Info("OTEL audit export enabled")
	}
	holder.Load().SetAuditFunc(auditFunc)

	// Initialize cert cache.
	leafExpiry := time.Duration(cfg.TLS.LeafCertExpiryHours) * time.Hour
	certCache, err := certcache.New(cfg.TLS.CACert, cfg.TLS.CAKey, cfg.TLS.CertCacheSize, leafExpiry)
	if err != nil {
		logger.Error("initializing cert cache", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Build upstream resolver.
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

	// Initialize DNS server.
	dnsServer, err := idns.New(cfg.DNS, resolver, logger)
	if err != nil {
		logger.Error("initializing DNS server", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Initialize proxy.
	p := proxy.New(cfg.Proxy.HTTPListen, cfg.Proxy.HTTPSListen, cfg.Proxy.TunnelListen, certCache, holder, resolver, logger)

	// Initialize metrics server.
	metricsServer := metrics.New(cfg.Metrics.Listen, logger)

	// Start services.
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
	if pipeline := holder.Load(); !pipeline.Empty() {
		logger.Info("transform pipeline", slog.String("transforms", pipeline.Names()))
	}

	// Wait for shutdown signal or fatal error from any background goroutine.
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigc:
		logger.Info("received signal, shutting down", slog.String("signal", sig.String()))
	case err := <-errc:
		logger.Error("fatal error", slog.String("error", err.Error()))
	}

	// Cancel context to stop the poller, then shut down services.
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if otelShutdown != nil {
		if err := otelShutdown(shutdownCtx); err != nil {
			logger.Error("shutting down OTEL log provider", slog.String("error", err.Error()))
		}
	}
	if err := dnsServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("dns shutdown error", slog.String("error", err.Error()))
	}
	if err := p.Shutdown(shutdownCtx); err != nil {
		logger.Error("proxy shutdown error", slog.String("error", err.Error()))
	}
	if err := metricsServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("metrics server shutdown error", slog.String("error", err.Error()))
	}

	logger.Info("iron-proxy stopped")
}

// initManaged registers with the control plane, performs an initial sync, builds
// the initial pipeline, and starts the config poller. The poller runs until ctx
// is canceled and sends fatal errors on errc.
func initManaged(ctx context.Context, cfg *config.Config, bodyLimits transform.BodyLimits, errc chan<- error, stateStore string, logger *slog.Logger) *transform.PipelineHolder {
	bootstrapToken := os.Getenv("IRON_BOOTSTRAP_TOKEN")

	cred, err := controlplane.LoadCredential(stateStore)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		logger.Error("loading credential", slog.String("error", err.Error()))
		os.Exit(1)
	}

	cpURL := envOrDefault("IRON_CONTROL_PLANE_URL", "https://api.iron.sh")
	tags := parseTags(os.Getenv("IRON_TAGS"))
	logger.Info("starting in managed mode", slog.String("control_plane_url", cpURL))

	client := controlplane.NewClient(cpURL, logger)

	// Register if we don't have a credential yet.
	if cred == nil {
		logger.Info("registering with control plane")
		var regErr error
		cred, regErr = client.Register(ctx, bootstrapToken, controlplane.RegisterMetadata{
			Tags:    tags,
			Version: version,
		})
		if regErr != nil {
			logger.Error("registration failed", slog.String("error", regErr.Error()))
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
	syncResp, err := client.Sync(ctx, "")
	if err != nil {
		var apiErr *controlplane.APIError
		if errors.As(err, &apiErr) && apiErr.Code == controlplane.ErrProxyRevoked {
			logger.Error("proxy has been revoked, deleting credential and exiting")
			_ = controlplane.DeleteCredential(stateStore)
			os.Exit(1)
		}
		logger.Warn("initial sync failed, will retry in background", slog.String("error", err.Error()))
	}

	configHash := ""
	var initialRules json.RawMessage
	if syncResp != nil {
		configHash = syncResp.ConfigHash
		initialRules = syncResp.Rules
		if len(syncResp.Rules) > 0 {
			logger.Info("received initial config from control plane",
				slog.String("config_hash", syncResp.ConfigHash),
			)
		}
	}

	// Build initial pipeline from sync response.
	initialTransforms, err := config.TransformsFromSync(initialRules)
	if err != nil {
		logger.Error("parsing initial config", slog.String("error", err.Error()))
		os.Exit(1)
	}

	pipeline, err := buildPipeline(initialTransforms, bodyLimits, logger)
	if err != nil {
		logger.Error("building initial pipeline", slog.String("error", err.Error()))
		os.Exit(1)
	}
	holder := transform.NewPipelineHolder(pipeline)

	// Start config poller.
	poller := controlplane.NewPoller(client, configHash, func(rules json.RawMessage, secrets json.RawMessage) error {
		newTransforms, err := config.TransformsFromSync(rules)
		if err != nil {
			return fmt.Errorf("parsing config update: %w", err)
		}
		newPipeline, err := buildPipeline(newTransforms, bodyLimits, logger)
		if err != nil {
			return fmt.Errorf("building updated pipeline: %w", err)
		}
		newPipeline.SetAuditFunc(holder.Load().AuditFunc())
		holder.Store(newPipeline)
		logger.Info("pipeline reloaded", slog.String("transforms", newPipeline.Names()))
		return nil
	}, logger)

	go func() {
		errc <- poller.Run(ctx)
	}()

	return holder
}

// initStandalone builds the pipeline from the YAML config's transforms.
func initStandalone(cfg *config.Config, bodyLimits transform.BodyLimits, logger *slog.Logger) *transform.PipelineHolder {
	pipeline, err := buildPipeline(cfg.Transforms, bodyLimits, logger)
	if err != nil {
		logger.Error("building transform pipeline", slog.String("error", err.Error()))
		os.Exit(1)
	}
	return transform.NewPipelineHolder(pipeline)
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

// resolveStateStore returns the state store path, creating its parent directory
// if needed. It honors IRON_STATE_STORE and falls back to the XDG config directory.
func resolveStateStore() (string, error) {
	stateStore := os.Getenv("IRON_STATE_STORE")
	if stateStore == "" {
		configDir, err := os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("determining config directory: %w", err)
		}
		stateStore = filepath.Join(configDir, "iron-proxy", "state")
	}

	if err := os.MkdirAll(filepath.Dir(stateStore), 0o700); err != nil {
		return "", fmt.Errorf("creating state store directory: %w", err)
	}

	return stateStore, nil
}

// buildPipeline creates a transform.Pipeline from config transforms.
func buildPipeline(transforms []config.Transform, bodyLimits transform.BodyLimits, logger *slog.Logger) (*transform.Pipeline, error) {
	var transformers []transform.Transformer
	for _, tc := range transforms {
		factory, err := transform.Lookup(tc.Name)
		if err != nil {
			return nil, fmt.Errorf("unknown transform %q: %w", tc.Name, err)
		}
		t, err := factory(tc.Config)
		if err != nil {
			return nil, fmt.Errorf("initializing transform %q: %w", tc.Name, err)
		}
		transformers = append(transformers, t)
	}
	return transform.NewPipeline(transformers, bodyLimits, logger), nil
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
