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
	"syscall"
	"time"

	"github.com/ironsh/iron-proxy/internal/certcache"
	"github.com/ironsh/iron-proxy/internal/config"
	"github.com/ironsh/iron-proxy/internal/controlplane"
	idns "github.com/ironsh/iron-proxy/internal/dns"
	"github.com/ironsh/iron-proxy/internal/dnsguard"
	"github.com/ironsh/iron-proxy/internal/management"
	"github.com/ironsh/iron-proxy/internal/mcp"
	"github.com/ironsh/iron-proxy/internal/metrics"
	iotel "github.com/ironsh/iron-proxy/internal/otel"
	"github.com/ironsh/iron-proxy/internal/postgres"
	"github.com/ironsh/iron-proxy/internal/proxy"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/version"

	// Register built-in transforms.
	_ "github.com/ironsh/iron-proxy/internal/transform/allowlist"
	_ "github.com/ironsh/iron-proxy/internal/transform/annotate"
	_ "github.com/ironsh/iron-proxy/internal/transform/gcpauth"
	_ "github.com/ironsh/iron-proxy/internal/transform/grpc"
	_ "github.com/ironsh/iron-proxy/internal/transform/headerallowlist"
	_ "github.com/ironsh/iron-proxy/internal/transform/judge"
	_ "github.com/ironsh/iron-proxy/internal/transform/oauth"
	_ "github.com/ironsh/iron-proxy/internal/transform/secrets"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "generate-ca":
			runGenerateCA(os.Args[2:])
			return
		case "init":
			runInit(os.Args[2:])
			return
		case "version", "--version", "-v":
			fmt.Println(version.Version)
			return
		}
	}

	configPath := flag.String("config", "", "path to iron-proxy YAML config file")
	enrollmentTokenFlag := flag.String("enrollment-token", "", "enrollment token for control plane registration")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Load config: parse file (if provided) → env overrides → defaults.
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	logger, err := config.NewLogger(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// CLI flag takes precedence over environment variable.
	enrollmentToken := *enrollmentTokenFlag
	if enrollmentToken == "" {
		enrollmentToken = os.Getenv("IRON_ENROLLMENT_TOKEN")
	}

	// Managed mode is determined by the presence of an enrollment token or
	// an existing credential from a prior registration.
	stateStore, err := stateStorePath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	cred, credErr := controlplane.LoadCredential(stateStore)
	if credErr != nil && !errors.Is(credErr, os.ErrNotExist) {
		logger.Error("loading credential", slog.String("error", credErr.Error()))
		os.Exit(1)
	}
	managed := enrollmentToken != "" || cred != nil

	if cfg.Management.Listen != "" {
		if managed {
			fmt.Fprintln(os.Stderr, "error: management.listen cannot be used with managed mode; the control plane is the source of truth")
			os.Exit(1)
		}
		if *configPath == "" {
			fmt.Fprintln(os.Stderr, "error: management.listen requires --config; /v1/reload has no file to re-read")
			os.Exit(1)
		}
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
	errc := make(chan error, 5)
	var holder *transform.PipelineHolder
	var mcpHolder *mcp.PolicyHolder
	var otelCfg iotel.ExportConfig

	if managed {
		var ingestToken string
		holder, mcpHolder, ingestToken = initManaged(ctx, cfg, bodyLimits, errc, stateStore, enrollmentToken, cred, logger)
		if ingestToken != "" {
			otelCfg.DefaultEndpoint = "https://ingest.iron.sh/v1/logs"
			otelCfg.DefaultHeaders = map[string]string{
				"Authorization": "Bearer " + ingestToken,
			}
		}
	} else {
		holder, mcpHolder = initStandalone(cfg, bodyLimits, logger)
	}

	// 5. Validate the fully-assembled config.
	if err := config.Validate(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Set up audit function.
	auditFunc := transform.AuditFunc(transform.NewAuditLogger(logger))
	var otelShutdown func(context.Context) error
	if otelCfg.Enabled() {
		otelProvider, otelErr := iotel.NewLoggerProvider(ctx, otelCfg)
		if otelErr != nil {
			logger.Error("initializing OTEL log provider", slog.String("error", otelErr.Error()))
			os.Exit(1)
		}
		otelShutdown = otelProvider.Shutdown
		auditFunc = transform.ChainAuditFuncs(auditFunc, transform.NewOTELAuditFunc(otelProvider))
		logger.Info("OTEL audit export enabled")
	}
	holder.Load().SetAuditFunc(auditFunc)

	// Initialize cert cache. Not needed in sni-only mode since TLS is never
	// terminated and no leaf certs are generated.
	var certCache *certcache.Cache
	if cfg.TLS.Mode != config.TLSModeSNIOnly {
		leafExpiry := time.Duration(cfg.TLS.LeafCertExpiryHours) * time.Hour
		certCache, err = certcache.New(cfg.TLS.CACert, cfg.TLS.CAKey, cfg.TLS.CertCacheSize, leafExpiry)
		if err != nil {
			logger.Error("initializing cert cache", slog.String("error", err.Error()))
			os.Exit(1)
		}
	} else if cfg.TLS.CACert != "" || cfg.TLS.CAKey != "" {
		logger.Warn("tls.ca_cert and tls.ca_key are ignored when tls.mode=sni-only")
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

	// Build the upstream-dial deny guard. config.Validate has already
	// confirmed the entries parse, so this should not fail.
	guard, err := dnsguard.New(cfg.Proxy.UpstreamDenyCIDRs.Values)
	if err != nil {
		logger.Error("initializing upstream deny guard", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if len(cfg.Proxy.UpstreamDenyCIDRs.Values) > 0 {
		logger.Info("upstream deny list active",
			slog.Any("cidrs", cfg.Proxy.UpstreamDenyCIDRs.Values),
		)
	}

	pgPolicies, err := postgres.LoadFromNode(cfg.Postgres, logger)
	if err != nil {
		logger.Error("loading postgres config", slog.String("error", err.Error()))
		os.Exit(1)
	}
	pgManager := postgres.NewManager(logger)

	// Initialize proxy.
	p := proxy.New(proxy.Options{
		HTTPAddr:                      cfg.Proxy.HTTPListen,
		HTTPSAddr:                     cfg.Proxy.HTTPSListen,
		TunnelAddr:                    cfg.Proxy.TunnelListen,
		TLSMode:                       cfg.TLS.Mode,
		CertCache:                     certCache,
		Pipeline:                      holder,
		Resolver:                      resolver,
		Guard:                         guard,
		MCPPolicy:                     mcpHolder,
		Logger:                        logger,
		UpstreamResponseHeaderTimeout: time.Duration(cfg.Proxy.UpstreamResponseHeaderTimeout),
	})

	// Initialize metrics server.
	metricsServer := metrics.New(cfg.Metrics.Listen, logger)

	// Initialize management server (standalone mode only; guarded above).
	var mgmtServer *management.Server
	if cfg.Management.Listen != "" {
		mgmtServer = management.New(management.Options{
			Addr:   cfg.Management.Listen,
			APIKey: os.Getenv(cfg.Management.APIKeyEnv),
			Reload: newReloadFunc(*configPath, holder, mcpHolder, pgManager, bodyLimits, logger),
			Logger: logger,
			Ctx:    ctx,
		})
	}

	// Start services.
	go func() { errc <- fmt.Errorf("dns: %w", dnsServer.ListenAndServe()) }()
	go func() { errc <- fmt.Errorf("proxy: %w", p.ListenAndServe()) }()
	go func() { errc <- fmt.Errorf("metrics: %w", metricsServer.ListenAndServe()) }()
	if mgmtServer != nil {
		go func() { errc <- fmt.Errorf("management: %w", mgmtServer.ListenAndServe()) }()
	}
	pgManager.Start(pgPolicies, errc)

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
	if mgmtServer != nil {
		if err := mgmtServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("management server shutdown error", slog.String("error", err.Error()))
		}
	}
	if err := pgManager.Shutdown(shutdownCtx); err != nil {
		logger.Error("postgres server shutdown error", slog.String("error", err.Error()))
	}

	logger.Info("iron-proxy stopped")
}

// initManaged registers with the control plane, performs an initial sync, builds
// the initial pipeline and MCP policy, and starts the config poller. The poller
// runs until ctx is canceled and sends fatal errors on errc. Returns the
// pipeline holder, the MCP policy holder, and the ingest token from the initial
// sync (empty if the sync failed).
//
// Initial MCP policy preference: control-plane-supplied mcp block first, then
// fall back to cfg.MCP from the YAML if the sync did not include one.
func initManaged(ctx context.Context, cfg *config.Config, bodyLimits transform.BodyLimits, errc chan<- error, stateStore, enrollmentToken string, cred *controlplane.Credential, logger *slog.Logger) (*transform.PipelineHolder, *mcp.PolicyHolder, string) {
	cpURL := envOrDefault("IRON_CONTROL_PLANE_URL", "https://api.iron.sh")
	logger.Info("starting in managed mode", slog.String("control_plane_url", cpURL))

	client := controlplane.NewClient(cpURL, logger)

	// Register if we don't have a credential yet.
	if cred == nil {
		logger.Info("registering with control plane")
		var regErr error
		cred, regErr = client.Register(ctx, enrollmentToken, controlplane.RegisterMetadata{
			Version: version.Version,
		})
		if regErr != nil {
			logger.Error("registration failed", slog.String("error", regErr.Error()))
			os.Exit(1)
		}
		logger.Info("registered successfully", slog.String("proxy_id", cred.ProxyID))

		if err := ensureStateStoreDir(stateStore); err != nil {
			logger.Error("creating state store directory", slog.String("error", err.Error()))
			os.Exit(1)
		}
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
	ingestToken := ""
	var initialRules, initialSecrets, initialMCP json.RawMessage
	if syncResp != nil {
		configHash = syncResp.ConfigHash
		initialRules = syncResp.Rules
		initialSecrets = syncResp.Secrets
		initialMCP = syncResp.MCP
		ingestToken = syncResp.IngestToken
		if len(syncResp.Rules) > 0 || len(syncResp.Secrets) > 0 || len(syncResp.MCP) > 0 {
			logger.Info("received initial config from control plane",
				slog.String("config_hash", syncResp.ConfigHash),
			)
		}
	}

	// Build initial pipeline from sync response.
	initialTransforms, err := config.TransformsFromSync(initialRules, initialSecrets)
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

	// Build initial MCP policy: prefer the control-plane-supplied block; fall
	// back to cfg.MCP from the YAML so an operator can ship a default that
	// applies until the first sync arrives.
	mcpHolder, err := buildInitialMCPHolder(cfg, initialMCP, logger)
	if err != nil {
		logger.Error("building initial mcp policy", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Start config poller.
	poller := controlplane.NewPoller(client, configHash, func(u controlplane.SyncUpdate) error {
		if u.Rules != nil || u.Secrets != nil {
			applyPipelineSync(holder, bodyLimits, logger, u.Rules, u.Secrets)
		}
		if u.MCP != nil {
			applyMCPSync(mcpHolder, logger, u.MCP)
		}
		return nil
	}, logger)

	go func() {
		errc <- poller.Run(ctx)
	}()

	return holder, mcpHolder, ingestToken
}

// buildInitialMCPHolder picks the initial MCP policy source: a control-plane
// MCP block when present, otherwise the YAML cfg.MCP fallback. A nil holder
// means "no policy configured"; the proxy treats it as MCP disabled.
func buildInitialMCPHolder(cfg *config.Config, initialMCP json.RawMessage, logger *slog.Logger) (*mcp.PolicyHolder, error) {
	node, present, err := config.MCPFromSync(initialMCP)
	if err != nil {
		return nil, err
	}
	if !present {
		node = cfg.MCP
	}
	policy, err := mcp.LoadFromNode(node)
	if err != nil {
		return nil, err
	}
	if policy != nil {
		logger.Info("mcp policy enabled")
	}
	return mcp.NewPolicyHolder(policy), nil
}

// initStandalone builds the pipeline and MCP policy from the YAML config.
func initStandalone(cfg *config.Config, bodyLimits transform.BodyLimits, logger *slog.Logger) (*transform.PipelineHolder, *mcp.PolicyHolder) {
	pipeline, err := buildPipeline(cfg.Transforms, bodyLimits, logger)
	if err != nil {
		logger.Error("building transform pipeline", slog.String("error", err.Error()))
		os.Exit(1)
	}
	mcpPolicy, err := mcp.LoadFromNode(cfg.MCP)
	if err != nil {
		logger.Error("loading mcp policy", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if mcpPolicy != nil {
		logger.Info("mcp policy enabled")
	}
	return transform.NewPipelineHolder(pipeline), mcp.NewPolicyHolder(mcpPolicy)
}

// stateStorePath returns the state store path without creating any directories.
// It honors IRON_STATE_STORE and falls back to the XDG config directory.
func stateStorePath() (string, error) {
	if v := os.Getenv("IRON_STATE_STORE"); v != "" {
		return v, nil
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("determining config directory: %w", err)
	}
	return filepath.Join(configDir, "iron-proxy", "state"), nil
}

// ensureStateStoreDir creates the parent directory for the state store path.
func ensureStateStoreDir(stateStore string) error {
	if err := os.MkdirAll(filepath.Dir(stateStore), 0o700); err != nil {
		return fmt.Errorf("creating state store directory: %w", err)
	}
	return nil
}

// applyPipelineSync builds a new pipeline from a sync payload and atomically
// swaps it in. If parsing or pipeline construction fails, the existing pipeline
// is preserved and an error is logged: an invalid push from the control plane
// must not take down the proxy.
func applyPipelineSync(holder *transform.PipelineHolder, bodyLimits transform.BodyLimits, logger *slog.Logger, rules, secrets json.RawMessage) {
	newTransforms, err := config.TransformsFromSync(rules, secrets)
	if err != nil {
		logger.Error("rejecting invalid pipeline config from sync, keeping current pipeline", slog.String("error", err.Error()))
		return
	}
	newPipeline, err := buildPipeline(newTransforms, bodyLimits, logger)
	if err != nil {
		logger.Error("rejecting invalid pipeline config from sync, keeping current pipeline", slog.String("error", err.Error()))
		return
	}
	newPipeline.SetAuditFunc(holder.Load().AuditFunc())
	holder.Store(newPipeline)
	logger.Info("pipeline reloaded", slog.String("transforms", newPipeline.Names()))
}

// applyMCPSync compiles a new MCP policy from a sync payload and atomically
// swaps it in. Parse or compile errors are logged and the prior policy is
// preserved: an invalid push from the control plane must not take down a
// running proxy. An empty/null mcp block is interpreted by the caller as
// "no update" and is not delivered here.
func applyMCPSync(holder *mcp.PolicyHolder, logger *slog.Logger, raw json.RawMessage) {
	node, present, err := config.MCPFromSync(raw)
	if err != nil {
		logger.Error("rejecting invalid mcp policy from sync, keeping current policy", slog.String("error", err.Error()))
		return
	}
	if !present {
		// Should not happen — caller filters absent/null — but treat as no-op.
		return
	}
	policy, err := mcp.LoadFromNode(node)
	if err != nil {
		logger.Error("rejecting invalid mcp policy from sync, keeping current policy", slog.String("error", err.Error()))
		return
	}
	holder.Store(policy)
	if policy == nil {
		logger.Info("mcp policy cleared by control plane")
	} else {
		logger.Info("mcp policy reloaded")
	}
}

// newReloadFunc returns a management.ReloadFunc that re-reads the YAML config
// from configPath, rebuilds the pipeline, MCP policy, and postgres listeners,
// and atomically swaps them in. Parse, validation, and build errors are
// wrapped in *management.ValidationError so the management server returns
// 422 and the existing state is left untouched. Validation runs for every
// component before any state is mutated.
func newReloadFunc(configPath string, holder *transform.PipelineHolder, mcpHolder *mcp.PolicyHolder, pgManager *postgres.Manager, bodyLimits transform.BodyLimits, logger *slog.Logger) management.ReloadFunc {
	return func(ctx context.Context) error {
		newCfg, err := config.LoadConfig(configPath)
		if err != nil {
			return &management.ValidationError{Err: err}
		}
		if err := config.Validate(newCfg); err != nil {
			return &management.ValidationError{Err: err}
		}
		newPipeline, err := buildPipeline(newCfg.Transforms, bodyLimits, logger)
		if err != nil {
			return &management.ValidationError{Err: err}
		}
		newPolicy, err := mcp.LoadFromNode(newCfg.MCP)
		if err != nil {
			return &management.ValidationError{Err: err}
		}
		newPgPolicies, err := postgres.LoadFromNode(newCfg.Postgres, logger)
		if err != nil {
			return &management.ValidationError{Err: err}
		}
		newPipeline.SetAuditFunc(holder.Load().AuditFunc())
		holder.Store(newPipeline)
		mcpHolder.Store(newPolicy)
		pgManager.Reload(ctx, newPgPolicies)
		logger.Info("pipeline reloaded via management API",
			slog.String("transforms", newPipeline.Names()),
			slog.Int("postgres_servers", len(newPgPolicies)),
		)
		return nil
	}
}

// buildPipeline creates a transform.Pipeline from config transforms.
func buildPipeline(transforms []config.Transform, bodyLimits transform.BodyLimits, logger *slog.Logger) (*transform.Pipeline, error) {
	var transformers []transform.Transformer
	for _, tc := range transforms {
		factory, err := transform.Lookup(tc.Name)
		if err != nil {
			return nil, fmt.Errorf("unknown transform %q: %w", tc.Name, err)
		}
		t, err := factory(tc.Config, logger)
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
