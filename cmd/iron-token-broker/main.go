// Command iron-token-broker runs the OAuth refresh coordinator. It owns the
// refresh-token state machine for one or more credentials and serves
// current access tokens to iron-proxy instances over HTTP. See the
// README.iron-token-broker.md and internal/broker package docs for the
// architecture and bootstrap procedure.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ironsh/iron-proxy/internal/broker"
	"github.com/ironsh/iron-proxy/internal/broker/config"
	"github.com/ironsh/iron-proxy/internal/version"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-v":
			fmt.Println(version.Version)
			return
		}
	}

	configPath := flag.String("config", "", "path to iron-token-broker YAML config (required)")
	flag.Parse()

	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "error: --config is required")
		os.Exit(2)
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	logger, err := newLogger(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	bearerToken := ""
	if cfg.BearerAuthEnv != "" {
		bearerToken = os.Getenv(cfg.BearerAuthEnv)
		if bearerToken == "" {
			logger.Error("bearer_auth_env is set but the env var is empty",
				slog.String("env", cfg.BearerAuthEnv),
			)
			os.Exit(1)
		}
	} else {
		logger.Warn("bearer auth is disabled; bind the broker to a private network")
	}

	credentials, err := config.BuildCredentials(cfg, logger)
	if err != nil {
		logger.Error("building credentials", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if len(credentials) == 0 {
		logger.Warn("no credentials configured; broker will serve only /healthz")
	}

	b, err := broker.New(broker.Options{
		Config:      cfg,
		Credentials: credentials,
		Logger:      logger,
		BearerToken: bearerToken,
	})
	if err != nil {
		logger.Error("initializing broker", slog.String("error", err.Error()))
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	b.Start(ctx)

	errc := make(chan error, 2)
	go func() { errc <- b.ListenAndServe() }()
	go func() { errc <- b.ListenAndServeMetrics() }()

	logger.Info("iron-token-broker started",
		slog.String("version", version.Version),
		slog.Int("credentials", len(credentials)),
	)

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)

	var fatal error
	select {
	case sig := <-sigc:
		logger.Info("received signal, shutting down", slog.String("signal", sig.String()))
	case err := <-errc:
		if err != nil {
			logger.Error("fatal server error", slog.String("error", err.Error()))
			fatal = err
		}
	}

	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := b.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown error", slog.String("error", err.Error()))
	}
	b.Wait()

	logger.Info("iron-token-broker stopped")
	// Preserve the fatal flag so the supervisor (systemd Restart=on-failure,
	// container scheduler) treats a listener crash as a failure rather than
	// a clean exit.
	if fatal != nil {
		os.Exit(1)
	}
}

func newLogger(cfg *config.Config) (*slog.Logger, error) {
	level, err := config.ParseLogLevel(cfg.Log.Level)
	if err != nil {
		return nil, err
	}
	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	switch cfg.Log.Format {
	case "json":
		handler = slog.NewJSONHandler(os.Stderr, opts)
	default:
		handler = slog.NewTextHandler(os.Stderr, opts)
	}
	return slog.New(handler), nil
}

