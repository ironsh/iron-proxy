// Package otel configures OpenTelemetry log export for iron-proxy audit events.
//
// Configuration is driven by standard OTEL environment variables:
//   - OTEL_EXPORTER_OTLP_ENDPOINT: OTLP collector endpoint (e.g. https://logfire-us.pydantic.dev)
//   - OTEL_EXPORTER_OTLP_PROTOCOL: "http/protobuf" (default) or "grpc"
//   - OTEL_EXPORTER_OTLP_HEADERS: comma-separated key=value pairs for auth
//   - OTEL_RESOURCE_ATTRIBUTES: comma-separated key=value resource attributes
//   - OTEL_SERVICE_NAME: service name (defaults to "iron-proxy")
//
// Callers may also provide an [ExportConfig] with defaults (used in managed
// mode). Environment variables always take precedence over these defaults.
package otel

import (
	"context"
	"fmt"
	"os"

	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
)

// ExportConfig provides default OTLP export settings for fields not set via
// OTEL_EXPORTER_OTLP_* environment variables.
type ExportConfig struct {
	DefaultEndpoint string
	DefaultHeaders  map[string]string
}

// Enabled reports whether OTLP export should be initialized.
func (c ExportConfig) Enabled() bool {
	return c.DefaultEndpoint != "" || endpointFromEnv()
}

// NewLoggerProvider creates an OTEL LoggerProvider. Endpoint and headers from
// cfg are used only when the corresponding OTEL_EXPORTER_OTLP_* env vars are
// unset, so env vars always win.
func NewLoggerProvider(ctx context.Context, cfg ExportConfig) (*sdklog.LoggerProvider, error) {
	protocol := os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	if protocol == "" {
		protocol = "http/protobuf"
	}

	var exporter sdklog.Exporter
	var err error
	switch protocol {
	case "http/protobuf":
		exporter, err = otlploghttp.New(ctx, httpOptions(cfg)...)
	case "grpc":
		exporter, err = otlploggrpc.New(ctx, grpcOptions(cfg)...)
	default:
		return nil, fmt.Errorf("unsupported OTEL_EXPORTER_OTLP_PROTOCOL: %q (expected \"http/protobuf\" or \"grpc\")", protocol)
	}
	if err != nil {
		return nil, fmt.Errorf("creating OTLP log exporter: %w", err)
	}

	serviceName := os.Getenv("OTEL_SERVICE_NAME")
	if serviceName == "" {
		serviceName = "iron-proxy"
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
		),
		resource.WithFromEnv(),
		resource.WithTelemetrySDK(),
	)
	if err != nil {
		return nil, fmt.Errorf("creating OTEL resource: %w", err)
	}

	provider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
		sdklog.WithResource(res),
	)

	return provider, nil
}

func httpOptions(cfg ExportConfig) []otlploghttp.Option {
	var opts []otlploghttp.Option
	if cfg.DefaultEndpoint != "" && !endpointFromEnv() {
		opts = append(opts, otlploghttp.WithEndpointURL(cfg.DefaultEndpoint))
	}
	if len(cfg.DefaultHeaders) > 0 && !headersFromEnv() {
		opts = append(opts, otlploghttp.WithHeaders(cfg.DefaultHeaders))
	}
	return opts
}

func grpcOptions(cfg ExportConfig) []otlploggrpc.Option {
	var opts []otlploggrpc.Option
	if cfg.DefaultEndpoint != "" && !endpointFromEnv() {
		opts = append(opts, otlploggrpc.WithEndpointURL(cfg.DefaultEndpoint))
	}
	if len(cfg.DefaultHeaders) > 0 && !headersFromEnv() {
		opts = append(opts, otlploggrpc.WithHeaders(cfg.DefaultHeaders))
	}
	return opts
}

func endpointFromEnv() bool {
	return os.Getenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT") != "" ||
		os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != ""
}

func headersFromEnv() bool {
	return os.Getenv("OTEL_EXPORTER_OTLP_LOGS_HEADERS") != "" ||
		os.Getenv("OTEL_EXPORTER_OTLP_HEADERS") != ""
}
