// Package otel configures OpenTelemetry log export for iron-proxy audit events.
//
// Configuration is driven by standard OTEL environment variables:
//   - OTEL_EXPORTER_OTLP_ENDPOINT: OTLP collector endpoint (e.g. https://logfire-us.pydantic.dev)
//   - OTEL_EXPORTER_OTLP_PROTOCOL: "http/protobuf" (default) or "grpc"
//   - OTEL_EXPORTER_OTLP_HEADERS: comma-separated key=value pairs for auth
//   - OTEL_RESOURCE_ATTRIBUTES: comma-separated key=value resource attributes
//   - OTEL_SERVICE_NAME: service name (defaults to "iron-proxy")
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

// NewLoggerProvider creates an OTEL LoggerProvider configured via environment
// variables. The caller must call Shutdown on the returned provider during
// graceful shutdown. Both exporters read their config (endpoint, headers, TLS,
// etc.) from standard OTEL_EXPORTER_OTLP_* env vars automatically.
func NewLoggerProvider(ctx context.Context) (*sdklog.LoggerProvider, error) {
	protocol := os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	if protocol == "" {
		protocol = "http/protobuf"
	}

	var exporter sdklog.Exporter
	var err error
	switch protocol {
	case "http/protobuf":
		exporter, err = otlploghttp.New(ctx)
	case "grpc":
		exporter, err = otlploggrpc.New(ctx)
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

// Enabled returns true if OTEL_EXPORTER_OTLP_ENDPOINT is set, indicating
// that the user wants to export telemetry.
func Enabled() bool {
	return os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != ""
}

