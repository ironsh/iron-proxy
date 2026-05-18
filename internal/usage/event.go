package usage

import (
	"context"
	"time"
)

// Event is the durable usage-count record emitted by iron-proxy.
type Event struct {
	SchemaVersion int       `json:"schema_version"`
	RequestID     string    `json:"request_id"`
	TS            time.Time `json:"ts"`

	Provider string `json:"provider"`
	Host     string `json:"host"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	Model    string `json:"model,omitempty"`

	StatusCode int     `json:"status_code"`
	DurationMS float64 `json:"duration_ms"`

	InputTokens              *int64 `json:"input_tokens,omitempty"`
	OutputTokens             *int64 `json:"output_tokens,omitempty"`
	CacheCreationInputTokens *int64 `json:"cache_creation_input_tokens,omitempty"`
	CacheReadInputTokens     *int64 `json:"cache_read_input_tokens,omitempty"`

	ErrorClass             string `json:"error_class,omitempty"`
	UsageUnavailableReason string `json:"usage_unavailable_reason,omitempty"`
}

// Sink accepts usage events from the proxy hot path.
type Sink interface {
	TryEnqueue(Event) bool
	Close(context.Context) error
}
