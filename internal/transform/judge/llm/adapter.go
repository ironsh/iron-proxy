// Package llm defines the adapter interface for LLM backends used by the
// judge transform. Adapters are thin transports: they send the prompt and
// return the raw model output. Decision parsing lives in the judge package.
package llm

import (
	"context"
	"fmt"
	"log/slog"

	"gopkg.in/yaml.v3"
)

// Request is a single LLM call. Timeouts flow through ctx.
type Request struct {
	SystemPrompt string
	UserContent  string
	MaxTokens    int
}

// Response is the raw result from the LLM. The adapter does not parse the
// decision: callers extract JSON from RawOutput themselves.
type Response struct {
	RawOutput    string
	Model        string
	InputTokens  int
	OutputTokens int
}

// Adapter is the backend interface the judge transform calls. Implementations
// must be safe for concurrent use from multiple goroutines.
type Adapter interface {
	Name() string
	Model() string
	Complete(ctx context.Context, req Request) (Response, error)
}

// NewAdapter constructs an Adapter from a provider type string and its
// type-specific YAML config. v1 supports only "anthropic".
func NewAdapter(providerType string, cfg yaml.Node, logger *slog.Logger) (Adapter, error) {
	switch providerType {
	case "anthropic":
		return newAnthropic(cfg, logger)
	case "":
		return nil, fmt.Errorf("provider.type is required")
	default:
		return nil, fmt.Errorf("unknown judge provider %q", providerType)
	}
}
