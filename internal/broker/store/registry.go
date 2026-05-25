package store

import (
	"fmt"
	"log/slog"

	"gopkg.in/yaml.v3"
)

// Builder validates a store config and returns a Handle. Build must not
// perform I/O — only static config validation. Backends are dispatched by
// the "type" field on the YAML node, mirroring the pattern in
// internal/transform/secrets so operators learn one schema.
type Builder interface {
	Build(raw yaml.Node, logger *slog.Logger) (Handle, error)
}

type typeHint struct {
	Type string `yaml:"type"`
}

// BuildHandle constructs a Handle from a yaml node shaped like a top-level
// "store:" block (e.g. {type: file, path: ...}). The env source from
// internal/transform/secrets is intentionally absent — environment
// variables are read-only and cannot back a writable store.
func BuildHandle(node yaml.Node, logger *slog.Logger) (Handle, error) {
	var hint typeHint
	if err := node.Decode(&hint); err != nil {
		return nil, fmt.Errorf("parsing store type: %w", err)
	}
	if hint.Type == "" {
		return nil, fmt.Errorf("store.type is required")
	}
	b, ok := defaultBuilders()[hint.Type]
	if !ok {
		return nil, fmt.Errorf("unsupported store type %q", hint.Type)
	}
	return b.Build(node, logger)
}

func defaultBuilders() map[string]Builder {
	return map[string]Builder{
		"file":              fileBuilder{},
		"1password":         opBuilder{},
		"1password_connect": opConnectBuilder{},
		"aws_sm":            awsSMBuilder{},
		"aws_ssm":           awsSSMBuilder{},
	}
}
