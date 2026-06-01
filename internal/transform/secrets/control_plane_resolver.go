package secrets

import (
	"context"
	"fmt"
	"log/slog"

	"gopkg.in/yaml.v3"
)

// controlPlaneBuilder builds sources whose value is delivered inline by the
// control plane via the authenticated sync channel. There is no backend to
// reach out to: Get returns the static value carried in the config payload.
type controlPlaneBuilder struct{}

type controlPlaneConfig struct {
	Type  string `yaml:"type"`
	Value string `yaml:"value"`
}

func newControlPlaneBuilder(_ *slog.Logger) *controlPlaneBuilder {
	return &controlPlaneBuilder{}
}

func (b *controlPlaneBuilder) Build(raw yaml.Node) (secretSource, error) {
	var cfg controlPlaneConfig
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing control_plane source config: %w", err)
	}
	if cfg.Value == "" {
		return nil, fmt.Errorf("control_plane source requires \"value\" field")
	}
	return &staticSource{name: "control_plane", value: cfg.Value}, nil
}

// staticSource returns a fixed value supplied at config-build time. The display
// name is fixed rather than the value so the secret never appears in logs or
// annotations.
type staticSource struct {
	name  string
	value string
}

func (s *staticSource) Name() string { return s.name }

func (s *staticSource) Get(context.Context) (string, error) { return s.value, nil }
