package transform

import (
	"fmt"
	"log/slog"
	"sync"

	"gopkg.in/yaml.v3"
)

// Factory creates a Transformer from a raw YAML config node.
type Factory func(cfg yaml.Node, logger *slog.Logger) (Transformer, error)

var (
	registryMu sync.RWMutex
	registry   = make(map[string]Factory)
)

// Register adds a transform factory under the given name.
// Typically called from init() in transform implementation packages.
func Register(name string, factory Factory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[name] = factory
}

// Lookup returns the factory for the given transform name.
func Lookup(name string) (Factory, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()

	f, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown transform: %q", name)
	}
	return f, nil
}
