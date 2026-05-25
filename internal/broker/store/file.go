package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type fileBuilder struct{}

type fileConfig struct {
	Type string `yaml:"type"`
	Path string `yaml:"path"`
}

func (fileBuilder) Build(raw yaml.Node, logger *slog.Logger) (Handle, error) {
	var cfg fileConfig
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing file store config: %w", err)
	}
	if cfg.Path == "" {
		return nil, fmt.Errorf("file store requires \"path\" field")
	}
	if !filepath.IsAbs(cfg.Path) {
		return nil, fmt.Errorf("file store path %q must be absolute", cfg.Path)
	}
	return &fileHandle{path: cfg.Path, logger: logger}, nil
}

// fileHandle reads and writes a single JSON file via tmpfile + fsync +
// rename so the on-disk blob is never observed half-written.
type fileHandle struct {
	path   string
	logger *slog.Logger
}

func (h *fileHandle) Name() string { return h.path }

func (h *fileHandle) Get(_ context.Context) (CredentialBlob, error) {
	raw, err := os.ReadFile(h.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return CredentialBlob{}, ErrNotFound
		}
		return CredentialBlob{}, fmt.Errorf("reading credential blob %q: %w", h.path, err)
	}
	blob, err := unmarshalBlob(raw)
	if err != nil {
		return CredentialBlob{}, fmt.Errorf("file store %q: %w", h.path, err)
	}
	return blob, nil
}

func (h *fileHandle) Put(_ context.Context, blob CredentialBlob) error {
	// Stat the existing file (if any) only to preserve its permission
	// bits across the rename. Brand-new files land at 0600 so a fresh
	// blob is never world-readable.
	mode := os.FileMode(0o600)
	if info, err := os.Stat(h.path); err == nil {
		mode = info.Mode().Perm()
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat credential blob %q: %w", h.path, err)
	}

	raw, err := marshalBlob(blob)
	if err != nil {
		return err
	}

	dir := filepath.Dir(h.path)
	f, err := os.CreateTemp(dir, filepath.Base(h.path)+".tmp.*")
	if err != nil {
		return fmt.Errorf("creating tmpfile in %q: %w", dir, err)
	}
	tmpName := f.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		return fmt.Errorf("writing tmpfile %q: %w", tmpName, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("fsync tmpfile %q: %w", tmpName, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing tmpfile %q: %w", tmpName, err)
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return fmt.Errorf("chmod tmpfile %q: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, h.path); err != nil {
		return fmt.Errorf("renaming tmpfile to %q: %w", h.path, err)
	}
	return nil
}
