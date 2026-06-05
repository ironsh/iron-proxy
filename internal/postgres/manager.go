package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
)

// Manager owns the single running postgres listener server and supports hot
// reload by closing the old one and starting a new one from an updated
// listener. Safe for concurrent use.
type Manager struct {
	logger *slog.Logger

	mu     sync.Mutex
	server *Server
}

// NewManager returns a Manager with no running server.
func NewManager(logger *slog.Logger) *Manager {
	return &Manager{logger: logger}
}

// Start launches the listener server. A nil listener is a no-op. A server that
// exits with a non-nil error sends it to errc so the calling process can treat
// it as fatal; bind failures during a subsequent Reload are logged instead.
func (m *Manager) Start(listener *Listener, errc chan<- error) {
	if listener == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	srv := NewServer(listener, m.logger)
	m.server = srv
	go m.run(srv, errc)
}

// Reload closes the running listener and starts a new one from the given
// listener (nil means "no listener"). In-flight client sessions on the closed
// listener are not interrupted, but no new connections will be accepted on the
// old address. ctx bounds the shutdown of the old listener. A bind failure
// during reload (e.g. address already in use) is logged, not fatal: the
// management /v1/reload caller has already received a 200.
func (m *Manager) Reload(ctx context.Context, listener *Listener) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.server != nil {
		if err := m.server.Shutdown(ctx); err != nil {
			m.logger.Error("postgres listener shutdown during reload",
				slog.String("name", m.server.Name()),
				slog.String("error", err.Error()),
			)
		}
		m.server = nil
	}

	if listener == nil {
		return
	}
	srv := NewServer(listener, m.logger)
	m.server = srv
	go m.run(srv, nil)
}

// Shutdown closes the running listener, if any.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.server == nil {
		return nil
	}
	return m.server.Shutdown(ctx)
}

// Running reports whether a listener server is currently running. Test-only.
func (m *Manager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.server != nil
}

func (m *Manager) run(s *Server, errc chan<- error) {
	err := s.ListenAndServe()
	if err == nil {
		return
	}
	if errc != nil {
		errc <- fmt.Errorf("postgres[%s]: %w", s.Name(), err)
		return
	}
	m.logger.Error("postgres listener stopped",
		slog.String("name", s.Name()),
		slog.String("error", err.Error()),
	)
}
