package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
)

// Manager owns the running set of postgres listener servers and supports
// hot reload by closing the old set and starting a new one from updated
// policies. Safe for concurrent use.
type Manager struct {
	logger *slog.Logger

	mu      sync.Mutex
	servers []*Server
}

// NewManager returns a Manager with no running servers.
func NewManager(logger *slog.Logger) *Manager {
	return &Manager{logger: logger}
}

// Start launches a listener for each policy. A listener that exits with a
// non-nil error sends it to errc so the calling process can treat it as
// fatal; bind failures during a subsequent Reload are logged instead.
func (m *Manager) Start(policies []*Policy, errc chan<- error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range policies {
		srv := NewServer(p, m.logger)
		m.servers = append(m.servers, srv)
		go m.run(srv, errc)
	}
}

// Reload closes all running listeners and starts a new set from policies.
// In-flight client sessions on the closed listeners are not interrupted, but
// no new connections will be accepted on the old addresses. ctx bounds the
// shutdown of the old listeners. Listener failures during reload (e.g.
// address already in use) are logged, not fatal: the management /v1/reload
// caller has already received a 200.
func (m *Manager) Reload(ctx context.Context, policies []*Policy) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, s := range m.servers {
		if err := s.Shutdown(ctx); err != nil {
			m.logger.Error("postgres listener shutdown during reload",
				slog.String("name", s.Name()),
				slog.String("error", err.Error()),
			)
		}
	}

	m.servers = make([]*Server, 0, len(policies))
	for _, p := range policies {
		srv := NewServer(p, m.logger)
		m.servers = append(m.servers, srv)
		go m.run(srv, nil)
	}
}

// Shutdown closes all running listeners. The first error from any server is
// returned; remaining listeners are still asked to shut down.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var firstErr error
	for _, s := range m.servers {
		if err := s.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Names returns the names of the currently running servers. Test-only.
func (m *Manager) Names() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.servers))
	for _, s := range m.servers {
		out = append(out, s.Name())
	}
	return out
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
