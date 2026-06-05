package postgres

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// handshakeTimeout bounds the time a half-open client can spend before its
// StartupMessage / auth round-trip completes. The relay loop, once started,
// manages its own I/O cadence and clears the deadline.
const handshakeTimeout = 30 * time.Second

// Server is the listener that accepts incoming PostgreSQL client connections
// and dispatches them to per-conn session handlers.
type Server struct {
	listener *Listener
	logger   *slog.Logger

	mu       sync.Mutex
	netLn    net.Listener
	shutdown bool
}

// NewServer constructs a postgres server bound to the given listener config.
func NewServer(listener *Listener, logger *slog.Logger) *Server {
	return &Server{listener: listener, logger: logger}
}

// Name returns the configured listener name. Used in logs and error wrapping
// when multiple postgres listeners are running.
func (s *Server) Name() string { return s.listener.Name() }

// Addr returns the address the server is bound to. Useful in tests where the
// configured listen address is ":0" — the actual port is only known after
// Listen completes. Returns an empty string before ListenAndServe binds.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.netLn == nil {
		return ""
	}
	return s.netLn.Addr().String()
}

// ListenAndServe binds to the configured listen address and serves clients
// until Shutdown is called or the listener returns a fatal error.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.listener.Listen())
	if err != nil {
		return fmt.Errorf("postgres listen: %w", err)
	}
	s.mu.Lock()
	s.netLn = ln
	s.mu.Unlock()

	s.logger.Info("postgres proxy starting",
		slog.String("name", s.listener.Name()),
		slog.String("addr", ln.Addr().String()),
		slog.Int("upstreams", len(s.listener.upstreams)),
	)

	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			down := s.shutdown
			s.mu.Unlock()
			if down {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("postgres accept: %w", err)
		}
		go s.handle(conn)
	}
}

// Shutdown closes the listener so ListenAndServe returns. In-flight sessions
// are not interrupted; their connections will end as the client disconnects or
// the upstream times out. v1 does not implement graceful drain.
func (s *Server) Shutdown(_ context.Context) error {
	s.mu.Lock()
	s.shutdown = true
	ln := s.netLn
	s.mu.Unlock()
	if ln == nil {
		return nil
	}
	return ln.Close()
}

func (s *Server) handle(conn net.Conn) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	runSession(ctx, conn, s.listener, s.logger)
}
