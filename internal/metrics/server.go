// Package metrics provides the iron-proxy health check and metrics HTTP server.
package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
)

// Server serves health check and metrics endpoints.
type Server struct {
	server *http.Server
	logger *slog.Logger
}

// New creates a new metrics server listening on the given address.
func New(addr string, logger *slog.Logger) *Server {
	mux := http.NewServeMux()
	s := &Server{
		server: &http.Server{
			Addr:    addr,
			Handler: mux,
		},
		logger: logger,
	}
	mux.HandleFunc("/healthz", s.handleHealthz)
	return s
}

// ListenAndServe starts the server. It blocks until the server is shut down.
func (s *Server) ListenAndServe() error {
	s.logger.Info("metrics server starting", slog.String("addr", s.server.Addr))
	return s.server.ListenAndServe()
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "OK")
}
