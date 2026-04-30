// Package management provides iron-proxy's authenticated operator HTTP API.
package management

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
)

// ReloadFunc rebuilds the running pipeline from the on-disk config. Returning
// a *ValidationError signals that the supplied config could not be parsed or
// built into a pipeline; the server maps that to HTTP 422.
type ReloadFunc func() error

// ValidationError marks an error as the result of bad on-disk configuration
// rather than an internal failure. Reload handlers translate this to a 422.
type ValidationError struct{ Err error }

// Error returns the wrapped error message.
func (e *ValidationError) Error() string { return e.Err.Error() }

// Unwrap exposes the underlying error to errors.Is / errors.As.
func (e *ValidationError) Unwrap() error { return e.Err }

// Options configures Server.
type Options struct {
	Addr   string
	APIKey string
	Reload ReloadFunc
	Logger *slog.Logger
}

// Server serves the management API.
type Server struct {
	server *http.Server
	apiKey string
	reload ReloadFunc
	logger *slog.Logger
}

// New creates a Server bound to opts.Addr. The caller starts it with
// ListenAndServe and stops it with Shutdown.
func New(opts Options) *Server {
	mux := http.NewServeMux()
	s := &Server{
		apiKey: opts.APIKey,
		reload: opts.Reload,
		logger: opts.Logger,
	}
	mux.HandleFunc("/reload", s.handleReload)
	s.server = &http.Server{
		Addr:    opts.Addr,
		Handler: mux,
	}
	return s
}

// ListenAndServe starts the server. It blocks until the server is shut down.
func (s *Server) ListenAndServe() error {
	s.logger.Info("management server starting", slog.String("addr", s.server.Addr))
	return s.server.ListenAndServe()
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	err := s.reload()
	if err == nil {
		s.logger.Info("management reload succeeded")
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}

	var vErr *ValidationError
	if errors.As(err, &vErr) {
		s.logger.Warn("management reload rejected invalid config", slog.String("error", vErr.Error()))
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": vErr.Error()})
		return
	}

	s.logger.Error("management reload failed", slog.String("error", err.Error()))
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
}

func (s *Server) authorize(r *http.Request) bool {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return false
	}
	got := []byte(strings.TrimPrefix(h, prefix))
	want := []byte(s.apiKey)
	return subtle.ConstantTimeCompare(got, want) == 1
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
