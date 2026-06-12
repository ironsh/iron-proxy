// Package management provides iron-proxy's authenticated operator HTTP API.
package management

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

// ReloadFunc rebuilds the running pipeline from the on-disk config. ctx is
// the server's process-scoped context (configured via Options.Ctx) so a
// reload survives an HTTP client disconnect: a partially-applied swap of
// pipeline, MCP, and postgres listeners would leave the proxy in a
// half-reloaded state. Returning a *ValidationError signals that the
// supplied config could not be parsed or built; the server maps that to
// HTTP 422.
type ReloadFunc func(context.Context) error

// ValidationError marks an error as the result of bad on-disk configuration
// rather than an internal failure. Reload handlers translate this to a 422.
type ValidationError struct{ Err error }

// Error returns the wrapped error message.
func (e *ValidationError) Error() string { return e.Err.Error() }

// Unwrap exposes the underlying error to errors.Is / errors.As.
func (e *ValidationError) Unwrap() error { return e.Err }

// errorResponse is the JSON body sent for any non-2xx response.
type errorResponse struct {
	Error string `json:"error"`
}

// statusResponse is the JSON body sent for successful operations.
type statusResponse struct {
	Status string `json:"status"`
}

// Options configures Server.
type Options struct {
	Addr   string
	APIKey string
	// Reload rebuilds the pipeline from the on-disk config. Standalone mode
	// only; nil disables /v1/reload (managed proxies have no file to re-read).
	Reload ReloadFunc
	// Status returns a JSON-encodable snapshot of the applied control-plane
	// state. Managed mode only; nil disables /v1/status.
	Status func() any
	// SyncNow requests an immediate control-plane sync. Managed mode only;
	// nil disables /v1/sync.
	SyncNow func()
	Logger  *slog.Logger

	// Ctx is the process-scoped context passed to Reload. It must outlive
	// individual HTTP requests so a client disconnect cannot abort a reload
	// after pipeline/MCP have been swapped but before postgres listeners
	// have been recycled. If nil, context.Background() is used.
	Ctx context.Context
}

// Server serves the management API.
type Server struct {
	server  *http.Server
	apiKey  string
	reload  ReloadFunc
	status  func() any
	syncNow func()
	logger  *slog.Logger
	ctx     context.Context
}

// New creates a Server bound to opts.Addr. The caller starts it with
// ListenAndServe and stops it with Shutdown.
func New(opts Options) *Server {
	mux := http.NewServeMux()
	ctx := opts.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	s := &Server{
		apiKey:  opts.APIKey,
		reload:  opts.Reload,
		status:  opts.Status,
		syncNow: opts.SyncNow,
		logger:  opts.Logger,
		ctx:     ctx,
	}
	mux.HandleFunc("/v1/reload", s.handleReload)
	mux.HandleFunc("/v1/status", s.handleStatus)
	mux.HandleFunc("/v1/sync", s.handleSync)
	s.server = &http.Server{
		Addr:    opts.Addr,
		Handler: mux,
	}
	return s
}

// ListenAndServe starts the server. It blocks until the server is shut down.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.server.Addr)
	if err != nil {
		return err
	}
	s.logger.Info("management server starting", slog.String("addr", ln.Addr().String()))
	return s.server.Serve(ln)
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(r) {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed"})
		return
	}
	if s.reload == nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "reload is unavailable in managed mode"})
		return
	}

	// Use the server-scoped context, not r.Context(): reload mutates
	// process-wide state and must not be cut short by a client disconnect.
	err := s.reload(s.ctx)
	if err == nil {
		s.logger.Info("management reload succeeded")
		writeJSON(w, http.StatusOK, statusResponse{Status: "ok"})
		return
	}

	var vErr *ValidationError
	if errors.As(err, &vErr) {
		s.logger.Warn("management reload rejected invalid config", slog.String("error", vErr.Error()))
		writeJSON(w, http.StatusUnprocessableEntity, errorResponse{Error: vErr.Error()})
		return
	}

	s.logger.Error("management reload failed", slog.String("error", err.Error()))
	writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal error"})
}

// handleStatus serves the applied control-plane state (managed mode).
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(r) {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed"})
		return
	}
	if s.status == nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "status is unavailable in standalone mode"})
		return
	}
	writeJSON(w, http.StatusOK, s.status())
}

// handleSync requests an immediate control-plane sync (managed mode). The
// sync itself is asynchronous: callers poll /v1/status to observe the
// applied result.
func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(r) {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed"})
		return
	}
	if s.syncNow == nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "sync is unavailable in standalone mode"})
		return
	}
	s.syncNow()
	writeJSON(w, http.StatusAccepted, statusResponse{Status: "sync requested"})
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
