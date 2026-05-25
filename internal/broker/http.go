package broker

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// httpServer fronts the broker's HTTP API. The single served path is
// GET /credentials/{id}/access_token; everything else falls through to a
// 404 the operator can spot in the access log.
type httpServer struct {
	creds      map[string]*credentialState
	bearerEnv  string // env var name to read; "" disables auth
	bearer     string // captured at startup so we don't read env on every request
	log        *slog.Logger
	met        *metrics
	now        func() time.Time
	server     *http.Server
	listenAddr string
}

type httpOptions struct {
	Addr          string
	Credentials   map[string]*credentialState
	BearerAuthEnv string
	BearerToken   string // captured value of the env var
	Logger        *slog.Logger
	Metrics       *metrics
}

func newHTTPServer(opts httpOptions) *httpServer {
	mux := http.NewServeMux()
	h := &httpServer{
		creds:      opts.Credentials,
		bearerEnv:  opts.BearerAuthEnv,
		bearer:     opts.BearerToken,
		log:        opts.Logger,
		met:        opts.Metrics,
		now:        time.Now,
		listenAddr: opts.Addr,
	}
	mux.HandleFunc("GET /credentials/{id}/access_token", h.handleAccessToken)
	mux.HandleFunc("GET /healthz", h.handleHealth)
	h.server = &http.Server{
		Addr:              opts.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return h
}

func (s *httpServer) Addr() string { return s.listenAddr }

func (s *httpServer) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.server.Addr)
	if err != nil {
		return err
	}
	s.listenAddr = ln.Addr().String()
	s.log.Info("broker HTTP API starting",
		slog.String("addr", s.listenAddr),
		slog.Int("credentials", len(s.creds)),
	)
	return s.server.Serve(ln)
}

func (s *httpServer) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

func (s *httpServer) handleAccessToken(w http.ResponseWriter, r *http.Request) {
	const endpoint = "/credentials/{id}/access_token"
	start := s.now()
	status := http.StatusOK
	defer func() {
		s.met.recordHTTPRequest(endpoint, strconv.Itoa(status), s.now().Sub(start))
	}()

	// Token material must not be cached by any intermediary or client
	// middleware. Setting these before writing the response (including
	// errors) keeps the header consistent across status codes.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if !s.authorize(r) {
		status = http.StatusUnauthorized
		writeJSON(w, status, errorBody{Error: "unauthorized"})
		return
	}

	id := r.PathValue("id")
	cred, ok := s.creds[id]
	if !ok {
		status = http.StatusNotFound
		writeJSON(w, status, errorBody{Error: "credential not found"})
		return
	}

	token, expiresAt, err := cred.AccessToken(r.Context())
	if err != nil {
		var dErr *deadError
		switch {
		case errors.As(err, &dErr):
			status = http.StatusUnprocessableEntity
			writeJSON(w, status, errorBody{
				Error:  "credential dead",
				Reason: dErr.reason,
			})
		case errors.Is(err, errNotReady):
			status = http.StatusServiceUnavailable
			w.Header().Set("Retry-After", "5")
			writeJSON(w, status, errorBody{Error: "bootstrapping"})
		default:
			status = http.StatusInternalServerError
			s.log.Error("access_token request failed",
				slog.String("credential_id", id),
				slog.String("error", err.Error()),
			)
			writeJSON(w, status, errorBody{Error: "internal error"})
		}
		return
	}

	writeJSON(w, status, accessTokenBody{
		AccessToken: token,
		ExpiresAt:   expiresAt,
	})
}

func (s *httpServer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

func (s *httpServer) authorize(r *http.Request) bool {
	if s.bearer == "" {
		// Auth disabled at startup.
		return true
	}
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return false
	}
	got := []byte(strings.TrimPrefix(h, prefix))
	want := []byte(s.bearer)
	return subtle.ConstantTimeCompare(got, want) == 1
}

type errorBody struct {
	Error  string `json:"error"`
	Reason string `json:"reason,omitempty"`
}

type accessTokenBody struct {
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
