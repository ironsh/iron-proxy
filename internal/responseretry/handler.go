// Package responseretry implements a protocol-neutral, externally decided
// response retry hook.
package responseretry

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ironsh/iron-proxy/internal/dnsguard"
	"golang.org/x/net/http/httpguts"
)

var forbiddenRetryHeaders = map[string]struct{}{
	"Connection":          {},
	"Content-Length":      {},
	"Host":                {},
	"Keep-Alive":          {},
	"Proxy-Authorization": {},
	"Proxy-Authenticate":  {},
	"Proxy-Connection":    {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

const defaultClientTimeout = 10 * time.Second

// Handler asks a trusted service whether a bounded upstream response should
// be retried and reports the result of the one permitted replay.
type Handler struct {
	authorizeEndpoint *url.URL
	completeEndpoint  *url.URL
	token             string
	sandboxID         string
	statuses          map[int]struct{}
	completionHeaders map[string]struct{}
	client            *http.Client
}

// Options configures a response retry handler.
type Options struct {
	AuthorizeEndpoint string
	CompleteEndpoint  string
	Token             string
	SandboxID         string
	Statuses          []int
	AllowHTTP         bool
	CompletionHeaders []string
	Resolver          *net.Resolver
	Guard             *dnsguard.Guard
	ClientTimeout     time.Duration
	Client            *http.Client
}

// DecisionRequest describes the completed request and response. Request and
// response bodies are deliberately excluded.
type DecisionRequest struct {
	Host            string              `json:"host"`
	Method          string              `json:"method"`
	Path            string              `json:"path"`
	Replayable      bool                `json:"replayable"`
	Status          int                 `json:"status"`
	ResponseHeaders map[string][]string `json:"response_headers"`
	SandboxID       string              `json:"sandbox_id"`
	Traceparent     string              `json:"traceparent,omitempty"`
}

// DecisionResponse authorizes at most one replay with additional headers.
type DecisionResponse struct {
	Retry       bool              `json:"retry"`
	Headers     map[string]string `json:"headers"`
	AttemptID   string            `json:"attempt_id"`
	Traceparent string            `json:"traceparent,omitempty"`
}

// CompletionRequest reports the replay result without any request or response
// body and includes only explicitly selected response headers.
type CompletionRequest struct {
	AttemptID        string              `json:"attempt_id"`
	ReplayStatus     *int                `json:"replay_status"`
	ResponseHeaders  map[string][]string `json:"response_headers"`
	TransportError   string              `json:"transport_error,omitempty"`
	Traceparent      string              `json:"traceparent,omitempty"`
	ReplayDurationMS int64               `json:"replay_duration_ms,omitempty"`
	ChargeDurationMS int64               `json:"charge_duration_ms,omitempty"`
}

// Decision contains the validated result of an authorization call.
type Decision struct {
	Headers     http.Header
	AttemptID   string
	Traceparent string
}

// New creates a Handler for the configured response status codes.
func New(opts Options) (*Handler, error) {
	authorizeURL, err := parseEndpoint(opts.AuthorizeEndpoint, opts.AllowHTTP)
	if err != nil {
		return nil, fmt.Errorf("authorize endpoint: %w", err)
	}
	completeURL, err := parseEndpoint(opts.CompleteEndpoint, opts.AllowHTTP)
	if err != nil {
		return nil, fmt.Errorf("complete endpoint: %w", err)
	}
	if opts.Token == "" {
		return nil, fmt.Errorf("response retry handler token is required")
	}
	if opts.SandboxID == "" {
		return nil, fmt.Errorf("response retry handler sandbox identity is required")
	}
	statusSet := make(map[int]struct{}, len(opts.Statuses))
	for _, status := range opts.Statuses {
		if status < 100 || status > 599 {
			return nil, fmt.Errorf("invalid response retry status %s", strconv.Itoa(status))
		}
		statusSet[status] = struct{}{}
	}
	if len(statusSet) == 0 {
		return nil, fmt.Errorf("at least one response retry status is required")
	}
	completionHeaders := make(map[string]struct{}, len(opts.CompletionHeaders))
	for _, name := range opts.CompletionHeaders {
		if !httpguts.ValidHeaderFieldName(name) {
			return nil, fmt.Errorf("invalid completion response header %q", name)
		}
		completionHeaders[http.CanonicalHeaderKey(name)] = struct{}{}
	}
	return &Handler{
		authorizeEndpoint: authorizeURL,
		completeEndpoint:  completeURL,
		token:             opts.Token,
		sandboxID:         opts.SandboxID,
		statuses:          statusSet,
		completionHeaders: completionHeaders,
		client:            hardenedClient(opts.Client, opts.Resolver, opts.Guard, opts.ClientTimeout),
	}, nil
}

// Decide returns authorization metadata for one replay. The caller passes
// replayable=false when the exact request body cannot be replayed safely.
func (h *Handler) Decide(ctx context.Context, req *http.Request, resp *http.Response, replayable bool) (*Decision, bool, error) {
	if _, ok := h.statuses[resp.StatusCode]; !ok {
		return nil, false, nil
	}
	path := req.URL.EscapedPath()
	if req.URL.RawQuery != "" {
		path += "?" + req.URL.RawQuery
	}
	payload, err := json.Marshal(DecisionRequest{
		Host:            req.URL.Host,
		Method:          req.Method,
		Path:            path,
		Replayable:      replayable,
		Status:          resp.StatusCode,
		ResponseHeaders: resp.Header,
		SandboxID:       h.sandboxID,
		Traceparent:     req.Header.Get("Traceparent"),
	})
	if err != nil {
		return nil, false, fmt.Errorf("encode response retry decision request: %w", err)
	}
	decisionReq, err := h.newRequest(ctx, h.authorizeEndpoint, payload)
	if err != nil {
		return nil, false, fmt.Errorf("create response retry decision request: %w", err)
	}
	decisionResp, err := h.client.Do(decisionReq)
	if err != nil {
		return nil, false, fmt.Errorf("request response retry decision: %w", err)
	}
	defer decisionResp.Body.Close()
	if decisionResp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(decisionResp.Body, 64<<10))
		return nil, false, fmt.Errorf("response retry handler rejected request with status %d", decisionResp.StatusCode)
	}
	var decision DecisionResponse
	if err := json.NewDecoder(io.LimitReader(decisionResp.Body, 64<<10)).Decode(&decision); err != nil {
		return nil, false, fmt.Errorf("decode response retry decision: %w", err)
	}
	if !decision.Retry {
		return nil, false, nil
	}
	if !replayable {
		return nil, false, fmt.Errorf("response retry handler authorized a non-replayable request")
	}
	if decision.AttemptID == "" {
		return nil, false, fmt.Errorf("response retry handler omitted attempt id")
	}
	if decision.Traceparent != "" && !validTraceparent(decision.Traceparent) {
		return nil, false, fmt.Errorf("response retry handler returned invalid traceparent")
	}
	headers := make(http.Header, len(decision.Headers))
	for name, value := range decision.Headers {
		if !httpguts.ValidHeaderFieldName(name) {
			return nil, false, fmt.Errorf("response retry handler returned an invalid header name")
		}
		if !httpguts.ValidHeaderFieldValue(value) {
			return nil, false, fmt.Errorf("response retry handler returned an invalid value for header %s", name)
		}
		canonical := http.CanonicalHeaderKey(name)
		if _, forbidden := forbiddenRetryHeaders[canonical]; forbidden {
			return nil, false, fmt.Errorf("response retry handler returned forbidden header %s", canonical)
		}
		if _, duplicate := headers[canonical]; duplicate {
			return nil, false, fmt.Errorf("response retry handler returned duplicate header %s", canonical)
		}
		headers.Set(canonical, value)
	}
	return &Decision{
		Headers:     headers,
		AttemptID:   decision.AttemptID,
		Traceparent: decision.Traceparent,
	}, true, nil
}

// Complete reports the replay outcome. It is idempotent at the handler.
func (h *Handler) Complete(ctx context.Context, attemptID string, resp *http.Response, transportError, traceparent string, replayDuration, chargeDuration time.Duration) error {
	var status *int
	headers := make(http.Header)
	if resp != nil {
		value := resp.StatusCode
		status = &value
		headers = selectedHeaders(resp.Header, h.completionHeaders)
	}
	payload, err := json.Marshal(CompletionRequest{
		AttemptID:        attemptID,
		ReplayStatus:     status,
		ResponseHeaders:  headers,
		TransportError:   transportError,
		Traceparent:      traceparent,
		ReplayDurationMS: replayDuration.Milliseconds(),
		ChargeDurationMS: chargeDuration.Milliseconds(),
	})
	if err != nil {
		return fmt.Errorf("encode response retry completion request: %w", err)
	}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		req, err := h.newRequest(ctx, h.completeEndpoint, payload)
		if err != nil {
			return fmt.Errorf("create response retry completion request: %w", err)
		}
		completionResp, err := h.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("request response retry completion: %w", err)
			continue
		}
		_, copyErr := io.Copy(io.Discard, io.LimitReader(completionResp.Body, 64<<10))
		closeErr := completionResp.Body.Close()
		if copyErr != nil {
			return fmt.Errorf("read response retry completion: %w", copyErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close response retry completion: %w", closeErr)
		}
		if completionResp.StatusCode >= 200 && completionResp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("response retry completion returned status %d", completionResp.StatusCode)
		if completionResp.StatusCode < 500 {
			break
		}
	}
	return lastErr
}

func (h *Handler) newRequest(ctx context.Context, endpoint *url.URL, payload []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

func parseEndpoint(endpoint string, allowHTTP bool) (*url.URL, error) {
	u, err := url.Parse(endpoint)
	if err != nil || !u.IsAbs() || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("response retry handler URL must be absolute without credentials")
	}
	httpAllowed := u.Scheme == "http" && (allowHTTP || isLoopback(u.Hostname()))
	if u.Scheme != "https" && !httpAllowed {
		return nil, fmt.Errorf("response retry handler URL must use HTTPS unless HTTP is explicitly allowed")
	}
	return u, nil
}

func hardenedClient(client *http.Client, resolver *net.Resolver, guard *dnsguard.Guard, timeout time.Duration) *http.Client {
	if client == nil {
		client = &http.Client{Transport: newHandlerTransport(resolver, guard)}
	}
	result := *client
	if result.Timeout <= 0 {
		result.Timeout = timeout
		if result.Timeout <= 0 {
			result.Timeout = defaultClientTimeout
		}
	}
	result.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &result
}

type handlerTransport struct {
	guarded  http.RoundTripper
	loopback http.RoundTripper
}

func newHandlerTransport(resolver *net.Resolver, guard *dnsguard.Guard) http.RoundTripper {
	guardedDialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver:  resolver,
		Control:   guard.DialControl,
	}
	loopbackDialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   loopbackOnlyDialControl,
	}
	return &handlerTransport{
		guarded:  newHTTPTransport(guardedDialer),
		loopback: newHTTPTransport(loopbackDialer),
	}
}

func (t *handlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if isLoopback(req.URL.Hostname()) {
		return t.loopback.RoundTrip(req)
	}
	return t.guarded.RoundTrip(req)
}

func newHTTPTransport(dialer *net.Dialer) *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		DialContext:         dialer.DialContext,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
}

func loopbackOnlyDialControl(_ string, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.Unmap().IsLoopback() {
		return fmt.Errorf("response retry loopback endpoint resolved to non-loopback address %q", host)
	}
	return nil
}

func selectedHeaders(headers http.Header, allowed map[string]struct{}) http.Header {
	result := make(http.Header)
	for name := range allowed {
		if values := headers.Values(name); len(values) > 0 {
			result[name] = append([]string(nil), values...)
		}
	}
	return result
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address, err := netip.ParseAddr(host)
	return err == nil && address.Unmap().IsLoopback()
}

func validTraceparent(value string) bool {
	parts := strings.Split(value, "-")
	if len(parts) != 4 || parts[0] != "00" || len(parts[1]) != 32 || len(parts[2]) != 16 || len(parts[3]) != 2 {
		return false
	}
	traceID, traceErr := hex.DecodeString(parts[1])
	spanID, spanErr := hex.DecodeString(parts[2])
	_, flagsErr := hex.DecodeString(parts[3])
	return traceErr == nil && spanErr == nil && flagsErr == nil &&
		!allZero(traceID) && !allZero(spanID)
}

func allZero(value []byte) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}
