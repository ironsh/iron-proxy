// Package responseretry implements a protocol-neutral, externally decided
// response retry hook.
package responseretry

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var forbiddenRetryHeaders = map[string]struct{}{
	"Connection":          {},
	"Content-Length":      {},
	"Host":                {},
	"Proxy-Authorization": {},
	"Transfer-Encoding":   {},
}

// Handler asks a trusted service whether a bounded upstream response should
// be retried and reports the result of the one permitted replay.
type Handler struct {
	authorizeEndpoint *url.URL
	completeEndpoint  *url.URL
	token             string
	sandboxID         string
	statuses          map[int]struct{}
	client            *http.Client
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
// body and includes only the payment receipt response header.
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
func New(authorizeEndpoint, completeEndpoint, token, sandboxID string, statuses []int, allowHTTP bool, client *http.Client) (*Handler, error) {
	authorizeURL, err := parseEndpoint(authorizeEndpoint, allowHTTP)
	if err != nil {
		return nil, fmt.Errorf("authorize endpoint: %w", err)
	}
	completeURL, err := parseEndpoint(completeEndpoint, allowHTTP)
	if err != nil {
		return nil, fmt.Errorf("complete endpoint: %w", err)
	}
	if token == "" {
		return nil, fmt.Errorf("response retry handler token is required")
	}
	if sandboxID == "" {
		return nil, fmt.Errorf("response retry handler sandbox identity is required")
	}
	statusSet := make(map[int]struct{}, len(statuses))
	for _, status := range statuses {
		if status < 100 || status > 599 {
			return nil, fmt.Errorf("invalid response retry status %s", strconv.Itoa(status))
		}
		statusSet[status] = struct{}{}
	}
	if len(statusSet) == 0 {
		return nil, fmt.Errorf("at least one response retry status is required")
	}
	if client == nil {
		client = http.DefaultClient
	}
	return &Handler{
		authorizeEndpoint: authorizeURL,
		completeEndpoint:  completeURL,
		token:             token,
		sandboxID:         sandboxID,
		statuses:          statusSet,
		client:            client,
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
		canonical := http.CanonicalHeaderKey(name)
		if canonical == "" {
			return nil, false, fmt.Errorf("response retry handler returned an invalid header name")
		}
		if _, forbidden := forbiddenRetryHeaders[canonical]; forbidden {
			return nil, false, fmt.Errorf("response retry handler returned forbidden header %s", canonical)
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
		headers = receiptHeaders(resp.Header)
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
	req, err := h.newRequest(ctx, h.completeEndpoint, payload)
	if err != nil {
		return fmt.Errorf("create response retry completion request: %w", err)
	}
	completionResp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("request response retry completion: %w", err)
	}
	defer completionResp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(completionResp.Body, 64<<10))
	if completionResp.StatusCode < 200 || completionResp.StatusCode >= 300 {
		return fmt.Errorf("response retry completion returned status %d", completionResp.StatusCode)
	}
	return nil
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
	if u.Scheme != "https" && !(u.Scheme == "http" && (allowHTTP || isLoopback(u.Hostname()))) {
		return nil, fmt.Errorf("response retry handler URL must use HTTPS unless HTTP is explicitly allowed")
	}
	return u, nil
}

func receiptHeaders(headers http.Header) http.Header {
	result := make(http.Header)
	for name, values := range headers {
		if strings.EqualFold(name, "Payment-Receipt") {
			result[name] = append([]string(nil), values...)
		}
	}
	return result
}

func isLoopback(host string) bool {
	return host == "localhost" || strings.HasPrefix(host, "127.") || host == "::1"
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
