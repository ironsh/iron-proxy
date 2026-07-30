// Package responseretry implements a protocol-neutral, externally decided
// response retry hook.
package responseretry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

var forbiddenRetryHeaders = map[string]struct{}{
	"Connection":          {},
	"Content-Length":      {},
	"Host":                {},
	"Proxy-Authorization": {},
	"Transfer-Encoding":   {},
}

// Handler asks a trusted service whether a bounded upstream response should
// be retried and which request headers to add. It does not interpret response
// protocols or credentials.
type Handler struct {
	endpoint *url.URL
	token    string
	statuses map[int]struct{}
	client   *http.Client
}

// DecisionRequest describes the completed request and response. Response
// bodies are deliberately excluded.
type DecisionRequest struct {
	Host            string              `json:"host"`
	Method          string              `json:"method"`
	Path            string              `json:"path"`
	Status          int                 `json:"status"`
	ResponseHeaders map[string][]string `json:"response_headers"`
}

// DecisionResponse authorizes at most one replay with additional headers.
type DecisionResponse struct {
	Retry   bool              `json:"retry"`
	Headers map[string]string `json:"headers"`
}

// New creates a Handler for the configured response status codes.
func New(endpoint, token string, statuses []int, client *http.Client) (*Handler, error) {
	u, err := url.Parse(endpoint)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return nil, fmt.Errorf("response retry handler URL must be absolute")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname())) {
		return nil, fmt.Errorf("response retry handler URL must use HTTPS unless it is loopback")
	}
	if token == "" {
		return nil, fmt.Errorf("response retry handler token is required")
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
	return &Handler{endpoint: u, token: token, statuses: statusSet, client: client}, nil
}

// Decide returns request headers for one replay. retry is false when the
// response status is outside the configured set or the handler declines.
func (h *Handler) Decide(ctx context.Context, req *http.Request, resp *http.Response) (headers http.Header, retry bool, err error) {
	if _, ok := h.statuses[resp.StatusCode]; !ok {
		return nil, false, nil
	}
	payload, err := json.Marshal(DecisionRequest{
		Host:            req.URL.Host,
		Method:          req.Method,
		Path:            req.URL.EscapedPath(),
		Status:          resp.StatusCode,
		ResponseHeaders: resp.Header,
	})
	if err != nil {
		return nil, false, fmt.Errorf("encode response retry decision request: %w", err)
	}
	decisionReq, err := http.NewRequestWithContext(ctx, http.MethodPost, h.endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, false, fmt.Errorf("create response retry decision request: %w", err)
	}
	decisionReq.Header.Set("Authorization", "Bearer "+h.token)
	decisionReq.Header.Set("Content-Type", "application/json")
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
	headers = make(http.Header, len(decision.Headers))
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
	return headers, true, nil
}

func isLoopback(host string) bool {
	return host == "localhost" || strings.HasPrefix(host, "127.") || host == "::1"
}
