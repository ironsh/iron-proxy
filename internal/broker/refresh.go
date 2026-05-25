package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// refreshResult is the broker's normalized view of an OAuth token endpoint
// response. Fields are taken straight from the RFC 6749 4.1.4 body shape;
// RefreshToken is empty when the IdP did not rotate (so the caller carries
// the previous one forward).
type refreshResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    time.Duration
}

// refreshRequest carries everything the broker needs to mint a new token
// pair from a refresh_token. All of these fields are resolved freshly each
// call so a rotated client_secret or client_id picks up without restart.
type refreshRequest struct {
	TokenEndpoint string
	ClientID      string
	ClientSecret  string // empty for public clients
	RefreshToken  string
	Scopes        []string // optional
}

// refreshClient performs the raw RFC 6749 4.5 refresh_token grant POST and
// returns the parsed response. The broker drives all retry/backoff state
// itself; this function is single-shot.
//
// SECURITY: this function deliberately never logs req.RefreshToken,
// req.ClientSecret, the response body, or any decoded token. The caller
// must keep the same discipline when handling the returned result.
type refreshClient struct {
	http *http.Client
}

func newRefreshClient(client *http.Client) *refreshClient {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &refreshClient{http: client}
}

func (rc *refreshClient) Refresh(ctx context.Context, req refreshRequest) (refreshResult, error) {
	if req.TokenEndpoint == "" {
		return refreshResult{}, errors.New("token endpoint is required")
	}
	if req.ClientID == "" {
		return refreshResult{}, errors.New("client_id is required")
	}
	if req.RefreshToken == "" {
		return refreshResult{}, errors.New("refresh_token is required")
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", req.RefreshToken)
	form.Set("client_id", req.ClientID)
	if req.ClientSecret != "" {
		form.Set("client_secret", req.ClientSecret)
	}
	if len(req.Scopes) > 0 {
		form.Set("scope", strings.Join(req.Scopes, " "))
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, req.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return refreshResult{}, fmt.Errorf("building refresh request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := rc.http.Do(httpReq)
	if err != nil {
		return refreshResult{}, &refreshError{
			Stage:     refreshStageNetwork,
			Cause:     err,
			Retryable: true,
		}
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return refreshResult{}, &refreshError{
			Stage:     refreshStageNetwork,
			Cause:     err,
			Retryable: true,
		}
	}

	if resp.StatusCode/100 != 2 {
		return refreshResult{}, classifyTokenEndpointError(resp.StatusCode, body)
	}

	var parsed tokenResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		// Treat malformed 2xx bodies as transient: a misbehaving LB or
		// gateway in front of the IdP can corrupt a response without the
		// credential itself being invalid. The dead-after-N-failures
		// escalation in the credential loop still catches a persistently
		// broken IdP.
		return refreshResult{}, &refreshError{
			Stage:      refreshStageParse,
			Cause:      fmt.Errorf("parsing token response: %w", err),
			StatusCode: resp.StatusCode,
			Retryable:  true,
		}
	}
	if parsed.AccessToken == "" {
		return refreshResult{}, &refreshError{
			Stage:      refreshStageParse,
			Cause:      errors.New("token endpoint returned an empty access_token"),
			StatusCode: resp.StatusCode,
			Retryable:  true,
		}
	}
	return refreshResult{
		AccessToken:  parsed.AccessToken,
		RefreshToken: parsed.RefreshToken,
		ExpiresIn:    time.Duration(parsed.ExpiresIn) * time.Second,
	}, nil
}

// tokenResponse is the RFC 6749 success body shape.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
}

// refreshErrorStage tags where in the refresh flow the failure occurred.
// Used for metric labels and operator-facing diagnostics.
type refreshErrorStage string

const (
	refreshStageNetwork refreshErrorStage = "network"
	refreshStageHTTP    refreshErrorStage = "http"
	refreshStageOAuth   refreshErrorStage = "oauth"
	refreshStageParse   refreshErrorStage = "parse"
)

// refreshError categorizes failures from a refresh attempt. Retryable
// failures (network, 5xx, unknown oauth codes) feed the backoff loop;
// non-retryable ones (invalid_grant, invalid_client) immediately mark the
// credential dead.
type refreshError struct {
	Stage      refreshErrorStage
	Code       string // RFC 6749 5.2 error code or "" if not present
	StatusCode int
	Cause      error
	Retryable  bool
}

func (e *refreshError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("refresh failed (%s, code=%s, status=%d): %v", e.Stage, e.Code, e.StatusCode, e.Cause)
	}
	if e.StatusCode != 0 {
		return fmt.Sprintf("refresh failed (%s, status=%d): %v", e.Stage, e.StatusCode, e.Cause)
	}
	return fmt.Sprintf("refresh failed (%s): %v", e.Stage, e.Cause)
}

func (e *refreshError) Unwrap() error { return e.Cause }

// classifyTokenEndpointError categorizes a non-2xx token endpoint
// response. The classification is intentionally aggressive on the
// non-retryable side: every RFC 6749 5.2 error code is structural
// (invalid_grant, invalid_client, invalid_request, unauthorized_client,
// unsupported_grant_type, invalid_scope) and so are every IdP-specific
// extension code we've seen (refresh_token_reused, token_revoked, etc.).
// If the IdP returned an OAuth error code at all, the credential is
// dead until a human acts; retrying just wastes IdP load and, for
// reuse-detecting IdPs, makes the situation worse.
//
// Retryable failures are transport-shaped: 5xx, or 4xx with no OAuth
// error body (e.g. a bare 429 from a gateway). 5xx wins over any
// body shape because the IdP itself is unhealthy and may not even be
// the source of the body.
func classifyTokenEndpointError(status int, body []byte) error {
	var parsed errorResponse
	_ = json.Unmarshal(body, &parsed) // body may not be JSON; that's OK

	if status/100 == 5 {
		return &refreshError{
			Stage:      refreshStageHTTP,
			Code:       parsed.Error,
			StatusCode: status,
			Cause:      fmt.Errorf("token endpoint http %d: %s", status, parsed.Error),
			Retryable:  true,
		}
	}

	if parsed.Error == "" {
		// 4xx with no OAuth error body — a gateway, rate limiter, or
		// reverse proxy is most likely speaking, not the IdP. Treat as
		// retryable; if the IdP itself is the source, repeated bodyless
		// 4xx attempts will eventually be ridden out by backoff
		// exhaustion.
		return &refreshError{
			Stage:      refreshStageHTTP,
			StatusCode: status,
			Cause:      fmt.Errorf("token endpoint http %d", status),
			Retryable:  true,
		}
	}

	return &refreshError{
		Stage:      refreshStageOAuth,
		Code:       parsed.Error,
		StatusCode: status,
		Cause:      fmt.Errorf("token endpoint rejected credential: %s: %s", parsed.Error, parsed.ErrorDescription),
		Retryable:  false,
	}
}

// errorResponse is the RFC 6749 5.2 error body shape.
type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorURI         string `json:"error_uri"`
}

