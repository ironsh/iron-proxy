package controlplane

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
)

// Credential holds the proxy's persistent identity with the control plane.
type Credential struct {
	ProxyID string `json:"proxy_id"`
	Secret  []byte `json:"secret"`
}

// SyncResponse is the parsed response from the sync endpoint.
type SyncResponse struct {
	ConfigHash  string          `json:"config_hash"`
	Rules       json.RawMessage `json:"rules"`
	Secrets     json.RawMessage `json:"secrets"`
	IngestToken string          `json:"ingest_token"`
}

// Client talks to the iron.sh control plane REST API.
type Client struct {
	baseURL    string
	httpClient *http.Client
	cred       *Credential
	logger     *slog.Logger
}

// RegisterMetadata contains information sent during registration.
type RegisterMetadata struct {
	Version string
}

// NewClient creates a control plane client without authentication.
// Call SetCredential after registration to enable HMAC signing.
func NewClient(baseURL string, logger *slog.Logger) *Client {
	return &Client{
		baseURL:    baseURL,
		httpClient: &http.Client{},
		logger:     logger,
	}
}

// SetCredential configures the client with a credential and enables HMAC signing
// on all subsequent requests.
func (c *Client) SetCredential(cred *Credential) {
	c.cred = cred
	c.httpClient = &http.Client{
		Transport: &hmacTransport{
			inner: http.DefaultTransport,
			cred:  cred,
		},
	}
}

// Credential returns the client's current credential, or nil if not set.
func (c *Client) GetCredential() *Credential {
	return c.cred
}

type registerRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
	Hostname        string `json:"hostname"`
	Version         string `json:"version"`
	Platform        string `json:"platform"`
}

type registerResponse struct {
	ProxyID string `json:"proxy_id"`
	Secret  string `json:"secret"`
}

// Register exchanges an enrollment token for a persistent credential.
// Retries up to 5 times with exponential backoff on transient errors.
func (c *Client) Register(ctx context.Context, token string, meta RegisterMetadata) (*Credential, error) {
	return WithRetry(ctx, 5, func() (*Credential, error) {
		return c.register(ctx, token, meta)
	})
}

func (c *Client) register(ctx context.Context, token string, meta RegisterMetadata) (*Credential, error) {
	hostname, _ := os.Hostname()

	body := registerRequest{
		EnrollmentToken: token,
		Hostname:        hostname,
		Version:         meta.Version,
		Platform:        detectPlatform(),
	}

	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshaling register request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/proxies/enroll", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("building register request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading register response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, parseAPIError(resp.StatusCode, respBody)
	}

	var rr registerResponse
	if err := json.Unmarshal(respBody, &rr); err != nil {
		return nil, fmt.Errorf("parsing register response: %w", err)
	}

	secret, err := hex.DecodeString(rr.Secret)
	if err != nil {
		return nil, fmt.Errorf("decoding register secret: %w", err)
	}

	return &Credential{
		ProxyID: rr.ProxyID,
		Secret:  secret,
	}, nil
}

type syncRequest struct {
	ConfigHash string `json:"config_hash"`
}

// Sync polls the control plane for config updates.
// Retries indefinitely with exponential backoff on transient errors.
func (c *Client) Sync(ctx context.Context, configHash string) (*SyncResponse, error) {
	return WithRetry(ctx, 0, func() (*SyncResponse, error) {
		return c.sync(ctx, configHash)
	})
}

func (c *Client) sync(ctx context.Context, configHash string) (*SyncResponse, error) {
	data, err := json.Marshal(syncRequest{ConfigHash: configHash})
	if err != nil {
		return nil, fmt.Errorf("marshaling sync request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/proxy/sync", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("building sync request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading sync response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp.StatusCode, respBody)
	}

	var sr SyncResponse
	if err := json.Unmarshal(respBody, &sr); err != nil {
		return nil, fmt.Errorf("parsing sync response: %w", err)
	}

	return &sr, nil
}

type apiErrorResponse struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func parseAPIError(statusCode int, body []byte) *APIError {
	var er apiErrorResponse
	if err := json.Unmarshal(body, &er); err != nil || er.Error.Code == "" {
		return &APIError{
			StatusCode: statusCode,
			Code:       ErrorCode(fmt.Sprintf("http_%d", statusCode)),
			Detail:     string(body),
		}
	}
	return &APIError{
		StatusCode: statusCode,
		Code:       ErrorCode(er.Error.Code),
		Detail:     er.Error.Message,
	}
}

func detectPlatform() string {
	if os.Getenv("ECS_CONTAINER_METADATA_URI") != "" {
		return "ecs"
	}
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return "k8s"
	}
	if os.Getenv("GITHUB_ACTIONS") != "" {
		return "gha"
	}
	return "bare"
}
