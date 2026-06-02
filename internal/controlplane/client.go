package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
)

// SyncResponse is the parsed response from the sync endpoint.
type SyncResponse struct {
	ConfigHash  string          `json:"config_hash"`
	Rules       json.RawMessage `json:"rules"`
	Secrets     json.RawMessage `json:"secrets"`
	MCP         json.RawMessage `json:"mcp"`
	Postgres    json.RawMessage `json:"postgres"`
	IngestToken string          `json:"ingest_token"`
}

// Client talks to the iron.sh control plane REST API. Requests are
// authenticated with a fixed bearer token issued by the control plane.
type Client struct {
	baseURL    string
	httpClient *http.Client
	logger     *slog.Logger
}

// NewClient creates a control plane client that authenticates every request
// with the given bearer token.
func NewClient(baseURL, token string, logger *slog.Logger) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Transport: &bearerTransport{
				inner: http.DefaultTransport,
				token: token,
			},
		},
		logger: logger,
	}
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/proxy/sync", bytes.NewReader(data))
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
