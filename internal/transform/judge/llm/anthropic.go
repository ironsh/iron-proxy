package llm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	defaultAnthropicBaseURL = "https://api.anthropic.com"
	defaultMaxTokens        = 256
	anthropicVersion        = "2023-06-01"
)

type anthropicConfig struct {
	Model     string `yaml:"model"`
	APIKeyEnv string `yaml:"api_key_env"`
	BaseURL   string `yaml:"base_url"`
	MaxTokens int    `yaml:"max_tokens"`
}

type anthropicAdapter struct {
	model      string
	apiKey     string
	baseURL    string
	maxTokens  int
	httpClient *http.Client
	logger     *slog.Logger
}

func newAnthropic(cfg yaml.Node, logger *slog.Logger) (*anthropicAdapter, error) {
	var c anthropicConfig
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing anthropic config: %w", err)
	}
	if c.Model == "" {
		return nil, fmt.Errorf("anthropic provider: model is required")
	}
	if c.APIKeyEnv == "" {
		return nil, fmt.Errorf("anthropic provider: api_key_env is required")
	}
	apiKey := os.Getenv(c.APIKeyEnv)
	if apiKey == "" {
		return nil, fmt.Errorf("anthropic provider: env var %q is empty", c.APIKeyEnv)
	}
	baseURL := c.BaseURL
	if baseURL == "" {
		baseURL = defaultAnthropicBaseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")
	maxTokens := c.MaxTokens
	if maxTokens <= 0 {
		maxTokens = defaultMaxTokens
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &anthropicAdapter{
		model:      c.Model,
		apiKey:     apiKey,
		baseURL:    baseURL,
		maxTokens:  maxTokens,
		httpClient: &http.Client{Transport: buildTransport()},
		logger:     logger,
	}, nil
}

// buildTransport mirrors the proxy's upstream-transport timeouts so a stuck
// Anthropic endpoint can't hold a goroutine past the per-call context timeout.
func buildTransport() *http.Transport {
	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

func (a *anthropicAdapter) Name() string  { return "anthropic" }
func (a *anthropicAdapter) Model() string { return a.model }

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type anthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type anthropicResponse struct {
	Content []anthropicContentBlock `json:"content"`
	Model   string                  `json:"model"`
	Usage   anthropicUsage          `json:"usage"`
}

func (a *anthropicAdapter) Complete(ctx context.Context, req Request) (Response, error) {
	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = a.maxTokens
	}

	body, err := json.Marshal(anthropicRequest{
		Model:     a.model,
		MaxTokens: maxTokens,
		System:    req.SystemPrompt,
		Messages: []anthropicMessage{
			{Role: "user", Content: req.UserContent},
		},
	})
	if err != nil {
		return Response{}, fmt.Errorf("marshaling anthropic request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		return Response{}, fmt.Errorf("building anthropic request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", a.apiKey)
	httpReq.Header.Set("anthropic-version", anthropicVersion)

	httpResp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("calling anthropic: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return Response{}, fmt.Errorf("reading anthropic response: %w", err)
	}

	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return Response{}, fmt.Errorf("anthropic returned %d: %s", httpResp.StatusCode, truncateForError(respBody))
	}

	var parsed anthropicResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return Response{}, fmt.Errorf("unmarshaling anthropic response: %w", err)
	}

	var raw strings.Builder
	for _, block := range parsed.Content {
		if block.Type == "text" {
			raw.WriteString(block.Text)
		}
	}

	model := parsed.Model
	if model == "" {
		model = a.model
	}

	return Response{
		RawOutput:    raw.String(),
		Model:        model,
		InputTokens:  parsed.Usage.InputTokens,
		OutputTokens: parsed.Usage.OutputTokens,
	}, nil
}

func truncateForError(b []byte) string {
	const max = 512
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "..."
}
