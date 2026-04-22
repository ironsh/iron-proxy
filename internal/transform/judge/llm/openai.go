package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"gopkg.in/yaml.v3"
)

const defaultOpenAIBaseURL = "https://api.openai.com"

type openaiConfig struct {
	Model     string `yaml:"model"`
	APIKeyEnv string `yaml:"api_key_env"`
	BaseURL   string `yaml:"base_url"`
	MaxTokens int    `yaml:"max_tokens"`
}

type openaiAdapter struct {
	model      string
	apiKey     string
	baseURL    string
	maxTokens  int
	httpClient *http.Client
	logger     *slog.Logger
}

func newOpenAI(cfg yaml.Node, logger *slog.Logger) (*openaiAdapter, error) {
	var c openaiConfig
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing openai config: %w", err)
	}
	if c.Model == "" {
		return nil, fmt.Errorf("openai provider: model is required")
	}
	apiKey, err := resolveAPIKey("openai", c.APIKeyEnv)
	if err != nil {
		return nil, err
	}
	baseURL := c.BaseURL
	if baseURL == "" {
		baseURL = defaultOpenAIBaseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")
	maxTokens := c.MaxTokens
	if maxTokens <= 0 {
		maxTokens = defaultMaxTokens
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &openaiAdapter{
		model:      c.Model,
		apiKey:     apiKey,
		baseURL:    baseURL,
		maxTokens:  maxTokens,
		httpClient: &http.Client{Transport: buildTransport()},
		logger:     logger,
	}, nil
}

func (a *openaiAdapter) Name() string  { return "openai" }
func (a *openaiAdapter) Model() string { return a.model }

type openaiMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openaiRequest struct {
	Model               string          `json:"model"`
	MaxCompletionTokens int             `json:"max_completion_tokens"`
	Messages            []openaiMessage `json:"messages"`
}

type openaiChoice struct {
	Message openaiMessage `json:"message"`
}

type openaiUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
}

type openaiResponse struct {
	Model   string         `json:"model"`
	Choices []openaiChoice `json:"choices"`
	Usage   openaiUsage    `json:"usage"`
}

func (a *openaiAdapter) Complete(ctx context.Context, req Request) (Response, error) {
	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = a.maxTokens
	}

	body, err := json.Marshal(openaiRequest{
		Model:               a.model,
		MaxCompletionTokens: maxTokens,
		Messages: []openaiMessage{
			{Role: "system", Content: req.SystemPrompt},
			{Role: "user", Content: req.UserContent},
		},
	})
	if err != nil {
		return Response{}, fmt.Errorf("marshaling openai request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return Response{}, fmt.Errorf("building openai request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+a.apiKey)

	httpResp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("calling openai: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return Response{}, fmt.Errorf("reading openai response: %w", err)
	}

	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return Response{}, fmt.Errorf("openai returned %d: %s", httpResp.StatusCode, truncateForError(respBody))
	}

	var parsed openaiResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return Response{}, fmt.Errorf("unmarshaling openai response: %w", err)
	}

	if len(parsed.Choices) == 0 {
		return Response{}, fmt.Errorf("openai response contained no choices")
	}

	model := parsed.Model
	if model == "" {
		model = a.model
	}

	return Response{
		RawOutput:    parsed.Choices[0].Message.Content,
		Model:        model,
		InputTokens:  parsed.Usage.PromptTokens,
		OutputTokens: parsed.Usage.CompletionTokens,
	}, nil
}
