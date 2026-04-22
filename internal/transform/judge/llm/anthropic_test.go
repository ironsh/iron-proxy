package llm

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func decodeYAML(t *testing.T, raw string) yaml.Node {
	t.Helper()
	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(raw), &node))
	require.NotEmpty(t, node.Content)
	return *node.Content[0]
}

func TestAnthropic_HappyPath(t *testing.T) {
	t.Setenv("TEST_KEY", "sk-test-key")

	var gotReq anthropicRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/messages", r.URL.Path)
		require.Equal(t, "sk-test-key", r.Header.Get("x-api-key"))
		require.Equal(t, anthropicVersion, r.Header.Get("anthropic-version"))
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &gotReq))

		resp := anthropicResponse{
			Content: []anthropicContentBlock{
				{Type: "text", Text: `{"decision":"ALLOW","reason":"ok"}`},
			},
			Model: "claude-test",
			Usage: anthropicUsage{InputTokens: 42, OutputTokens: 7},
		}
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	defer srv.Close()

	cfg := decodeYAML(t, `
type: anthropic
model: claude-test
api_key_env: TEST_KEY
base_url: `+srv.URL+`
max_tokens: 128
`)

	adapter, err := newAnthropic(cfg, slog.Default())
	require.NoError(t, err)
	require.Equal(t, "anthropic", adapter.Name())
	require.Equal(t, "claude-test", adapter.Model())

	resp, err := adapter.Complete(context.Background(), Request{
		SystemPrompt: "be a judge",
		UserContent:  "envelope json",
	})
	require.NoError(t, err)
	require.Equal(t, `{"decision":"ALLOW","reason":"ok"}`, resp.RawOutput)
	require.Equal(t, "claude-test", resp.Model)
	require.Equal(t, 42, resp.InputTokens)
	require.Equal(t, 7, resp.OutputTokens)

	require.Equal(t, "claude-test", gotReq.Model)
	require.Equal(t, 128, gotReq.MaxTokens)
	require.Equal(t, "be a judge", gotReq.System)
	require.Len(t, gotReq.Messages, 1)
	require.Equal(t, "user", gotReq.Messages[0].Role)
	require.Equal(t, "envelope json", gotReq.Messages[0].Content)
}

func TestAnthropic_APIError4xx(t *testing.T) {
	t.Setenv("TEST_KEY", "sk-test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"rate limited"}}`))
	}))
	defer srv.Close()

	cfg := decodeYAML(t, `
type: anthropic
model: claude-test
api_key_env: TEST_KEY
base_url: `+srv.URL+`
`)
	adapter, err := newAnthropic(cfg, slog.Default())
	require.NoError(t, err)

	_, err = adapter.Complete(context.Background(), Request{SystemPrompt: "x", UserContent: "y"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "429")
}

func TestAnthropic_APIError5xx(t *testing.T) {
	t.Setenv("TEST_KEY", "sk-test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	cfg := decodeYAML(t, `
type: anthropic
model: claude-test
api_key_env: TEST_KEY
base_url: `+srv.URL+`
`)
	adapter, err := newAnthropic(cfg, slog.Default())
	require.NoError(t, err)

	_, err = adapter.Complete(context.Background(), Request{SystemPrompt: "x", UserContent: "y"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "502")
}

func TestAnthropic_MissingAPIKeyEnvFailsFactory(t *testing.T) {
	cfg := decodeYAML(t, `
type: anthropic
model: claude-test
api_key_env: DEFINITELY_NOT_SET_12345
`)
	_, err := newAnthropic(cfg, slog.Default())
	require.Error(t, err)
	require.Contains(t, err.Error(), "DEFINITELY_NOT_SET_12345")
}

func TestAnthropic_MissingModelFailsFactory(t *testing.T) {
	cfg := decodeYAML(t, `
type: anthropic
api_key_env: TEST_KEY
`)
	t.Setenv("TEST_KEY", "x")
	_, err := newAnthropic(cfg, slog.Default())
	require.Error(t, err)
	require.Contains(t, err.Error(), "model is required")
}

func TestAnthropic_ContextCancellationReturnsError(t *testing.T) {
	t.Setenv("TEST_KEY", "sk-test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(5 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	cfg := decodeYAML(t, `
type: anthropic
model: claude-test
api_key_env: TEST_KEY
base_url: `+srv.URL+`
`)
	adapter, err := newAnthropic(cfg, slog.Default())
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = adapter.Complete(ctx, Request{SystemPrompt: "x", UserContent: "y"})
	require.Error(t, err)
}

func TestAdapterFactory_UnknownType(t *testing.T) {
	_, err := NewAdapter("not-a-real-provider", yaml.Node{}, slog.Default())
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown judge provider")
}

func TestAdapterFactory_EmptyType(t *testing.T) {
	_, err := NewAdapter("", yaml.Node{}, slog.Default())
	require.Error(t, err)
	require.Contains(t, err.Error(), "type is required")
}
