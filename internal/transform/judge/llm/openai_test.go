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
)

func TestOpenAI_HappyPath(t *testing.T) {
	t.Setenv("OPENAI_TEST_KEY", "sk-test-key")

	var gotReq openaiRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/chat/completions", r.URL.Path)
		require.Equal(t, "Bearer sk-test-key", r.Header.Get("Authorization"))
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &gotReq))

		resp := openaiResponse{
			Model: "gpt-test",
			Choices: []openaiChoice{
				{Message: openaiMessage{Role: "assistant", Content: `{"decision":"ALLOW","reason":"ok"}`}},
			},
			Usage: openaiUsage{PromptTokens: 42, CompletionTokens: 7},
		}
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	defer srv.Close()

	cfg := decodeYAML(t, `
type: openai
model: gpt-test
api_key_env: OPENAI_TEST_KEY
base_url: `+srv.URL+`
max_tokens: 128
`)

	adapter, err := newOpenAI(cfg, slog.Default())
	require.NoError(t, err)
	require.Equal(t, "openai", adapter.Name())
	require.Equal(t, "gpt-test", adapter.Model())

	resp, err := adapter.Complete(context.Background(), Request{
		SystemPrompt: "be a judge",
		UserContent:  "envelope json",
	})
	require.NoError(t, err)
	require.Equal(t, `{"decision":"ALLOW","reason":"ok"}`, resp.RawOutput)
	require.Equal(t, "gpt-test", resp.Model)
	require.Equal(t, 42, resp.InputTokens)
	require.Equal(t, 7, resp.OutputTokens)

	require.Equal(t, "gpt-test", gotReq.Model)
	require.Equal(t, 128, gotReq.MaxCompletionTokens)
	require.Len(t, gotReq.Messages, 2)
	require.Equal(t, "system", gotReq.Messages[0].Role)
	require.Equal(t, "be a judge", gotReq.Messages[0].Content)
	require.Equal(t, "user", gotReq.Messages[1].Role)
	require.Equal(t, "envelope json", gotReq.Messages[1].Content)
}

func TestOpenAI_EmptyChoicesFails(t *testing.T) {
	t.Setenv("OPENAI_TEST_KEY", "sk-test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model":"gpt-test","choices":[],"usage":{}}`))
	}))
	defer srv.Close()

	cfg := decodeYAML(t, `
type: openai
model: gpt-test
api_key_env: OPENAI_TEST_KEY
base_url: `+srv.URL+`
`)
	adapter, err := newOpenAI(cfg, slog.Default())
	require.NoError(t, err)

	_, err = adapter.Complete(context.Background(), Request{SystemPrompt: "x", UserContent: "y"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no choices")
}

func TestOpenAI_APIError4xx(t *testing.T) {
	t.Setenv("OPENAI_TEST_KEY", "sk-test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"rate limited"}}`))
	}))
	defer srv.Close()

	cfg := decodeYAML(t, `
type: openai
model: gpt-test
api_key_env: OPENAI_TEST_KEY
base_url: `+srv.URL+`
`)
	adapter, err := newOpenAI(cfg, slog.Default())
	require.NoError(t, err)

	_, err = adapter.Complete(context.Background(), Request{SystemPrompt: "x", UserContent: "y"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "429")
}

func TestOpenAI_MissingAPIKeyEnvFailsFactory(t *testing.T) {
	cfg := decodeYAML(t, `
type: openai
model: gpt-test
api_key_env: DEFINITELY_NOT_SET_OPENAI_67890
`)
	_, err := newOpenAI(cfg, slog.Default())
	require.Error(t, err)
	require.Contains(t, err.Error(), "DEFINITELY_NOT_SET_OPENAI_67890")
}

func TestOpenAI_MissingModelFailsFactory(t *testing.T) {
	cfg := decodeYAML(t, `
type: openai
api_key_env: OPENAI_TEST_KEY
`)
	t.Setenv("OPENAI_TEST_KEY", "x")
	_, err := newOpenAI(cfg, slog.Default())
	require.Error(t, err)
	require.Contains(t, err.Error(), "model is required")
}

func TestOpenAI_ContextCancellationReturnsError(t *testing.T) {
	t.Setenv("OPENAI_TEST_KEY", "sk-test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(5 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	cfg := decodeYAML(t, `
type: openai
model: gpt-test
api_key_env: OPENAI_TEST_KEY
base_url: `+srv.URL+`
`)
	adapter, err := newOpenAI(cfg, slog.Default())
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = adapter.Complete(ctx, Request{SystemPrompt: "x", UserContent: "y"})
	require.Error(t, err)
}

func TestAdapterFactory_OpenAI(t *testing.T) {
	t.Setenv("OPENAI_TEST_KEY", "sk-test")
	cfg := decodeYAML(t, `
type: openai
model: gpt-test
api_key_env: OPENAI_TEST_KEY
`)
	a, err := NewAdapter("openai", cfg, slog.Default())
	require.NoError(t, err)
	require.Equal(t, "openai", a.Name())
}
