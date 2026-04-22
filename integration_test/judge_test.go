package integration_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestJudgeAnthropic exercises the judge transform's path-based policy
// against the real Anthropic API. /allowed passes, /denied is rejected.
func TestJudgeAnthropic(t *testing.T) {
	f := setupJudgeFixture(t, "judge_pipeline.yaml")

	t.Run("allow_decision_passes_through", func(t *testing.T) {
		resp := f.do(t, "GET", "/allowed", "")
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		require.Equal(t, http.StatusOK, resp.StatusCode, "/allowed should reach upstream; body=%q", string(body))
		require.Equal(t, "/allowed", f.expectHit(t).path)
	})

	t.Run("deny_decision_returns_403", func(t *testing.T) {
		resp := f.do(t, "GET", "/denied", "")
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)

		require.Equal(t, http.StatusForbidden, resp.StatusCode, "/denied should be rejected by the judge")
		f.expectNoHit(t)
	})
}

// TestJudgeAnthropicBody verifies the judge inspects the request body in its
// envelope. The policy denies any request whose body mentions "banana".
func TestJudgeAnthropicBody(t *testing.T) {
	f := setupJudgeFixture(t, "judge_body.yaml")

	t.Run("clean_body_allowed", func(t *testing.T) {
		resp := f.do(t, "POST", "/submit", "I would like to order some apples and pears.")
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)

		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Contains(t, f.expectHit(t).body, "apples")
	})

	t.Run("banana_body_denied", func(t *testing.T) {
		resp := f.do(t, "POST", "/submit", "Please send three bananas to my address.")
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)

		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		f.expectNoHit(t)
	})
}

type upstreamHit struct {
	path string
	body string
}

type judgeFixture struct {
	proxyAddr    string
	upstreamHost string
	hits         chan upstreamHit
}

// setupJudgeFixture boots a local upstream and an iron-proxy instance
// configured from the named testdata template. It skips the test if
// ANTHROPIC_API_KEY is unset so local runs without the secret pass cleanly.
func setupJudgeFixture(t *testing.T, configTemplate string) *judgeFixture {
	t.Helper()
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		t.Skip("ANTHROPIC_API_KEY not set; skipping real-LLM judge integration test")
	}

	hits := make(chan upstreamHit, 8)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		hits <- upstreamHit{path: r.URL.Path, body: string(body)}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "upstream-ok")
	}))
	t.Cleanup(upstream.Close)

	cfgPath := renderConfig(t, t.TempDir(), configTemplate, nil)
	proxy := startProxy(t, proxyBinary(t), cfgPath, []string{"ANTHROPIC_API_KEY=" + apiKey})

	return &judgeFixture{
		proxyAddr:    proxy.HTTPAddr,
		upstreamHost: upstream.Listener.Addr().String(),
		hits:         hits,
	}
}

func (f *judgeFixture) do(t *testing.T, method, path, body string) *http.Response {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, "http://"+f.proxyAddr+path, r)
	require.NoError(t, err)
	req.Host = f.upstreamHost
	if body != "" {
		req.Header.Set("Content-Type", "text/plain")
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func (f *judgeFixture) expectHit(t *testing.T) upstreamHit {
	t.Helper()
	select {
	case hit := <-f.hits:
		return hit
	default:
		t.Fatal("upstream was not reached")
		return upstreamHit{}
	}
}

func (f *judgeFixture) expectNoHit(t *testing.T) {
	t.Helper()
	select {
	case hit := <-f.hits:
		t.Fatalf("upstream should not have been reached; got hit %+v", hit)
	default:
	}
}
