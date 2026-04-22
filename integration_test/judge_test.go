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

// TestJudgeAnthropic exercises the judge transform against the real Anthropic
// API. It is gated on ANTHROPIC_API_KEY being set so local runs without the
// key are skipped; CI provides the key via repository secrets.
func TestJudgeAnthropic(t *testing.T) {
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		t.Skip("ANTHROPIC_API_KEY not set; skipping real-LLM judge integration test")
	}

	tmpDir := t.TempDir()
	binary := proxyBinary(t)

	upstreamHits := make(chan string, 8)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits <- r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "upstream-ok")
	}))
	defer upstream.Close()
	upstreamHost := upstream.Listener.Addr().String()

	cfgPath := renderConfig(t, tmpDir, "judge_pipeline.yaml", nil)
	proxy := startProxy(t, binary, cfgPath, []string{"ANTHROPIC_API_KEY=" + apiKey})

	t.Run("allow_decision_passes_through", func(t *testing.T) {
		req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/allowed", proxy.HTTPAddr), nil)
		require.NoError(t, err)
		req.Host = upstreamHost

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, resp.StatusCode, "/allowed should pass the judge and reach upstream; body=%q", string(body))
		select {
		case hit := <-upstreamHits:
			require.Equal(t, "/allowed", hit)
		default:
			t.Fatal("upstream was not reached on allowed request")
		}
	})

	t.Run("deny_decision_returns_403", func(t *testing.T) {
		req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/denied", proxy.HTTPAddr), nil)
		require.NoError(t, err)
		req.Host = upstreamHost

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)

		require.Equal(t, http.StatusForbidden, resp.StatusCode, "/denied should be rejected by the judge")
		select {
		case hit := <-upstreamHits:
			t.Fatalf("upstream should not have been reached on denied request; got hit for %q", hit)
		default:
		}
	})
}

// TestJudgeAnthropicBody verifies the judge inspects the request body in its
// envelope. The policy denies any request whose body mentions "banana".
func TestJudgeAnthropicBody(t *testing.T) {
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		t.Skip("ANTHROPIC_API_KEY not set; skipping real-LLM judge integration test")
	}

	tmpDir := t.TempDir()
	binary := proxyBinary(t)

	upstreamHits := make(chan string, 8)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		upstreamHits <- string(body)
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "upstream-ok")
	}))
	defer upstream.Close()
	upstreamHost := upstream.Listener.Addr().String()

	cfgPath := renderConfig(t, tmpDir, "judge_body.yaml", nil)
	proxy := startProxy(t, binary, cfgPath, []string{"ANTHROPIC_API_KEY=" + apiKey})

	post := func(t *testing.T, body string) *http.Response {
		t.Helper()
		req, err := http.NewRequest("POST", fmt.Sprintf("http://%s/submit", proxy.HTTPAddr), strings.NewReader(body))
		require.NoError(t, err)
		req.Host = upstreamHost
		req.Header.Set("Content-Type", "text/plain")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		return resp
	}

	t.Run("clean_body_allowed", func(t *testing.T) {
		resp := post(t, "I would like to order some apples and pears.")
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)

		require.Equal(t, http.StatusOK, resp.StatusCode)
		select {
		case hit := <-upstreamHits:
			require.Contains(t, hit, "apples")
		default:
			t.Fatal("upstream was not reached on allowed body")
		}
	})

	t.Run("banana_body_denied", func(t *testing.T) {
		resp := post(t, "Please send three bananas to my address.")
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)

		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		select {
		case hit := <-upstreamHits:
			t.Fatalf("upstream should not have been reached on banana body; got hit with body %q", hit)
		default:
		}
	})
}
