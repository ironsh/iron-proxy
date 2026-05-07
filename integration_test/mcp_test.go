package integration_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestMCPPolicy boots a fake MCP server and an iron-proxy with an mcp policy
// configured, then exercises the full request/response interception path:
// allowed tools/call, denied tools/call (returning a JSON-RPC error envelope
// without reaching upstream), and tools/list response filtering over both
// JSON and SSE responses.
func TestMCPPolicy(t *testing.T) {
	type upstreamHit struct {
		method string
		body   string
	}
	hits := make(chan upstreamHit, 8)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		hits <- upstreamHit{method: r.Method, body: string(body)}

		// Inspect what was asked: tools/list returns a list of tools.
		// tools/call returns a generic ok result.
		var msg struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.Unmarshal([]byte(body), &msg)

		// Switch on a hint header so the test can ask for SSE responses.
		// Write errors are ignored: this is a fixture HTTP handler running in
		// a background goroutine, and a broken client connection cannot be
		// surfaced from here anyway.
		if r.Header.Get("X-Test-Response") == "sse" {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			flusher, _ := w.(http.Flusher)
			payload := buildToolsListPayload(msg.ID)
			_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", payload)
			if flusher != nil {
				flusher.Flush()
			}
			_, _ = fmt.Fprint(w, ": keepalive\n\n")
			if flusher != nil {
				flusher.Flush()
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		switch msg.Method {
		case "tools/list":
			_, _ = w.Write([]byte(buildToolsListPayload(msg.ID)))
		default:
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"ok":true}}`, idOrNull(msg.ID))
		}
	}))
	t.Cleanup(upstream.Close)

	cfgPath := renderConfig(t, t.TempDir(), "mcp_pipeline.yaml", nil)
	proxy := startProxy(t, proxyBinary(t), cfgPath, nil)

	upstreamHost := upstream.Listener.Addr().String()

	doReq := func(t *testing.T, body string, headers map[string]string) *http.Response {
		t.Helper()
		req, err := http.NewRequest("POST", "http://"+proxy.HTTPAddr+"/mcp", strings.NewReader(body))
		require.NoError(t, err)
		req.Host = upstreamHost
		req.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		return resp
	}

	drainHits := func() {
		for {
			select {
			case <-hits:
			default:
				return
			}
		}
	}

	t.Run("allowed_tools_call_reaches_upstream", func(t *testing.T) {
		drainHits()
		resp := doReq(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_repositories","arguments":{"q":"foo"}}}`, nil)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		require.Equal(t, http.StatusOK, resp.StatusCode)

		var msg struct {
			Result struct {
				OK bool `json:"ok"`
			} `json:"result"`
			Error any `json:"error"`
		}
		require.NoError(t, json.Unmarshal(body, &msg))
		require.True(t, msg.Result.OK)
		require.Nil(t, msg.Error)

		select {
		case hit := <-hits:
			require.Contains(t, hit.body, "search_repositories")
		default:
			t.Fatal("upstream was not reached")
		}
	})

	t.Run("denied_tools_call_returns_json_rpc_error", func(t *testing.T) {
		drainHits()
		resp := doReq(t, `{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"delete_repo","arguments":{}}}`, nil)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		require.Equal(t, http.StatusOK, resp.StatusCode)
		var msg struct {
			ID    json.RawMessage `json:"id"`
			Error *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		require.NoError(t, json.Unmarshal(body, &msg))
		require.NotNil(t, msg.Error)
		require.Equal(t, -32001, msg.Error.Code)
		require.Equal(t, "blocked by iron-proxy policy", msg.Error.Message)
		require.Equal(t, "42", string(msg.ID))

		select {
		case hit := <-hits:
			t.Fatalf("upstream should not have been reached; got hit %+v", hit)
		default:
		}
	})

	t.Run("argument_constraint_denies", func(t *testing.T) {
		drainHits()
		resp := doReq(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_issue","arguments":{"owner":"someoneelse"}}}`, nil)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		var msg struct {
			Error *struct {
				Code int `json:"code"`
			} `json:"error"`
		}
		require.NoError(t, json.Unmarshal(body, &msg))
		require.NotNil(t, msg.Error)
		require.Equal(t, -32001, msg.Error.Code)
	})

	t.Run("tools_list_json_response_filtered", func(t *testing.T) {
		drainHits()
		resp := doReq(t, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, nil)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		var msg struct {
			Result struct {
				Tools []map[string]any `json:"tools"`
			} `json:"result"`
		}
		require.NoError(t, json.Unmarshal(body, &msg))

		names := make([]string, 0, len(msg.Result.Tools))
		for _, t := range msg.Result.Tools {
			if n, ok := t["name"].(string); ok {
				names = append(names, n)
			}
		}
		require.ElementsMatch(t, []string{"search_repositories", "create_issue"}, names,
			"hidden_tool should be filtered from response")
	})

	t.Run("tools_list_sse_response_filtered", func(t *testing.T) {
		drainHits()
		resp := doReq(t, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, map[string]string{"X-Test-Response": "sse"})
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		out := string(body)
		require.Contains(t, out, "search_repositories")
		require.Contains(t, out, "create_issue")
		require.NotContains(t, out, "hidden_tool")
		require.Contains(t, out, ": keepalive")
	})
}

func buildToolsListPayload(id json.RawMessage) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"search_repositories"},{"name":"hidden_tool"},{"name":"create_issue"}]}}`, idOrNull(id))
}

func idOrNull(id json.RawMessage) string {
	if len(id) == 0 {
		return "null"
	}
	return string(id)
}
