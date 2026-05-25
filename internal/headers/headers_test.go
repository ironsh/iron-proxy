package headers_test

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/headers"
)

func TestSetPreservesCasingAndReplacesCanonicalVariant(t *testing.T) {
	h := http.Header{}
	h.Set("X-Api-Key", "canonical")

	headers.Set(h, "x-api-key", "wire")

	require.Equal(t, []string{"wire"}, headers.Values(h, "x-api-key"))
	require.Empty(t, headers.Values(h, "X-Api-Key"))
}

func TestAddAppendsUnderExactKey(t *testing.T) {
	h := http.Header{}
	headers.Add(h, "x-trace", "a")
	headers.Add(h, "x-trace", "b")

	require.Equal(t, []string{"a", "b"}, headers.Values(h, "x-trace"))
	require.Empty(t, headers.Values(h, "X-Trace"))
}

func TestApplyBulkSetsEveryKey(t *testing.T) {
	h := http.Header{}
	h.Set("X-Tenant", "old")

	headers.Apply(h, map[string]string{
		"x-api-key": "venue",
		"X-Tenant":  "acme",
	})

	require.Equal(t, []string{"venue"}, headers.Values(h, "x-api-key"))
	require.Equal(t, []string{"acme"}, headers.Values(h, "X-Tenant"))
}

func TestSwapRewritesValuesAndPreservesWireCasing(t *testing.T) {
	h := http.Header{}
	h["X-Api-Key"] = []string{"first", "second"}

	headers.Swap(h, "X-Api-Key", "x-api-KEY", func(v string) string {
		return v + "!"
	})

	require.Empty(t, headers.Values(h, "X-Api-Key"))
	require.Equal(t, []string{"first!", "second!"}, headers.Values(h, "x-api-KEY"))
}

func TestSwapNoopWhenHeaderAbsent(t *testing.T) {
	h := http.Header{}
	called := false
	headers.Swap(h, "X-Missing", "x-missing", func(v string) string {
		called = true
		return v
	})
	require.False(t, called)
	require.Empty(t, h)
}

func TestSwapClosureCanCaptureHit(t *testing.T) {
	h := http.Header{}
	h["X-Api-Key"] = []string{"prefix-PROXY-suffix"}

	var hit bool
	headers.Swap(h, "X-Api-Key", "x-api-key", func(v string) string {
		if strings.Contains(v, "PROXY") {
			hit = true
		}
		return strings.ReplaceAll(v, "PROXY", "REAL")
	})
	require.True(t, hit)
	require.Equal(t, []string{"prefix-REAL-suffix"}, headers.Values(h, "x-api-key"))
}

// TestWireLevelCasingPreserved confirms that headers written via Set / Add /
// Apply reach the wire with the exact casing the caller asked for. The check
// uses a raw TCP listener because httptest's server parses headers through
// textproto, which canonicalizes — only a byte-level read can verify what
// went on the wire.
func TestWireLevelCasingPreserved(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	requestLines := make(chan []string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		br := bufio.NewReader(conn)
		var lines []string
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if line == "" {
				break
			}
			lines = append(lines, line)
		}
		requestLines <- lines
		body := "ok"
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: "+strconv.Itoa(len(body))+"\r\nConnection: close\r\n\r\n"+body)
	}()

	req, err := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/", nil)
	require.NoError(t, err)
	headers.Set(req.Header, "x-api-key", "lower")
	headers.Add(req.Header, "x-trace-id", "t1")
	headers.Apply(req.Header, map[string]string{
		"X-Tenant-ID": "acme",
	})

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	select {
	case lines := <-requestLines:
		joined := strings.Join(lines, "\n")
		require.Contains(t, joined, "x-api-key: lower", "Set must preserve lowercase casing on the wire:\n%s", joined)
		require.Contains(t, joined, "x-trace-id: t1", "Add must preserve lowercase casing on the wire:\n%s", joined)
		require.Contains(t, joined, "X-Tenant-ID: acme", "Apply must preserve mixed-case casing on the wire:\n%s", joined)
	case <-time.After(2 * time.Second):
		t.Fatal("server did not receive the request")
	}
}
