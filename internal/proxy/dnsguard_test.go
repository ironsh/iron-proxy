package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/dnsguard"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/allowlist"
)

// TestUpstreamDenyGuard_HTTP confirms the HTTP/HTTPS transport's dialer
// rejects upstream connections whose resolved address falls inside a denied
// CIDR. The allowlist is permissive ("*"), so the only thing that can stop
// the request is the dial-time guard.
func TestUpstreamDenyGuard_HTTP(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "from upstream")
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	build := func(t *testing.T, denyCIDRs []string) (proxyHTTPAddr string, audits func() []transform.PipelineResult) {
		t.Helper()
		al, err := allowlist.New([]string{"*"}, nil, &staticResolver{})
		require.NoError(t, err)
		pipeline := transform.NewPipeline([]transform.Transformer{al}, transform.BodyLimits{}, logger)

		var mu sync.Mutex
		var results []transform.PipelineResult
		pipeline.SetAuditFunc(func(r *transform.PipelineResult) {
			mu.Lock()
			results = append(results, *r)
			mu.Unlock()
		})

		guard, err := dnsguard.New(denyCIDRs)
		require.NoError(t, err)

		p := New(Options{
			HTTPAddr: "127.0.0.1:0",
			Pipeline: transform.NewPipelineHolder(pipeline),
			Guard:    guard,
			Logger:   logger,
		})

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		go func() { _ = p.httpServer.Serve(ln) }()
		t.Cleanup(func() { _ = p.httpServer.Close() })

		return ln.Addr().String(), func() []transform.PipelineResult {
			mu.Lock()
			defer mu.Unlock()
			out := make([]transform.PipelineResult, len(results))
			copy(out, results)
			return out
		}
	}

	t.Run("denied loopback returns 502", func(t *testing.T) {
		proxyAddr, _ := build(t, []string{"127.0.0.0/8"})
		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr}),
			},
			Timeout: 5 * time.Second,
		}

		resp, err := client.Get(upstream.URL + "/test")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusBadGateway, resp.StatusCode)
	})

	t.Run("empty deny list permits", func(t *testing.T) {
		proxyAddr, _ := build(t, nil)
		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr}),
			},
			Timeout: 5 * time.Second,
		}

		resp, err := client.Get(upstream.URL + "/test")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		require.Equal(t, "from upstream", string(body))
	})

	t.Run("guard records audit with err", func(t *testing.T) {
		proxyAddr, audits := build(t, []string{"127.0.0.0/8"})
		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr}),
			},
			Timeout: 5 * time.Second,
		}

		resp, err := client.Get(upstream.URL + "/test")
		require.NoError(t, err)
		defer resp.Body.Close()

		records := audits()
		require.Len(t, records, 1)
		require.NotNil(t, records[0].Err)
		require.True(t, dnsguard.IsDenyError(records[0].Err))
	})

	// Sanity: confirm we actually hit the dial path. The upstream listener
	// must be on loopback for the deny test to be meaningful.
	require.Equal(t, "127.0.0.1", upstreamURL.Hostname())
}

// TestUpstreamDenyGuard_SNIPassthrough confirms the sni-only dial path also
// honors the guard.
func TestUpstreamDenyGuard_SNIPassthrough(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	upstreamAddr, _ := startEchoTLSServer(t)
	_, upstreamPort, err := net.SplitHostPort(upstreamAddr)
	require.NoError(t, err)

	al, err := allowlist.New([]string{"*"}, nil, &staticResolver{hosts: sniTestHosts})
	require.NoError(t, err)
	pipeline := transform.NewPipeline([]transform.Transformer{al}, transform.BodyLimits{}, logger)

	guard, err := dnsguard.New([]string{"127.0.0.0/8"})
	require.NoError(t, err)

	p := New(Options{
		HTTPSAddr: "127.0.0.1:0",
		TLSMode:   "sni-only",
		Pipeline:  transform.NewPipelineHolder(pipeline),
		Guard:     guard,
		Logger:    logger,
	})
	p.sniUpstreamPort = upstreamPort

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleSNIPassthrough(conn)
		}
	}()

	// Connect raw TCP, send a TLS ClientHello with SNI=localhost. The dialer
	// will resolve localhost → 127.0.0.1 and the guard will refuse.
	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
	})
	defer tlsConn.Close()

	// Handshake should fail because the proxy refuses to dial upstream and
	// closes the connection.
	require.Error(t, tlsConn.HandshakeContext(context.Background()))
}
