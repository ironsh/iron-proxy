package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/allowlist"
)

const (
	rebindHost      = "safecompany.test"
	allowedPublicIP = "203.0.113.10"
	reboundLocalIP  = "127.0.0.1"
)

type staticLookupResolver struct {
	calls atomic.Int64
	addrs []string
}

func (r *staticLookupResolver) LookupHost(_ context.Context, _ string) ([]string, error) {
	r.calls.Add(1)
	return r.addrs, nil
}

func TestAllowlistedDomainDoesNotPermitPrivateReboundAddress(t *testing.T) {
	var backendHits atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		backendHits.Add(1)
		_, _ = io.WriteString(w, "metadata-like backend reached")
	}))
	defer backend.Close()
	_, backendPort, err := net.SplitHostPort(backend.Listener.Addr().String())
	require.NoError(t, err)

	al, err := allowlist.New([]string{rebindHost}, nil, &staticLookupResolver{})
	require.NoError(t, err)
	p := newRebindingTestProxy(t, al, startTestResolver(t, rebindHost, reboundLocalIP))

	req := httptest.NewRequest(http.MethodGet, "http://"+net.JoinHostPort(rebindHost, backendPort)+"/latest/meta-data/", nil)
	req.Host = net.JoinHostPort(rebindHost, backendPort)
	rec := httptest.NewRecorder()

	p.handleHTTP(rec, req)

	require.NotEqual(t, http.StatusOK, rec.Code)
	require.Equal(t, int64(0), backendHits.Load(), "allowlisted hostnames must not be able to rebind to private or loopback addresses")
}

func TestCIDRAllowlistPinsCheckedAddressBeforeDial(t *testing.T) {
	var backendHits atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		backendHits.Add(1)
		_, _ = io.WriteString(w, "rebound backend reached")
	}))
	defer backend.Close()
	_, backendPort, err := net.SplitHostPort(backend.Listener.Addr().String())
	require.NoError(t, err)

	policyResolver := &staticLookupResolver{addrs: []string{allowedPublicIP}}
	al, err := allowlist.New(nil, []string{"203.0.113.0/24"}, policyResolver)
	require.NoError(t, err)
	p := newRebindingTestProxy(t, al, startTestResolver(t, rebindHost, reboundLocalIP))

	req := httptest.NewRequest(http.MethodGet, "http://"+net.JoinHostPort(rebindHost, backendPort)+"/", nil)
	req.Host = net.JoinHostPort(rebindHost, backendPort)
	rec := httptest.NewRecorder()

	p.handleHTTP(rec, req)

	require.Equal(t, int64(1), policyResolver.calls.Load(), "CIDR allowlist should resolve once for policy")
	require.NotEqual(t, http.StatusOK, rec.Code)
	require.Equal(t, int64(0), backendHits.Load(), "proxy must dial the checked address, not re-resolve the hostname to a different address")
}

func TestTransformCheckedAddressIsUsedForDial(t *testing.T) {
	var backendHits atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		backendHits.Add(1)
		_, _ = io.WriteString(w, "rebound backend reached")
	}))
	defer backend.Close()
	_, backendPort, err := net.SplitHostPort(backend.Listener.Addr().String())
	require.NoError(t, err)

	_, allowedNet, err := net.ParseCIDR("203.0.113.0/24")
	require.NoError(t, err)
	policyResolver := &staticLookupResolver{addrs: []string{allowedPublicIP}}
	policyTransform := &resolvingPolicyTransform{
		resolver: policyResolver,
		allowed:  allowedNet,
	}
	p := newRebindingTestProxy(t, policyTransform, startTestResolver(t, rebindHost, reboundLocalIP))

	req := httptest.NewRequest(http.MethodGet, "http://"+net.JoinHostPort(rebindHost, backendPort)+"/", nil)
	req.Host = net.JoinHostPort(rebindHost, backendPort)
	rec := httptest.NewRecorder()

	p.handleHTTP(rec, req)

	require.Equal(t, int64(1), policyResolver.calls.Load(), "policy transform should resolve once for its decision")
	require.NotEqual(t, http.StatusOK, rec.Code)
	require.Equal(t, int64(0), backendHits.Load(), "proxy must not discard the address approved by a resolving transform and re-resolve the hostname")
}

func TestWebSocketTransformCheckedAddressIsUsedForDial(t *testing.T) {
	var backendHits atomic.Int64
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = backendLn.Close() })
	_, backendPort, err := net.SplitHostPort(backendLn.Addr().String())
	require.NoError(t, err)

	go func() {
		conn, err := backendLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		backendHits.Add(1)
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err == nil && req.Body != nil {
			_ = req.Body.Close()
		}
		_, _ = fmt.Fprint(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	}()

	_, allowedNet, err := net.ParseCIDR("203.0.113.0/24")
	require.NoError(t, err)
	policyResolver := &staticLookupResolver{addrs: []string{allowedPublicIP}}
	policyTransform := &resolvingPolicyTransform{
		resolver: policyResolver,
		allowed:  allowedNet,
	}
	proxyAddr := startRebindingHTTPProxy(t, newRebindingTestProxy(t, policyTransform, nil))

	clientConn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	require.NoError(t, err)
	defer clientConn.Close()
	_, err = fmt.Fprintf(clientConn, "GET /socket HTTP/1.1\r\nHost: localhost:%s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", backendPort)
	require.NoError(t, err)

	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, int64(1), policyResolver.calls.Load(), "policy transform should resolve once for its decision")
	require.NotEqual(t, http.StatusSwitchingProtocols, resp.StatusCode)
	require.Equal(t, int64(0), backendHits.Load(), "websocket proxying must not discard the address approved by a resolving transform and re-resolve the hostname")
}

func newRebindingTestProxy(t *testing.T, tform transform.Transformer, resolver *net.Resolver) *Proxy {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pipeline := transform.NewPipeline([]transform.Transformer{tform}, transform.BodyLimits{}, logger)
	return New(Options{
		Pipeline: transform.NewPipelineHolder(pipeline),
		Resolver: resolver,
		Logger:   logger,
	})
}

func startRebindingHTTPProxy(t *testing.T, p *Proxy) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &http.Server{Handler: http.HandlerFunc(p.handleHTTP)}
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	})

	return ln.Addr().String()
}

func startTestResolver(t *testing.T, host, ip string) *net.Resolver {
	t.Helper()

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &mdns.Server{
		PacketConn: packetConn,
		Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
			resp := new(mdns.Msg)
			resp.SetReply(r)
			for _, q := range r.Question {
				if q.Qtype != mdns.TypeA || q.Name != mdns.Fqdn(host) {
					continue
				}
				resp.Answer = append(resp.Answer, &mdns.A{
					Hdr: mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 1},
					A:   net.ParseIP(ip).To4(),
				})
			}
			_ = w.WriteMsg(resp)
		}),
	}

	go func() {
		_ = server.ActivateAndServe()
	}()
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.ShutdownContext(shutdownCtx)
	})

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: time.Second}
			return dialer.DialContext(ctx, "udp", packetConn.LocalAddr().String())
		},
	}
}

type resolvingPolicyTransform struct {
	resolver *staticLookupResolver
	allowed  *net.IPNet
}

func (t *resolvingPolicyTransform) Name() string { return "resolving-policy" }

func (t *resolvingPolicyTransform) TransformRequest(ctx context.Context, _ *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	addrs, err := t.resolver.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if t.allowed.Contains(net.ParseIP(addr)) {
			return &transform.TransformResult{Action: transform.ActionContinue}, nil
		}
	}
	return &transform.TransformResult{Action: transform.ActionReject}, nil
}

func (t *resolvingPolicyTransform) TransformResponse(context.Context, *transform.TransformContext, *http.Request, *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}
