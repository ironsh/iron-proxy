package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/certcache"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func startTunnelProxy(t *testing.T, transforms []transform.Transformer) (*Proxy, string, *x509.CertPool) {
	t.Helper()

	caCert, caKey := generateTestCA(t)
	cache, err := certcache.NewFromCA(caCert, caKey, 100, 72*time.Hour)
	require.NoError(t, err)

	pipeline := transform.NewPipeline(transforms, transform.BodyLimits{}, testLogger())
	holder := transform.NewPipelineHolder(pipeline)
	p := New(Options{
		HTTPAddr:   "127.0.0.1:0",
		HTTPSAddr:  "127.0.0.1:0",
		TunnelAddr: "127.0.0.1:0",
		CertCache:  cache,
		Pipeline:   holder,
		Logger:     testLogger(),
	})

	// Start tunnel listener
	tunnelLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	tunnelAddr := tunnelLn.Addr().String()
	p.tunnelListener = tunnelLn

	go func() {
		for {
			conn, err := tunnelLn.Accept()
			if err != nil {
				return
			}
			go p.handleTunnel(conn)
		}
	}()

	t.Cleanup(func() {
		tunnelLn.Close()
		close(p.tunnelDone)
	})

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	return p, tunnelAddr, pool
}

func TestTunnel_CONNECT_HTTP(t *testing.T) {
	// Start an upstream HTTP server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Tunnel", "true")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "hello from tunnel")
	}))
	defer upstream.Close()

	_, tunnelAddr, _ := startTunnelProxy(t, nil)

	// Send CONNECT request
	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	target := upstream.Listener.Addr().String()
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	require.NoError(t, err)

	// Read 200 Connection Established
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Now send an HTTP request through the tunnel (raw tunnel, not MITM)
	_, err = fmt.Fprintf(conn, "GET /test HTTP/1.1\r\nHost: %s\r\n\r\n", target)
	require.NoError(t, err)

	resp2, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	defer resp2.Body.Close()

	require.Equal(t, http.StatusOK, resp2.StatusCode)
	require.Equal(t, "true", resp2.Header.Get("X-Tunnel"))

	body, err := io.ReadAll(resp2.Body)
	require.NoError(t, err)
	require.Equal(t, "hello from tunnel", string(body))
}

func TestTunnel_CONNECT_HTTPS_MITM(t *testing.T) {
	// Start an upstream HTTPS server
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "hello from tls tunnel")
	}))
	defer upstream.Close()

	p, tunnelAddr, caPool := startTunnelProxy(t, nil)

	// Override transport to route to the upstream
	upstreamAddr := upstream.Listener.Addr().String()
	p.transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, upstreamAddr)
		},
	}

	const fakeHost = "mitm.example.com"

	// Send CONNECT to port 443 (triggers MITM)
	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", fakeHost, fakeHost)
	require.NoError(t, err)

	// Read 200 Connection Established
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Now do TLS handshake on the tunneled connection
	tlsConn := tls.Client(conn, &tls.Config{
		RootCAs:    caPool,
		ServerName: fakeHost,
	})
	defer func() { _ = tlsConn.Close() }()

	err = tlsConn.Handshake()
	require.NoError(t, err)

	// Send HTTP request through the TLS tunnel
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/test", fakeHost), nil)
	require.NoError(t, err)

	err = req.Write(tlsConn)
	require.NoError(t, err)

	tlsBr := bufio.NewReader(tlsConn)
	resp2, err := http.ReadResponse(tlsBr, req)
	require.NoError(t, err)
	defer resp2.Body.Close()

	require.Equal(t, http.StatusOK, resp2.StatusCode)

	body, err := io.ReadAll(resp2.Body)
	require.NoError(t, err)
	require.Equal(t, "hello from tls tunnel", string(body))
}

func TestTunnel_CONNECT_MethodNotAllowed(t *testing.T) {
	_, tunnelAddr, _ := startTunnelProxy(t, nil)

	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestTunnel_SOCKS5_HTTP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Socks", "true")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "hello from socks5")
	}))
	defer upstream.Close()

	_, tunnelAddr, _ := startTunnelProxy(t, nil)

	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	upstreamHost, upstreamPortStr, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	// SOCKS5 auth negotiation: version 5, 1 method (no auth)
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)

	// Read auth response
	authResp := make([]byte, 2)
	_, err = io.ReadFull(conn, authResp)
	require.NoError(t, err)
	require.Equal(t, byte(0x05), authResp[0])
	require.Equal(t, byte(0x00), authResp[1])

	// SOCKS5 connect request: IPv4
	ip := net.ParseIP(upstreamHost).To4()
	require.NotNil(t, ip)

	var port uint16
	_, err = fmt.Sscanf(upstreamPortStr, "%d", &port)
	require.NoError(t, err)

	connectReq := []byte{0x05, 0x01, 0x00, 0x01} // ver, cmd=connect, rsv, atyp=IPv4
	connectReq = append(connectReq, ip...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, port)
	connectReq = append(connectReq, portBuf...)

	_, err = conn.Write(connectReq)
	require.NoError(t, err)

	// Read connect response
	connectResp := make([]byte, 10)
	_, err = io.ReadFull(conn, connectResp)
	require.NoError(t, err)
	require.Equal(t, byte(0x05), connectResp[0]) // version
	require.Equal(t, byte(0x00), connectResp[1]) // success

	// Now send HTTP through the tunnel
	target := upstream.Listener.Addr().String()
	_, err = fmt.Fprintf(conn, "GET /test HTTP/1.1\r\nHost: %s\r\n\r\n", target)
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "true", resp.Header.Get("X-Socks"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "hello from socks5", string(body))
}

func TestTunnel_SOCKS5_DomainName(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "domain ok")
	}))
	defer upstream.Close()

	_, tunnelAddr, _ := startTunnelProxy(t, nil)

	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	_, upstreamPortStr, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	var port uint16
	_, err = fmt.Sscanf(upstreamPortStr, "%d", &port)
	require.NoError(t, err)

	// Auth negotiation
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)
	authResp := make([]byte, 2)
	_, err = io.ReadFull(conn, authResp)
	require.NoError(t, err)

	// Connect with domain name type (0x03) pointing to 127.0.0.1
	domain := "127.0.0.1" // using IP as "domain" for test simplicity
	connectReq := []byte{0x05, 0x01, 0x00, 0x03, byte(len(domain))}
	connectReq = append(connectReq, []byte(domain)...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, port)
	connectReq = append(connectReq, portBuf...)

	_, err = conn.Write(connectReq)
	require.NoError(t, err)

	connectResp := make([]byte, 10)
	_, err = io.ReadFull(conn, connectResp)
	require.NoError(t, err)
	require.Equal(t, byte(0x00), connectResp[1]) // success

	// Send HTTP request
	target := upstream.Listener.Addr().String()
	_, err = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", target)
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestTunnel_SOCKS5_NoAuth_Required(t *testing.T) {
	_, tunnelAddr, _ := startTunnelProxy(t, nil)

	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	// Offer only username/password auth (0x02), no no-auth
	_, err = conn.Write([]byte{0x05, 0x01, 0x02})
	require.NoError(t, err)

	resp := make([]byte, 2)
	_, err = io.ReadFull(conn, resp)
	require.NoError(t, err)
	require.Equal(t, byte(0x05), resp[0])
	require.Equal(t, byte(0xFF), resp[1]) // no acceptable methods
}

func TestTunnel_TransformReject(t *testing.T) {
	// Use a transform that rejects everything
	rejecter := &rejectTransform{}

	_, tunnelAddr, _ := startTunnelProxy(t, []transform.Transformer{rejecter})

	// Test CONNECT rejection
	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\n\r\n")
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestTunnel_CONNECTHeadersAndRejectResponse(t *testing.T) {
	auth := &connectHeaderAuthTransform{}

	_, tunnelAddr, _ := startTunnelProxy(t, []transform.Transformer{auth})

	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)
	require.Equal(t, `Basic realm="proxy"`, resp.Header.Get("Proxy-Authenticate"))
	require.Equal(t, "example.com:443", auth.lastTarget)

	conn2, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn2.Close()

	_, err = fmt.Fprintf(conn2, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic ok\r\n\r\n")
	require.NoError(t, err)

	resp2, err := http.ReadResponse(bufio.NewReader(conn2), nil)
	require.NoError(t, err)
	_ = resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode)
}

func TestTunnelInfoPropagatesToInnerTransforms(t *testing.T) {
	seen := make(chan *transform.TunnelInfo, 1)
	tunnelInfoTransform := &tunnelInfoTransform{seen: seen}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	_, tunnelAddr, _ := startTunnelProxy(t, []transform.Transformer{tunnelInfoTransform})
	target := upstream.Listener.Addr().String()

	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	_, err = fmt.Fprintf(conn, "GET /test HTTP/1.1\r\nHost: %s\r\n\r\n", target)
	require.NoError(t, err)

	resp2, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	_ = resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode)

	select {
	case info := <-seen:
		require.Equal(t, target, info.Target)
		require.Equal(t, "alice", info.Annotations["user_id"])
	case <-time.After(2 * time.Second):
		t.Fatal("inner transform did not receive tunnel info")
	}
}

func TestTunnel_SOCKS5_TransformReject(t *testing.T) {
	rejecter := &rejectTransform{}

	_, tunnelAddr, _ := startTunnelProxy(t, []transform.Transformer{rejecter})

	conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	// Auth
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)
	authResp := make([]byte, 2)
	_, err = io.ReadFull(conn, authResp)
	require.NoError(t, err)

	// Connect to some target
	connectReq := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50} // 127.0.0.1:80
	_, err = conn.Write(connectReq)
	require.NoError(t, err)

	connectResp := make([]byte, 10)
	_, err = io.ReadFull(conn, connectResp)
	require.NoError(t, err)
	require.Equal(t, byte(0x02), connectResp[1]) // connection not allowed
}

// rejectTransform rejects all requests.
type rejectTransform struct{}

func (r *rejectTransform) Name() string { return "rejecter" }

func (r *rejectTransform) TransformRequest(_ context.Context, _ *transform.TransformContext, _ *http.Request) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionReject}, nil
}

func (r *rejectTransform) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

type connectHeaderAuthTransform struct {
	lastTarget string
}

func (c *connectHeaderAuthTransform) Name() string { return "connect-auth" }

func (c *connectHeaderAuthTransform) TransformRequest(_ context.Context, _ *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	if req.Method != http.MethodConnect {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}
	c.lastTarget = req.Host
	if req.Header.Get("Proxy-Authorization") == "Basic ok" {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}
	return &transform.TransformResult{
		Action: transform.ActionReject,
		Response: &http.Response{
			StatusCode: http.StatusProxyAuthRequired,
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{"Proxy-Authenticate": []string{`Basic realm="proxy"`}},
			Body:       http.NoBody,
		},
	}, nil
}

func (c *connectHeaderAuthTransform) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

type tunnelInfoTransform struct {
	seen chan<- *transform.TunnelInfo
}

func (t *tunnelInfoTransform) Name() string { return "tunnel-info" }

func (t *tunnelInfoTransform) TransformRequest(_ context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	if req.Method == http.MethodConnect {
		tctx.Annotate("user_id", "alice")
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}
	if tctx.Tunnel != nil {
		select {
		case t.seen <- tctx.Tunnel:
		default:
		}
	}
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (t *tunnelInfoTransform) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}
