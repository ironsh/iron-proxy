package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	transformv1 "github.com/ironsh/iron-proxy/gen/transform/v1"
)

// TestIntegration_FullPipeline is a black-box end-to-end test. It compiles
// the iron-proxy binary, writes a config YAML, boots the proxy as a
// subprocess, and makes real HTTP requests through it.
//
// The test exercises:
//  1. Allowlist: permits the upstream host, blocks unlisted hosts with 403.
//  2. Secrets: swaps a proxy token for a real secret in the Authorization header.
//  3. Two chained gRPC transforms that modify request and response bodies.
//
// Uses plain HTTP so the proxy can forward directly to the upstream by
// IP:port without DNS resolution.
func TestIntegration_FullPipeline(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()

	// --- build binary ---
	binary := filepath.Join(tmpDir, "iron-proxy")
	build := exec.Command("go", "build", "-o", binary, "./cmd/iron-proxy")
	build.Dir = findRepoRoot(t)
	out, err := build.CombinedOutput()
	require.NoError(t, err, "go build: %s", out)

	// --- start external services ---

	// Upstream: echoes request body, validates Authorization header.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer real-secret-key" {
			http.Error(w, fmt.Sprintf("bad auth: %s", got), http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer upstream.Close()
	upstreamHost := upstream.Listener.Addr().String() // "127.0.0.1:PORT"

	// Two gRPC transform servers.
	grpcAddr1 := startGRPCTransformServer(t, "step1")
	grpcAddr2 := startGRPCTransformServer(t, "step2")

	// --- CA cert/key on disk (required by config even for HTTP-only) ---
	caCertPath, caKeyPath := writeTestCA(t, tmpDir)

	// --- pick ports ---
	// --- write config ---
	cfgYAML := fmt.Sprintf(`dns:
  proxy_ip: "127.0.0.1"
  listen: "127.0.0.1:0"

proxy:
  http_listen: "127.0.0.1:8080"
  https_listen: "127.0.0.1:8443"
  max_request_body_bytes: 1048576

tls:
  ca_cert: %q
  ca_key: %q

transforms:
  - name: allowlist
    config:
      domains:
        - "127.0.0.1"

  - name: secrets
    config:
      secrets:
        - source:
            type: env
            var: TEST_SECRET
          proxy_value: "proxy-token"
          match_headers: ["Authorization"]
          rules:
            - host: "127.0.0.1"

  - name: grpc
    config:
      name: grpc-step-1
      target: %q
      send_request_body: true
      send_response_body: true

  - name: grpc
    config:
      name: grpc-step-2
      target: %q
      send_request_body: true
      send_response_body: true

metrics:
  listen: "127.0.0.1:0"

log:
  level: error
`, caCertPath, caKeyPath, grpcAddr1, grpcAddr2)

	cfgPath := filepath.Join(tmpDir, "config.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfgYAML), 0644))

	// --- start proxy ---
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := exec.CommandContext(ctx, binary, "-config", cfgPath)
	cmd.Env = append(os.Environ(), "TEST_SECRET=real-secret-key")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
	})

	proxyHTTP := "127.0.0.1:8080"
	waitForPort(t, proxyHTTP, 5*time.Second)

	// --- test: allowed request with secrets + gRPC body transforms ---
	req, err := http.NewRequest("POST", fmt.Sprintf("http://%s/test", proxyHTTP), strings.NewReader("original"))
	require.NoError(t, err)
	req.Host = upstreamHost
	req.Header.Set("Authorization", "Bearer proxy-token")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Request body: "original" → step1 appends "-step1" → step2 appends "-step2"
	// Upstream echoes: "original-step1-step2"
	// Response body: "original-step1-step2" → step1 prepends "resp1-" → step2 prepends "resp2-"
	require.Equal(t, "resp2-resp1-original-step1-step2", string(respBody))

	// --- test: blocked request ---
	blockedReq, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", proxyHTTP), nil)
	require.NoError(t, err)
	blockedReq.Host = "evil.example.com"

	blockedResp, err := http.DefaultClient.Do(blockedReq)
	require.NoError(t, err)
	defer blockedResp.Body.Close()

	require.Equal(t, http.StatusForbidden, blockedResp.StatusCode)
}

// --- helpers ---

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (no go.mod)")
		}
		dir = parent
	}
}

func writeTestCA(t *testing.T, tmpDir string) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPath = filepath.Join(tmpDir, "ca.crt")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: certDER,
	}), 0644))

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPath = filepath.Join(tmpDir, "ca.key")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{
		Type: "EC PRIVATE KEY", Bytes: keyDER,
	}), 0600))

	return certPath, keyPath
}

func waitForPort(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("port %s not ready after %s", addr, timeout)
}

// --- gRPC test servers ---

type grpcTransformServer struct {
	transformv1.UnimplementedTransformServiceServer
	tag string
}

func (s *grpcTransformServer) TransformRequest(_ context.Context, in *transformv1.TransformRequestRequest) (*transformv1.TransformRequestResponse, error) {
	body := in.GetRequest().GetBody()
	modified := append(body, []byte("-"+s.tag)...)
	return &transformv1.TransformRequestResponse{
		Action: transformv1.TransformAction_TRANSFORM_ACTION_CONTINUE,
		ModifiedRequest: &transformv1.HttpRequest{
			Body: modified,
		},
	}, nil
}

func (s *grpcTransformServer) TransformResponse(_ context.Context, in *transformv1.TransformResponseRequest) (*transformv1.TransformResponseResponse, error) {
	body := in.GetResponse().GetBody()
	modified := append([]byte("resp"+strings.TrimPrefix(s.tag, "step")+"-"), body...)
	return &transformv1.TransformResponseResponse{
		Action:           transformv1.TransformAction_TRANSFORM_ACTION_CONTINUE,
		ModifiedResponse: &transformv1.HttpResponse{Body: modified},
	}, nil
}

func startGRPCTransformServer(t *testing.T, tag string) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	s := grpc.NewServer()
	transformv1.RegisterTransformServiceServer(s, &grpcTransformServer{tag: tag})
	t.Cleanup(func() { s.Stop() })

	go func() { _ = s.Serve(lis) }()
	return lis.Addr().String()
}
