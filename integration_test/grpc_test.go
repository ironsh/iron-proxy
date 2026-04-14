package integration_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	transformv1 "github.com/ironsh/iron-proxy/gen/transform/v1"
)

// TestGRPCPipeline is a black-box end-to-end test. It compiles the iron-proxy
// binary, boots it with a config that chains two gRPC transform servers, and
// makes real HTTP requests through the proxy.
//
// The test exercises:
//  1. Allowlist: permits the upstream host, blocks unlisted hosts with 403.
//  2. Secrets: swaps a proxy token for a real secret in the Authorization header.
//  3. Two chained gRPC transforms that modify request and response bodies.
func TestGRPCPipeline(t *testing.T) {
	tmpDir := t.TempDir()
	binary := proxyBinary(t)

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

	// Two gRPC transform servers.
	grpcAddr1 := startGRPCTransformServer(t, "step1")
	grpcAddr2 := startGRPCTransformServer(t, "step2")

	cfgPath := renderConfig(t, tmpDir, "grpc_pipeline.yaml", map[string]string{
		"GRPCAddr1": grpcAddr1,
		"GRPCAddr2": grpcAddr2,
	})

	proxy := startProxy(t, binary, cfgPath, []string{"TEST_SECRET=real-secret-key"})
	upstreamHost := upstream.Listener.Addr().String()

	t.Run("allowed_request_with_transforms", func(t *testing.T) {
		req, err := http.NewRequest("POST", fmt.Sprintf("http://%s/test", proxy.HTTPAddr), strings.NewReader("original"))
		require.NoError(t, err)
		req.Host = upstreamHost
		req.Header.Set("Authorization", "Bearer proxy-token")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)

		respBody, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		// Request body: "original" -> step1 appends "-step1" -> step2 appends "-step2"
		// Upstream echoes: "original-step1-step2"
		// Response body: "original-step1-step2" -> step1 prepends "resp1-" -> step2 prepends "resp2-"
		require.Equal(t, "resp2-resp1-original-step1-step2", string(respBody))
	})

	t.Run("blocked_host_returns_403", func(t *testing.T) {
		req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", proxy.HTTPAddr), nil)
		require.NoError(t, err)
		req.Host = "evil.example.com"

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	})
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
