package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/dnsguard"
)

func TestBuildTransport_HTTP2ReceiveWindowsAreBounded(t *testing.T) {
	guard, err := dnsguard.New(nil)
	require.NoError(t, err)
	transport := buildTransport(nil, guard, 0, nil)

	require.NotNil(t, transport.HTTP2)
	require.Equal(t, maxHTTP2ReceiveBufferPerConnection, transport.HTTP2.MaxReceiveBufferPerConnection)
	require.Equal(t, maxHTTP2ReceiveBufferPerStream, transport.HTTP2.MaxReceiveBufferPerStream)
}

func TestBuildTransport_HTTP2ConcurrentResponsesStayWithinMemoryBudget(t *testing.T) {
	const (
		streams  = 40
		bodySize = 8 << 20
	)

	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.CopyN(w, zeroReader{}, bodySize)
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()

	guard, err := dnsguard.New(nil)
	require.NoError(t, err)
	transport := buildTransport(nil, guard, 0, nil)
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	defer transport.CloseIdleConnections()

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	ctx := context.Background()
	responses := make([]*http.Response, streams)
	errs := make(chan error, streams)
	for i := range streams {
		go func(i int) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstream.URL, nil)
			if err != nil {
				errs <- err
				return
			}
			responses[i], err = transport.RoundTrip(req)
			errs <- err
		}(i)
	}
	for range streams {
		require.NoError(t, <-errs)
	}
	time.Sleep(500 * time.Millisecond)

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	require.Less(t, after.HeapAlloc, before.HeapAlloc+uint64(64<<20))

	drained := make(chan error, streams)
	for _, resp := range responses {
		require.Equal(t, 2, resp.ProtoMajor)
		go func(resp *http.Response) {
			got, err := io.Copy(io.Discard, resp.Body)
			if err == nil && got != int64(bodySize) {
				err = io.ErrUnexpectedEOF
			}
			if closeErr := resp.Body.Close(); err == nil {
				err = closeErr
			}
			drained <- err
		}(resp)
	}
	for range streams {
		require.NoError(t, <-drained)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
