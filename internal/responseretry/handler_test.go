package responseretry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ironsh/iron-proxy/internal/dnsguard"
	"github.com/stretchr/testify/require"
)

const testAttemptID = "8ace71a1-4e12-47e5-9df4-f2f660db6a82"

func testOptions(endpoint string, client *http.Client) Options {
	return Options{
		AuthorizeEndpoint: endpoint,
		CompleteEndpoint:  endpoint,
		Token:             "proxy-token",
		SandboxID:         "sandbox-1",
		Statuses:          []int{http.StatusPaymentRequired},
		CompletionHeaders: []string{"Payment-Receipt"},
		Client:            client,
	}
}

func TestHandlerAuthorizeAndComplete(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer proxy-token", r.Header.Get("Authorization"))
		var request DecisionRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		require.Equal(t, "service.example", request.Host)
		require.Equal(t, "/v1/search?q=one", request.Path)
		require.Equal(t, "sandbox-1", request.SandboxID)
		require.Equal(t, "00-trace-span-01", request.Traceparent)
		require.True(t, request.Replayable)
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(`{"retry":true,"attempt_id":"` + testAttemptID + `","traceparent":"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01","headers":{"Authorization":"credential"}}`))
		require.NoError(t, err)
	})
	mux.HandleFunc("/complete", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer proxy-token", r.Header.Get("Authorization"))
		var request CompletionRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		require.Equal(t, testAttemptID, request.AttemptID)
		require.NotNil(t, request.ReplayStatus)
		require.Equal(t, http.StatusOK, *request.ReplayStatus)
		require.Equal(t, []string{"receipt"}, request.ResponseHeaders["Payment-Receipt"])
		require.Empty(t, request.ResponseHeaders["Set-Cookie"])
		require.Equal(t, "00-trace-span-01", request.Traceparent)
		require.EqualValues(t, 25, request.ReplayDurationMS)
		require.EqualValues(t, 50, request.ChargeDurationMS)
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	opts := testOptions(server.URL+"/authorize", server.Client())
	opts.CompleteEndpoint = server.URL + "/complete"
	handler, err := New(opts)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, "https://service.example/v1/search?q=one", nil)
	require.NoError(t, err)
	req.Header.Set("Traceparent", "00-trace-span-01")
	resp := &http.Response{
		StatusCode: http.StatusPaymentRequired,
		Header:     http.Header{"Www-Authenticate": {"Payment challenge"}},
	}

	decision, retry, err := handler.Decide(context.Background(), req, resp, true)

	require.NoError(t, err)
	require.True(t, retry)
	require.Equal(t, "credential", decision.Headers.Get("Authorization"))
	require.Equal(t, testAttemptID, decision.AttemptID)
	require.Equal(t, "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", decision.Traceparent)

	replayResp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Payment-Receipt": {"receipt"},
			"Set-Cookie":      {"secret"},
		},
	}
	require.NoError(t, handler.Complete(
		context.Background(),
		decision.AttemptID,
		replayResp,
		"",
		"00-trace-span-01",
		25*time.Millisecond,
		50*time.Millisecond,
	))
}

func TestHandlerSkipsUnconfiguredStatus(t *testing.T) {
	opts := testOptions("http://127.0.0.1/authorize", nil)
	opts.CompleteEndpoint = "http://127.0.0.1/complete"
	handler, err := New(opts)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, "https://service.example/", nil)
	require.NoError(t, err)

	decision, retry, err := handler.Decide(context.Background(), req, &http.Response{StatusCode: http.StatusTooManyRequests}, true)

	require.NoError(t, err)
	require.False(t, retry)
	require.Nil(t, decision)
}

func TestHandlerRejectsForbiddenReplayHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte(`{"retry":true,"attempt_id":"` + testAttemptID + `","headers":{"Host":"other.example"}}`))
		require.NoError(t, err)
	}))
	defer server.Close()
	handler, err := New(testOptions(server.URL, server.Client()))
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, "https://service.example/", nil)
	require.NoError(t, err)

	_, _, err = handler.Decide(context.Background(), req, &http.Response{StatusCode: http.StatusPaymentRequired}, true)

	require.ErrorContains(t, err, "forbidden header Host")
}

func TestHandlerRejectsAuthorizedNonReplayableRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte(`{"retry":true,"attempt_id":"` + testAttemptID + `","headers":{"Authorization":"credential"}}`))
		require.NoError(t, err)
	}))
	defer server.Close()
	handler, err := New(testOptions(server.URL, server.Client()))
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, "https://service.example/", nil)
	require.NoError(t, err)

	_, _, err = handler.Decide(context.Background(), req, &http.Response{StatusCode: http.StatusPaymentRequired}, false)

	require.ErrorContains(t, err, "non-replayable")
}

func TestHandlerRejectsInvalidReturnedTraceparent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte(`{"retry":true,"attempt_id":"` + testAttemptID + `","traceparent":"invalid","headers":{"Authorization":"credential"}}`))
		require.NoError(t, err)
	}))
	defer server.Close()
	handler, err := New(testOptions(server.URL, server.Client()))
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, "https://service.example/", nil)
	require.NoError(t, err)

	_, _, err = handler.Decide(context.Background(), req, &http.Response{StatusCode: http.StatusPaymentRequired}, true)

	require.ErrorContains(t, err, "invalid traceparent")
}

func TestNewValidatesConfiguration(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Options)
		want   string
	}{
		{
			name: "plaintext non-loopback",
			mutate: func(opts *Options) {
				opts.AuthorizeEndpoint = "http://127.attacker.example/authorize"
			},
			want: "must use HTTPS",
		},
		{
			name: "URL credentials",
			mutate: func(opts *Options) {
				opts.AuthorizeEndpoint = "https://user:password@handler.example/authorize"
			},
			want: "without credentials",
		},
		{
			name: "missing token",
			mutate: func(opts *Options) {
				opts.Token = ""
			},
			want: "token is required",
		},
		{
			name: "missing sandbox",
			mutate: func(opts *Options) {
				opts.SandboxID = ""
			},
			want: "sandbox identity is required",
		},
		{
			name: "missing statuses",
			mutate: func(opts *Options) {
				opts.Statuses = nil
			},
			want: "at least one",
		},
		{
			name: "invalid status",
			mutate: func(opts *Options) {
				opts.Statuses = []int{99}
			},
			want: "invalid response retry status",
		},
		{
			name: "invalid completion header",
			mutate: func(opts *Options) {
				opts.CompletionHeaders = []string{"Bad Header"}
			},
			want: "invalid completion response header",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := testOptions("https://handler.example/authorize", nil)
			opts.CompleteEndpoint = "https://handler.example/complete"
			tc.mutate(&opts)
			_, err := New(opts)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestNewAllowsOnlyActualLoopbackHTTP(t *testing.T) {
	for _, endpoint := range []string{
		"http://localhost/authorize",
		"http://127.0.0.1/authorize",
		"http://127.255.255.255/authorize",
		"http://[::1]/authorize",
		"http://[::ffff:127.0.0.1]/authorize",
	} {
		t.Run(endpoint, func(t *testing.T) {
			opts := testOptions(endpoint, nil)
			opts.CompleteEndpoint = endpoint
			_, err := New(opts)
			require.NoError(t, err)
		})
	}
}

func TestHandlerRejectsRedirectsWithoutForwardingAuthorization(t *testing.T) {
	var redirectedCalls atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		redirectedCalls.Add(1)
		require.Empty(t, r.Header.Get("Authorization"))
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusFound)
	}))
	defer redirector.Close()

	handler, err := New(testOptions(redirector.URL, redirector.Client()))
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, "https://service.example/", nil)
	require.NoError(t, err)

	_, _, err = handler.Decide(context.Background(), req, &http.Response{StatusCode: http.StatusPaymentRequired}, true)

	require.ErrorContains(t, err, "status 302")
	require.Zero(t, redirectedCalls.Load())
}

func TestHandlerValidatesAllReturnedHeaders(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{name: "invalid name", headers: map[string]string{"Bad Header": "value"}, want: "invalid header name"},
		{name: "invalid value", headers: map[string]string{"X-Test": "bad\nvalue"}, want: "invalid value"},
		{name: "duplicate canonical name", headers: map[string]string{"X-Test": "one", "x-test": "two"}, want: "duplicate header"},
	}
	for name := range forbiddenRetryHeaders {
		cases = append(cases, struct {
			name    string
			headers map[string]string
			want    string
		}{name: "forbidden " + name, headers: map[string]string{name: "value"}, want: "forbidden header"})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := json.Marshal(DecisionResponse{
				Retry:     true,
				AttemptID: testAttemptID,
				Headers:   tc.headers,
			})
			require.NoError(t, err)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, writeErr := w.Write(payload)
				require.NoError(t, writeErr)
			}))
			defer server.Close()
			handler, err := New(testOptions(server.URL, server.Client()))
			require.NoError(t, err)
			req, err := http.NewRequest(http.MethodGet, "https://service.example/", nil)
			require.NoError(t, err)

			_, _, err = handler.Decide(context.Background(), req, &http.Response{StatusCode: http.StatusPaymentRequired}, true)

			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestHandlerDecisionFailureModes(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		body      string
		wantRetry bool
		wantErr   string
	}{
		{name: "declined", status: http.StatusOK, body: `{"retry":false}`, wantRetry: false},
		{name: "handler rejection", status: http.StatusUnauthorized, body: `{}`, wantErr: "status 401"},
		{name: "malformed JSON", status: http.StatusOK, body: `{`, wantErr: "decode response retry decision"},
		{name: "missing attempt", status: http.StatusOK, body: `{"retry":true}`, wantErr: "omitted attempt id"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, err := io.WriteString(w, tc.body)
				require.NoError(t, err)
			}))
			defer server.Close()
			handler, err := New(testOptions(server.URL, server.Client()))
			require.NoError(t, err)
			req, err := http.NewRequest(http.MethodGet, "https://service.example/", nil)
			require.NoError(t, err)

			decision, retry, err := handler.Decide(context.Background(), req, &http.Response{StatusCode: http.StatusPaymentRequired}, true)

			require.Equal(t, tc.wantRetry, retry)
			if tc.wantErr == "" {
				require.NoError(t, err)
				require.Nil(t, decision)
			} else {
				require.ErrorContains(t, err, tc.wantErr)
			}
		})
	}
}

func TestHandlerCompleteRetriesServerFailureAndSelectsConfiguredHeaders(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := calls.Add(1)
		var request CompletionRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		require.Equal(t, []string{"selected"}, request.ResponseHeaders["X-Selected"])
		require.Empty(t, request.ResponseHeaders["Payment-Receipt"])
		if call == 1 {
			http.Error(w, "retry", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	opts := testOptions(server.URL, server.Client())
	opts.CompletionHeaders = []string{"X-Selected"}
	handler, err := New(opts)
	require.NoError(t, err)

	err = handler.Complete(
		context.Background(),
		testAttemptID,
		&http.Response{StatusCode: http.StatusOK, Header: http.Header{
			"X-Selected":      {"selected"},
			"Payment-Receipt": {"not-selected"},
		}},
		"",
		"",
		0,
		0,
	)

	require.NoError(t, err)
	require.EqualValues(t, 2, calls.Load())
}

func TestHandlerCompleteDoesNotRetryClientFailure(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "invalid", http.StatusBadRequest)
	}))
	defer server.Close()
	handler, err := New(testOptions(server.URL, server.Client()))
	require.NoError(t, err)

	err = handler.Complete(context.Background(), testAttemptID, nil, "upstream_transport_error", "", 0, 0)

	require.ErrorContains(t, err, "status 400")
	require.EqualValues(t, 1, calls.Load())
}

func TestHardenedClientDoesNotMutateInputClient(t *testing.T) {
	originalRedirect := func(_ *http.Request, _ []*http.Request) error { return fmt.Errorf("original") }
	client := &http.Client{CheckRedirect: originalRedirect}
	hardened := hardenedClient(client, nil, nil, 0)

	require.NotSame(t, client, hardened)
	require.Zero(t, client.Timeout)
	require.Equal(t, defaultClientTimeout, hardened.Timeout)
	require.ErrorContains(t, client.CheckRedirect(nil, nil), "original")
	require.ErrorIs(t, hardened.CheckRedirect(nil, nil), http.ErrUseLastResponse)
}

func TestHandlerClientUsesConfiguredResolver(t *testing.T) {
	resolverErr := errors.New("configured resolver used")
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, resolverErr
		},
	}
	opts := testOptions("http://handler.invalid/authorize", nil)
	opts.AllowHTTP = true
	opts.Resolver = resolver
	handler, err := New(opts)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, "https://service.example/", nil)
	require.NoError(t, err)

	_, _, err = handler.Decide(context.Background(), req, &http.Response{StatusCode: http.StatusPaymentRequired}, true)

	require.ErrorContains(t, err, resolverErr.Error())
}

func TestHandlerClientEnforcesUpstreamDenyGuard(t *testing.T) {
	guard, err := dnsguard.New([]string{"169.254.169.254/32"})
	require.NoError(t, err)
	opts := testOptions("http://169.254.169.254/authorize", nil)
	opts.AllowHTTP = true
	opts.Guard = guard
	handler, err := New(opts)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, "https://service.example/", nil)
	require.NoError(t, err)

	_, _, err = handler.Decide(context.Background(), req, &http.Response{StatusCode: http.StatusPaymentRequired}, true)

	require.Error(t, err)
	require.True(t, dnsguard.IsDenyError(err))
}

func TestHandlerClientAllowsExplicitLoopbackDespiteGuard(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := io.WriteString(w, `{"retry":false}`)
		require.NoError(t, err)
	}))
	defer server.Close()
	guard, err := dnsguard.New([]string{"127.0.0.0/8", "::1/128"})
	require.NoError(t, err)
	opts := testOptions(server.URL, nil)
	opts.Guard = guard
	handler, err := New(opts)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, "https://service.example/", nil)
	require.NoError(t, err)

	decision, retry, err := handler.Decide(context.Background(), req, &http.Response{StatusCode: http.StatusPaymentRequired}, true)

	require.NoError(t, err)
	require.False(t, retry)
	require.Nil(t, decision)
}

func TestSelectedHeadersIsCaseInsensitive(t *testing.T) {
	headers := make(http.Header)
	headers.Add("x-receipt", "one")
	headers.Add("X-Receipt", "two")
	headers.Add("Set-Cookie", "secret")

	selected := selectedHeaders(headers, map[string]struct{}{"X-Receipt": {}})

	require.Equal(t, []string{"one", "two"}, selected.Values("X-Receipt"))
	require.Empty(t, selected.Values("Set-Cookie"))
}

func TestValidTraceparentRejectsAllZeroFlagsShape(t *testing.T) {
	require.False(t, validTraceparent(strings.Repeat("0", 55)))
}
