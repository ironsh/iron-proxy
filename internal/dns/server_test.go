package dns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/config"
)

// mockResolver implements Resolver for testing.
type mockResolver struct {
	hosts map[string][]string
}

func (m *mockResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	addrs, ok := m.hosts[host]
	if !ok {
		return nil, fmt.Errorf("no such host: %s", host)
	}
	return addrs, nil
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func startTestServer(t *testing.T, cfg config.DNS, resolver Resolver) (*Server, string) {
	t.Helper()

	// Use a random port
	cfg.Listen = "127.0.0.1:0"

	srv, err := New(cfg, resolver, testLogger())
	require.NoError(t, err)

	// Use PacketConn to get a random port
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	srv.server = &dns.Server{
		PacketConn: pc,
		Handler:    dns.HandlerFunc(srv.handleQuery),
	}

	go func() {
		_ = srv.server.ActivateAndServe()
	}()

	t.Cleanup(func() {
		_ = srv.Shutdown(context.Background())
	})

	return srv, pc.LocalAddr().String()
}

func query(t *testing.T, addr, name string, qtype uint16) *dns.Msg {
	t.Helper()

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)

	c := new(dns.Client)
	resp, _, err := c.Exchange(msg, addr)
	require.NoError(t, err)
	return resp
}

func TestIntercept_DefaultResolvesToProxyIP(t *testing.T) {
	cfg := config.DNS{ProxyIP: "10.16.0.1"}
	_, addr := startTestServer(t, cfg, &mockResolver{})

	resp := query(t, addr, "example.com", dns.TypeA)
	require.Len(t, resp.Answer, 1)

	a, ok := resp.Answer[0].(*dns.A)
	require.True(t, ok)
	require.Equal(t, net.ParseIP("10.16.0.1").To4(), a.A)
}

func TestIntercept_UnknownDomainResolvesToProxyIP(t *testing.T) {
	cfg := config.DNS{ProxyIP: "10.16.0.1"}
	_, addr := startTestServer(t, cfg, &mockResolver{})

	resp := query(t, addr, "anything.random.xyz", dns.TypeA)
	require.Len(t, resp.Answer, 1)

	a := resp.Answer[0].(*dns.A)
	require.Equal(t, net.ParseIP("10.16.0.1").To4(), a.A)
}

func TestPassthrough_MatchingDomainUsesResolver(t *testing.T) {
	cfg := config.DNS{
		ProxyIP:     "10.16.0.1",
		Passthrough: []string{"*.internal.corp"},
	}
	resolver := &mockResolver{
		hosts: map[string][]string{
			"db.internal.corp": {"192.168.1.10"},
		},
	}
	_, addr := startTestServer(t, cfg, resolver)

	resp := query(t, addr, "db.internal.corp", dns.TypeA)
	require.Len(t, resp.Answer, 1)

	a := resp.Answer[0].(*dns.A)
	require.Equal(t, net.ParseIP("192.168.1.10").To4(), a.A)
}

func TestPassthrough_DeepSubdomainMatches(t *testing.T) {
	cfg := config.DNS{
		ProxyIP:     "10.16.0.1",
		Passthrough: []string{"*.internal.corp"},
	}
	resolver := &mockResolver{
		hosts: map[string][]string{
			"a.b.c.internal.corp": {"192.168.1.20"},
		},
	}
	_, addr := startTestServer(t, cfg, resolver)

	resp := query(t, addr, "a.b.c.internal.corp", dns.TypeA)
	require.Len(t, resp.Answer, 1)

	a := resp.Answer[0].(*dns.A)
	require.Equal(t, net.ParseIP("192.168.1.20").To4(), a.A)
}

func TestPassthrough_NonMatchingDomainIsIntercepted(t *testing.T) {
	cfg := config.DNS{
		ProxyIP:     "10.16.0.1",
		Passthrough: []string{"*.internal.corp"},
	}
	_, addr := startTestServer(t, cfg, &mockResolver{})

	resp := query(t, addr, "example.com", dns.TypeA)
	require.Len(t, resp.Answer, 1)

	a := resp.Answer[0].(*dns.A)
	require.Equal(t, net.ParseIP("10.16.0.1").To4(), a.A)
}

func TestPassthrough_ExactMatch(t *testing.T) {
	cfg := config.DNS{
		ProxyIP:     "10.16.0.1",
		Passthrough: []string{"metadata.google.internal"},
	}
	resolver := &mockResolver{
		hosts: map[string][]string{
			"metadata.google.internal": {"169.254.169.254"},
		},
	}
	_, addr := startTestServer(t, cfg, resolver)

	resp := query(t, addr, "metadata.google.internal", dns.TypeA)
	require.Len(t, resp.Answer, 1)

	a := resp.Answer[0].(*dns.A)
	require.Equal(t, net.ParseIP("169.254.169.254").To4(), a.A)
}

func TestStaticRecord_ARecord(t *testing.T) {
	cfg := config.DNS{
		ProxyIP: "10.16.0.1",
		Records: []config.DNSRecord{
			{Name: "internal.example.com", Type: "A", Value: "10.0.0.5"},
		},
	}
	_, addr := startTestServer(t, cfg, &mockResolver{})

	resp := query(t, addr, "internal.example.com", dns.TypeA)
	require.Len(t, resp.Answer, 1)

	a := resp.Answer[0].(*dns.A)
	require.Equal(t, net.ParseIP("10.0.0.5").To4(), a.A)
}

func TestStaticRecord_CNAMERecord(t *testing.T) {
	cfg := config.DNS{
		ProxyIP: "10.16.0.1",
		Records: []config.DNSRecord{
			{Name: "alias.example.com", Type: "CNAME", Value: "real.example.com"},
		},
	}
	_, addr := startTestServer(t, cfg, &mockResolver{})

	resp := query(t, addr, "alias.example.com", dns.TypeCNAME)
	require.Len(t, resp.Answer, 1)

	cname := resp.Answer[0].(*dns.CNAME)
	require.Equal(t, "real.example.com.", cname.Target)
}

func TestStaticRecord_TakesPrecedenceOverPassthrough(t *testing.T) {
	cfg := config.DNS{
		ProxyIP:     "10.16.0.1",
		Passthrough: []string{"*.example.com"},
		Records: []config.DNSRecord{
			{Name: "override.example.com", Type: "A", Value: "10.0.0.99"},
		},
	}
	resolver := &mockResolver{
		hosts: map[string][]string{
			"override.example.com": {"1.2.3.4"},
		},
	}
	_, addr := startTestServer(t, cfg, resolver)

	resp := query(t, addr, "override.example.com", dns.TypeA)
	require.Len(t, resp.Answer, 1)

	a := resp.Answer[0].(*dns.A)
	require.Equal(t, net.ParseIP("10.0.0.99").To4(), a.A)
}

func TestStaticRecord_TakesPrecedenceOverIntercept(t *testing.T) {
	cfg := config.DNS{
		ProxyIP: "10.16.0.1",
		Records: []config.DNSRecord{
			{Name: "special.example.com", Type: "A", Value: "10.0.0.50"},
		},
	}
	_, addr := startTestServer(t, cfg, &mockResolver{})

	resp := query(t, addr, "special.example.com", dns.TypeA)
	require.Len(t, resp.Answer, 1)

	a := resp.Answer[0].(*dns.A)
	require.Equal(t, net.ParseIP("10.0.0.50").To4(), a.A)
}

func TestStaticRecord_WrongQtypeReturnsEmpty(t *testing.T) {
	cfg := config.DNS{
		ProxyIP: "10.16.0.1",
		Records: []config.DNSRecord{
			{Name: "only-a.example.com", Type: "A", Value: "10.0.0.5"},
		},
	}
	_, addr := startTestServer(t, cfg, &mockResolver{})

	// Ask for CNAME but only A is configured — should fall through to intercept
	resp := query(t, addr, "only-a.example.com", dns.TypeCNAME)
	require.Empty(t, resp.Answer)
}

