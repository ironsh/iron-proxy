// Package dns implements the iron-proxy DNS server that intercepts queries
// and resolves them to the proxy's IP, with support for passthrough domains
// and static records.
package dns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/miekg/dns"

	"github.com/ironsh/iron-proxy/internal/config"
	"github.com/ironsh/iron-proxy/internal/hostmatch"
)

// Resolver looks up DNS records by forwarding to an upstream resolver.
// Exists for testability — production uses the OS resolver.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// Server is the iron-proxy DNS server.
type Server struct {
	proxyIP     net.IP
	passthrough []string
	records     map[string]config.DNSRecord // keyed by lowercase FQDN
	resolver    Resolver
	logger      *slog.Logger
	server      *dns.Server
}

// New creates a new DNS server from the given config.
func New(cfg config.DNS, resolver Resolver, logger *slog.Logger) (*Server, error) {
	ip := net.ParseIP(cfg.ProxyIP)
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("invalid proxy_ip (must be IPv4): %q", cfg.ProxyIP)
	}

	records := make(map[string]config.DNSRecord, len(cfg.Records))
	for _, r := range cfg.Records {
		key := dns.Fqdn(strings.ToLower(r.Name))
		records[key] = r
	}

	s := &Server{
		proxyIP:     ip,
		passthrough: cfg.Passthrough,
		records:     records,
		resolver:    resolver,
		logger:      logger,
	}

	s.server = &dns.Server{
		Addr:    cfg.Listen,
		Net:     "udp",
		Handler: dns.HandlerFunc(s.handleQuery),
	}

	return s, nil
}

// ListenAndServe starts the DNS server. It blocks until the server is shut down.
func (s *Server) ListenAndServe() error {
	s.logger.Info("dns server starting", slog.String("addr", s.server.Addr))
	return s.server.ListenAndServe()
}

// Shutdown gracefully stops the DNS server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.ShutdownContext(ctx)
}

func (s *Server) handleQuery(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	for _, q := range r.Question {
		name := strings.ToLower(q.Name)

		if rr, ok := s.staticRecord(q, name); ok {
			msg.Answer = append(msg.Answer, rr)
			s.logger.Debug("dns static", slog.String("name", name))
		} else if s.isPassthrough(name) {
			s.handlePassthrough(msg, q, name)
			s.logger.Debug("dns passthrough", slog.String("name", name))
		} else {
			s.handleIntercept(msg, q)
			s.logger.Debug("dns intercept", slog.String("name", name))
		}
	}

	if err := w.WriteMsg(msg); err != nil {
		s.logger.Error("dns write failed", slog.String("error", err.Error()))
	}
}

// staticRecord returns a DNS resource record if a static entry matches the
// query name and type. Returns nil, false if no match.
func (s *Server) staticRecord(q dns.Question, name string) (dns.RR, bool) {
	rec, ok := s.records[name]
	if !ok {
		return nil, false
	}

	switch {
	case rec.Type == "A" && q.Qtype == dns.TypeA:
		ip := net.ParseIP(rec.Value)
		if ip == nil {
			return nil, false
		}
		return &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   ip.To4(),
		}, true
	case rec.Type == "CNAME" && q.Qtype == dns.TypeCNAME:
		return &dns.CNAME{
			Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
			Target: dns.Fqdn(rec.Value),
		}, true
	default:
		return nil, false
	}
}

// isPassthrough returns true if the name matches any passthrough glob pattern.
func (s *Server) isPassthrough(name string) bool {
	// Strip trailing dot for matching
	name = strings.TrimSuffix(name, ".")

	for _, pattern := range s.passthrough {
		if hostmatch.MatchGlob(pattern, name) {
			return true
		}
	}
	return false
}

// handlePassthrough resolves via the upstream resolver and appends results.
func (s *Server) handlePassthrough(msg *dns.Msg, q dns.Question, name string) {
	host := strings.TrimSuffix(name, ".")
	addrs, err := s.resolver.LookupHost(context.Background(), host)
	if err != nil {
		s.logger.Warn("dns passthrough lookup failed",
			slog.String("name", name),
			slog.String("error", err.Error()),
		)
		return
	}

	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil || ip.To4() == nil {
			continue
		}
		if q.Qtype == dns.TypeA {
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   ip.To4(),
			})
		}
	}
}

// handleIntercept resolves the query to the proxy's own IP.
func (s *Server) handleIntercept(msg *dns.Msg, q dns.Question) {
	if q.Qtype == dns.TypeA {
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   s.proxyIP.To4(),
		})
	}
}
