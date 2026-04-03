// Package hostmatch provides domain glob and CIDR matching for host-based
// access control, shared by the allowlist and secrets transforms.
package hostmatch

import (
	"context"
	"fmt"
	"net"
	"path"
	"strings"
)

// Resolver looks up IP addresses for a hostname.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// Matcher checks whether a host matches a set of domain globs and CIDR ranges.
type Matcher struct {
	domains  []string
	cidrs    []*net.IPNet
	resolver Resolver
}

// New creates a Matcher from domain globs and CIDR strings.
func New(domains []string, cidrs []string, resolver Resolver) (*Matcher, error) {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("parsing CIDR %q: %w", cidr, err)
		}
		nets = append(nets, ipNet)
	}

	return &Matcher{
		domains:  domains,
		cidrs:    nets,
		resolver: resolver,
	}, nil
}

// Matches returns true if the host matches any domain glob or, after DNS
// resolution, any CIDR range. The host should already have the port stripped.
func (m *Matcher) Matches(ctx context.Context, host string) bool {
	for _, pattern := range m.domains {
		if MatchGlob(pattern, host) {
			return true
		}
	}

	if len(m.cidrs) > 0 {
		addrs, err := m.resolver.LookupHost(ctx, host)
		if err == nil {
			for _, addr := range addrs {
				ip := net.ParseIP(addr)
				if ip == nil {
					continue
				}
				for _, cidr := range m.cidrs {
					if cidr.Contains(ip) {
						return true
					}
				}
			}
		}
	}

	return false
}

// MatchGlob matches a domain against a glob pattern.
// "*.example.com" matches any subdomain depth and "example.com" itself.
func MatchGlob(pattern, name string) bool {
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		return strings.HasSuffix(name, suffix) || name == pattern[2:]
	}
	matched, _ := path.Match(pattern, name)
	return matched
}

// DefaultResolver returns the system's default DNS resolver.
func DefaultResolver() Resolver {
	return net.DefaultResolver
}

// NullResolver is a Resolver that always returns "no such host". Useful when
// only domain glob matching is needed and CIDR resolution is not required.
type NullResolver struct{}

func (NullResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	return nil, fmt.Errorf("no such host: %s", host)
}

// StripPort removes the port from a host:port string. If there's no port,
// the host is returned unchanged.
func StripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
