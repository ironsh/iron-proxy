package hostmatch

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// RuleConfig is the YAML-decoded form of a host/method/path matching rule.
type RuleConfig struct {
	Host        string   `yaml:"host,omitempty"`
	CIDR        string   `yaml:"cidr,omitempty"`
	Methods     []string `yaml:"methods,omitempty"`
	Paths       []string `yaml:"paths,omitempty"`
	ProxyLogins []string `yaml:"proxy_logins,omitempty"`
	SourceCIDRs []string `yaml:"source_cidrs,omitempty"`
}

// Rule is a compiled matching rule ready for use.
type Rule struct {
	Matcher     *Matcher
	Methods     map[string]bool // nil = all methods
	Paths       []string        // nil = all paths
	ProxyLogins map[string]bool // nil = all proxy logins
	SourceCIDRs []*net.IPNet    // nil = all client source IPs
}

// MatchContext carries connection metadata used by optional rule filters.
type MatchContext struct {
	ProxyLogin string
	SourceIP   string
}

// Matches returns true if the request matches this rule.
func (r *Rule) Matches(host, method, path string) bool {
	return r.MatchesContext(host, method, path, MatchContext{})
}

// MatchesContext returns true if the request and connection metadata match.
func (r *Rule) MatchesContext(host, method, path string, ctx MatchContext) bool {
	if !r.Matcher.Matches(host) {
		return false
	}
	if r.Methods != nil && !r.Methods[method] {
		return false
	}
	if r.Paths != nil && !MatchAnyPath(r.Paths, path) {
		return false
	}
	if r.ProxyLogins != nil && !r.ProxyLogins[ctx.ProxyLogin] {
		return false
	}
	if len(r.SourceCIDRs) > 0 && !matchSourceCIDR(r.SourceCIDRs, ctx.SourceIP) {
		return false
	}
	return true
}

// CompileRules compiles a list of RuleConfigs into Rules.
// The prefix is used for error messages (e.g. "allowlist" or "grpc transform \"foo\"").
func CompileRules(configs []RuleConfig, prefix string) ([]Rule, error) {
	var rules []Rule
	for i, rc := range configs {
		if rc.Host != "" && rc.CIDR != "" {
			return nil, fmt.Errorf("%s: rules[%d]: host and cidr are mutually exclusive", prefix, i)
		}
		if rc.Host == "" && rc.CIDR == "" {
			return nil, fmt.Errorf("%s: rules[%d]: one of host or cidr is required", prefix, i)
		}

		var domains, cidrs []string
		if rc.Host != "" {
			domains = []string{rc.Host}
		}
		if rc.CIDR != "" {
			cidrs = []string{rc.CIDR}
		}

		m, err := New(domains, cidrs)
		if err != nil {
			return nil, fmt.Errorf("%s: rules[%d]: %w", prefix, i, err)
		}

		for _, p := range rc.Paths {
			if !strings.HasPrefix(p, "/") {
				return nil, fmt.Errorf("%s: rules[%d]: path %q must start with /", prefix, i, p)
			}
		}

		r := Rule{Matcher: m}
		if !isWildcard(rc.Methods) {
			r.Methods = make(map[string]bool, len(rc.Methods))
			for _, method := range rc.Methods {
				r.Methods[strings.ToUpper(method)] = true
			}
		}
		if len(rc.Paths) > 0 {
			r.Paths = rc.Paths
		}
		if len(rc.ProxyLogins) > 0 {
			r.ProxyLogins = make(map[string]bool, len(rc.ProxyLogins))
			for _, login := range rc.ProxyLogins {
				if login == "" {
					return nil, fmt.Errorf("%s: rules[%d]: proxy_logins contains empty login", prefix, i)
				}
				r.ProxyLogins[login] = true
			}
		}
		if len(rc.SourceCIDRs) > 0 {
			r.SourceCIDRs = make([]*net.IPNet, 0, len(rc.SourceCIDRs))
			for _, cidr := range rc.SourceCIDRs {
				_, ipNet, err := net.ParseCIDR(cidr)
				if err != nil {
					return nil, fmt.Errorf("%s: rules[%d]: parsing source_cidrs %q: %w", prefix, i, cidr, err)
				}
				r.SourceCIDRs = append(r.SourceCIDRs, ipNet)
			}
		}

		rules = append(rules, r)
	}
	return rules, nil
}

func isWildcard(methods []string) bool {
	return len(methods) == 0 || (len(methods) == 1 && methods[0] == "*")
}

// MatchAnyRule returns true if the request matches any rule in the list.
func MatchAnyRule(rules []Rule, req *http.Request) bool {
	return MatchAnyRuleContext(rules, req, MatchContext{})
}

// MatchAnyRuleContext returns true if the request and connection metadata
// match any rule in the list.
func MatchAnyRuleContext(rules []Rule, req *http.Request, ctx MatchContext) bool {
	host := StripPort(req.Host)
	for _, r := range rules {
		if r.MatchesContext(host, req.Method, req.URL.Path, ctx) {
			return true
		}
	}
	return false
}

func matchSourceCIDR(cidrs []*net.IPNet, sourceIP string) bool {
	ip := net.ParseIP(sourceIP)
	if ip == nil {
		return false
	}
	for _, cidr := range cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}
