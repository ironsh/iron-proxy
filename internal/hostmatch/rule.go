package hostmatch

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// RuleConfig is the YAML-decoded form of a host/method/path matching rule.
type RuleConfig struct {
	Host     string   `yaml:"host,omitempty"`
	CIDR     string   `yaml:"cidr,omitempty"`
	SourceIP string   `yaml:"source_ip,omitempty"`
	Methods  []string `yaml:"methods,omitempty"`
	Paths    []string `yaml:"paths,omitempty"`
}

// Rule is a compiled matching rule ready for use.
type Rule struct {
	Matcher  *Matcher
	SourceIP *net.IPNet      // nil = any source address
	Methods  map[string]bool // nil = all methods
	Paths    []string        // nil = all paths
}

// Matches returns true if the request matches this rule. remoteAddr is the
// client address ("host:port" or a bare IP); it is only read when the rule
// sets SourceIP. A rule with SourceIP never matches an unparsable address.
func (r *Rule) Matches(host, method, path, remoteAddr string) bool {
	if !r.Matcher.Matches(host) {
		return false
	}
	if r.SourceIP != nil && !r.SourceIP.Contains(net.ParseIP(StripPort(remoteAddr))) {
		return false
	}
	if r.Methods != nil && !r.Methods[method] {
		return false
	}
	if r.Paths != nil && !MatchAnyPath(r.Paths, path) {
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

		var sourceIP *net.IPNet
		if rc.SourceIP != "" {
			_, sourceIP, err = net.ParseCIDR(sourceCIDR(rc.SourceIP))
			if err != nil {
				return nil, fmt.Errorf("%s: rules[%d]: source_ip %q: %w", prefix, i, rc.SourceIP, err)
			}
		}

		for _, p := range rc.Paths {
			if !strings.HasPrefix(p, "/") {
				return nil, fmt.Errorf("%s: rules[%d]: path %q must start with /", prefix, i, p)
			}
		}

		r := Rule{Matcher: m, SourceIP: sourceIP}
		if !isWildcard(rc.Methods) {
			r.Methods = make(map[string]bool, len(rc.Methods))
			for _, method := range rc.Methods {
				r.Methods[strings.ToUpper(method)] = true
			}
		}
		if len(rc.Paths) > 0 {
			r.Paths = rc.Paths
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
	host := StripPort(req.Host)
	for _, r := range rules {
		if r.Matches(host, req.Method, req.URL.Path, req.RemoteAddr) {
			return true
		}
	}
	return false
}

// sourceCIDR widens a bare IP address into a single-address CIDR block and
// returns any other input unchanged.
func sourceCIDR(sourceIP string) string {
	if strings.Contains(sourceIP, "/") {
		return sourceIP
	}
	if strings.Contains(sourceIP, ":") {
		return sourceIP + "/128"
	}
	return sourceIP + "/32"
}
