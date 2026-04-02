// Package allowlist implements a default-deny domain and CIDR allowlist transform.
package allowlist

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"path"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func init() {
	transform.Register("allowlist", factory)
}

// Allowlist is a default-deny transform that checks request hosts, methods,
// and paths against a set of rules.
type Allowlist struct {
	rules []rule
}

type allowlistConfig struct {
	Domains []string     `yaml:"domains"`
	CIDRs   []string     `yaml:"cidrs"`
	Rules   []ruleConfig `yaml:"rules"`
}

type ruleConfig struct {
	Host    string   `yaml:"host,omitempty"`
	CIDR    string   `yaml:"cidr,omitempty"`
	Methods []string `yaml:"methods,omitempty"`
	Paths   []string `yaml:"paths,omitempty"`
}

// rule is a compiled allowlist rule ready for matching.
type rule struct {
	matcher *hostmatch.Matcher
	methods map[string]bool // nil = all methods allowed
	paths   []string        // nil = all paths allowed
}

func factory(cfg yaml.Node) (transform.Transformer, error) {
	var c allowlistConfig
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing allowlist config: %w", err)
	}
	return newFromConfig(c, net.DefaultResolver)
}

func newFromConfig(cfg allowlistConfig, resolver hostmatch.Resolver) (*Allowlist, error) {
	var rules []rule

	// Flat domains → rules with no method/path restrictions.
	for _, d := range cfg.Domains {
		m, err := hostmatch.New([]string{d}, nil, resolver)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule{matcher: m})
	}

	// Flat CIDRs → rules with no method/path restrictions.
	for _, c := range cfg.CIDRs {
		m, err := hostmatch.New(nil, []string{c}, resolver)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule{matcher: m})
	}

	// Explicit rules with optional method/path restrictions.
	for i, rc := range cfg.Rules {
		if rc.Host != "" && rc.CIDR != "" {
			return nil, fmt.Errorf("rules[%d]: host and cidr are mutually exclusive", i)
		}
		if rc.Host == "" && rc.CIDR == "" {
			return nil, fmt.Errorf("rules[%d]: one of host or cidr is required", i)
		}

		var domains []string
		var cidrs []string
		if rc.Host != "" {
			domains = []string{rc.Host}
		}
		if rc.CIDR != "" {
			cidrs = []string{rc.CIDR}
		}

		m, err := hostmatch.New(domains, cidrs, resolver)
		if err != nil {
			return nil, fmt.Errorf("rules[%d]: %w", i, err)
		}

		for _, p := range rc.Paths {
			if !strings.HasPrefix(p, "/") {
				return nil, fmt.Errorf("rules[%d]: path %q must start with /", i, p)
			}
		}

		r := rule{matcher: m}
		if len(rc.Methods) > 0 {
			r.methods = make(map[string]bool, len(rc.Methods))
			for _, method := range rc.Methods {
				r.methods[strings.ToUpper(method)] = true
			}
		}
		if len(rc.Paths) > 0 {
			r.paths = rc.Paths
		}

		rules = append(rules, r)
	}

	return &Allowlist{rules: rules}, nil
}

// New creates an Allowlist from domain globs and CIDR strings.
// All methods and paths are allowed. This is the backwards-compatible constructor.
func New(domains []string, cidrs []string, resolver hostmatch.Resolver) (*Allowlist, error) {
	return newFromConfig(allowlistConfig{Domains: domains, CIDRs: cidrs}, resolver)
}

func (a *Allowlist) Name() string { return "allowlist" }

func (a *Allowlist) TransformRequest(ctx context.Context, _ *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	host := hostmatch.StripPort(req.Host)

	for _, r := range a.rules {
		if !r.matcher.Matches(ctx, host) {
			continue
		}
		if r.methods != nil && !r.methods[req.Method] {
			continue
		}
		if r.paths != nil && !matchAnyPath(r.paths, req.URL.Path) {
			continue
		}
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}

	return &transform.TransformResult{Action: transform.ActionReject}, nil
}

func (a *Allowlist) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func matchAnyPath(patterns []string, reqPath string) bool {
	for _, p := range patterns {
		if matchPath(p, reqPath) {
			return true
		}
	}
	return false
}

// matchPath checks if reqPath matches a path pattern. Patterns ending in /*
// match any path under that prefix (e.g. /v1/* matches /v1/models and /v1).
// Other patterns use path.Match glob semantics.
func matchPath(pattern, reqPath string) bool {
	if strings.HasSuffix(pattern, "/*") {
		prefix := pattern[:len(pattern)-1] // "/v1/"
		base := pattern[:len(pattern)-2]   // "/v1"
		return strings.HasPrefix(reqPath, prefix) || reqPath == base
	}
	matched, _ := path.Match(pattern, reqPath)
	return matched
}
