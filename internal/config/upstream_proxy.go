package config

import (
	"net/http"
	"net/url"

	"golang.org/x/net/http/httpproxy"
)

// UpstreamProxy configures an upstream SOCKS5/HTTP CONNECT proxy that
// iron-proxy routes its own outbound connections through. This is for
// deployments (e.g. corporate networks) where all egress must traverse a
// forward proxy.
//
// Each field mirrors a standard proxy environment variable. The matching
// environment variable, when set, OVERRIDES the configured value — config
// supplies a default, env has the final word. This keeps iron-proxy
// well-behaved in environments that already export HTTP_PROXY/HTTPS_PROXY/
// NO_PROXY without forcing those operators to also edit YAML.
//
// Proxy URLs accept http, https, socks5, and socks5h schemes, e.g.
// "http://proxy.corp:3128" or "socks5://proxy.corp:1080".
type UpstreamProxy struct {
	// HTTPProxy is the proxy used for plain-HTTP upstream requests.
	// Overridden by HTTP_PROXY / http_proxy.
	HTTPProxy string `yaml:"http_proxy"`
	// HTTPSProxy is the proxy used for HTTPS upstream requests.
	// Overridden by HTTPS_PROXY / https_proxy.
	HTTPSProxy string `yaml:"https_proxy"`
	// NoProxy is a comma-separated list of hosts/domains/CIDRs that bypass
	// the proxy. Overridden by NO_PROXY / no_proxy.
	NoProxy string `yaml:"no_proxy"`
}

// proxyConfig builds an httpproxy.Config, letting environment variables
// override the configured fields one-for-one. httpproxy.FromEnvironment reads
// both the upper- and lower-case forms of each variable.
func (u UpstreamProxy) proxyConfig() *httpproxy.Config {
	env := httpproxy.FromEnvironment()
	cfg := &httpproxy.Config{
		HTTPProxy:  env.HTTPProxy,
		HTTPSProxy: env.HTTPSProxy,
		NoProxy:    env.NoProxy,
	}
	if cfg.HTTPProxy == "" {
		cfg.HTTPProxy = u.HTTPProxy
	}
	if cfg.HTTPSProxy == "" {
		cfg.HTTPSProxy = u.HTTPSProxy
	}
	if cfg.NoProxy == "" {
		cfg.NoProxy = u.NoProxy
	}
	return cfg
}

// ProxyFunc returns a function suitable for http.Transport.Proxy. It resolves
// the upstream proxy for each request from the merged config+env settings, or
// returns nil (direct connection) when no proxy applies. The returned function
// is safe to reuse across requests and goroutines.
func (u UpstreamProxy) ProxyFunc() func(*http.Request) (*url.URL, error) {
	pf := u.proxyConfig().ProxyFunc()
	return func(req *http.Request) (*url.URL, error) {
		return pf(req.URL)
	}
}
