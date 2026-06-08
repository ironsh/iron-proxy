package config

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// proxyForURL builds the ProxyFunc and resolves the proxy for rawurl,
// returning "" when the request should connect directly.
func proxyForURL(t *testing.T, u UpstreamProxy, rawurl string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawurl, nil)
	require.NoError(t, err)
	proxyURL, err := u.ProxyFunc()(req)
	require.NoError(t, err)
	if proxyURL == nil {
		return ""
	}
	return proxyURL.String()
}

// clearProxyEnv removes every standard proxy variable so a test starts from a
// known-empty environment regardless of the host's settings.
func clearProxyEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"HTTP_PROXY", "http_proxy",
		"HTTPS_PROXY", "https_proxy",
		"NO_PROXY", "no_proxy",
	} {
		t.Setenv(k, "")
	}
}

func TestUpstreamProxy_Direct(t *testing.T) {
	clearProxyEnv(t)
	var u UpstreamProxy
	require.Empty(t, proxyForURL(t, u, "http://example.com"))
	require.Empty(t, proxyForURL(t, u, "https://example.com"))
}

func TestUpstreamProxy_ConfigOnly(t *testing.T) {
	clearProxyEnv(t)
	u := UpstreamProxy{
		HTTPProxy:  "http://proxy.corp:3128",
		HTTPSProxy: "http://proxy.corp:3129",
	}
	require.Equal(t, "http://proxy.corp:3128", proxyForURL(t, u, "http://example.com"))
	require.Equal(t, "http://proxy.corp:3129", proxyForURL(t, u, "https://example.com"))
}

func TestUpstreamProxy_EnvOverridesConfig(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("HTTPS_PROXY", "http://env-proxy:8080")
	u := UpstreamProxy{
		HTTPProxy:  "http://config-proxy:3128",
		HTTPSProxy: "http://config-proxy:3129",
	}
	// HTTPS_PROXY env wins for https; http falls back to config (no env set).
	require.Equal(t, "http://env-proxy:8080", proxyForURL(t, u, "https://example.com"))
	require.Equal(t, "http://config-proxy:3128", proxyForURL(t, u, "http://example.com"))
}

func TestUpstreamProxy_NoProxyConfig(t *testing.T) {
	clearProxyEnv(t)
	u := UpstreamProxy{
		HTTPSProxy: "http://proxy.corp:3129",
		NoProxy:    "internal.example.com",
	}
	require.Empty(t, proxyForURL(t, u, "https://internal.example.com"))
	require.Equal(t, "http://proxy.corp:3129", proxyForURL(t, u, "https://external.example.com"))
}

func TestUpstreamProxy_NoProxyEnvOverridesConfig(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("NO_PROXY", "env.example.com")
	u := UpstreamProxy{
		HTTPSProxy: "http://proxy.corp:3129",
		NoProxy:    "config.example.com",
	}
	// Env NO_PROXY replaces the configured list entirely.
	require.Empty(t, proxyForURL(t, u, "https://env.example.com"))
	require.Equal(t, "http://proxy.corp:3129", proxyForURL(t, u, "https://config.example.com"))
}

func TestUpstreamProxy_SOCKS5Scheme(t *testing.T) {
	clearProxyEnv(t)
	u := UpstreamProxy{HTTPSProxy: "socks5://proxy.corp:1080"}
	require.Equal(t, "socks5://proxy.corp:1080", proxyForURL(t, u, "https://example.com"))
}
