package integration_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"


	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestInit runs "iron-proxy init" against a temp directory, then verifies
// the generated files, their permissions, and that the proxy actually starts
// and serves traffic using the generated config.
func TestInit(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root (run with sudo)")
	}

	binary := proxyBinary(t)
	configDir := t.TempDir()

	// Pick a free port for the tunnel listener.
	tunnelPort := freePort(t)

	// Run: iron-proxy init --config-dir <tmp> --tunnel-port <port> --no-start --allow "httpbin.org,example.com"
	cmd := exec.Command(binary, "init",
		"--config-dir", configDir,
		"--tunnel-port", tunnelPort,
		"--no-start",
		"--allow", "httpbin.org,example.com",
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "iron-proxy init failed: %s", string(out))

	certPath := filepath.Join(configDir, "ca.crt")
	keyPath := filepath.Join(configDir, "ca.key")
	configPath := filepath.Join(configDir, "proxy.yaml")

	t.Run("files exist", func(t *testing.T) {
		for _, p := range []string{certPath, keyPath, configPath} {
			_, err := os.Stat(p)
			require.NoError(t, err, "expected %s to exist", p)
		}
	})

	t.Run("ca key permissions", func(t *testing.T) {
		info, err := os.Stat(keyPath)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "ca.key should be 0600")
	})

	t.Run("ca cert permissions", func(t *testing.T) {
		info, err := os.Stat(certPath)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o644), info.Mode().Perm(), "ca.crt should be 0644")
	})

	t.Run("ca cert is valid", func(t *testing.T) {
		certPEM, err := os.ReadFile(certPath)
		require.NoError(t, err)

		pool := x509.NewCertPool()
		require.True(t, pool.AppendCertsFromPEM(certPEM), "ca.crt should contain a valid PEM certificate")

		// Also verify we can build a TLS keypair from the generated cert+key.
		keyPEM, err := os.ReadFile(keyPath)
		require.NoError(t, err)
		_, err = tls.X509KeyPair(certPEM, keyPEM)
		require.NoError(t, err, "ca.crt and ca.key should form a valid TLS keypair")
	})

	t.Run("config structure", func(t *testing.T) {
		data, err := os.ReadFile(configPath)
		require.NoError(t, err)

		var cfg struct {
			Proxy struct {
				HTTPListen   string `yaml:"http_listen"`
				HTTPSListen  string `yaml:"https_listen"`
				TunnelListen string `yaml:"tunnel_listen"`
			} `yaml:"proxy"`
			TLS struct {
				CACert string `yaml:"ca_cert"`
				CAKey  string `yaml:"ca_key"`
			} `yaml:"tls"`
			Transforms []struct {
				Name   string `yaml:"name"`
				Config struct {
					Domains []string `yaml:"domains"`
				} `yaml:"config"`
			} `yaml:"transforms"`
			Log struct {
				Level string `yaml:"level"`
			} `yaml:"log"`
		}
		require.NoError(t, yaml.Unmarshal(data, &cfg))

		require.Equal(t, ":8080", cfg.Proxy.HTTPListen)
		require.Equal(t, ":8443", cfg.Proxy.HTTPSListen)
		require.Equal(t, ":"+tunnelPort, cfg.Proxy.TunnelListen)
		require.Equal(t, filepath.Join(configDir, "ca.crt"), cfg.TLS.CACert)
		require.Equal(t, filepath.Join(configDir, "ca.key"), cfg.TLS.CAKey)
		require.Len(t, cfg.Transforms, 1)
		require.Equal(t, "allowlist", cfg.Transforms[0].Name)
		require.Equal(t, []string{"httpbin.org", "example.com"}, cfg.Transforms[0].Config.Domains)
		require.Equal(t, "info", cfg.Log.Level)
	})

	t.Run("refuses without force", func(t *testing.T) {
		cmd := exec.Command(binary, "init",
			"--config-dir", configDir,
			"--no-start",
		)
		out, err := cmd.CombinedOutput()
		require.Error(t, err, "init should refuse when files already exist")
		require.Contains(t, string(out), "already configured")
	})

	t.Run("force overwrites", func(t *testing.T) {
		cmd := exec.Command(binary, "init",
			"--config-dir", configDir,
			"--tunnel-port", tunnelPort,
			"--no-start",
			"--force",
		)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "iron-proxy init --force failed: %s", string(out))

		// Files should still exist after force overwrite.
		for _, p := range []string{certPath, keyPath, configPath} {
			_, err := os.Stat(p)
			require.NoError(t, err, "expected %s to exist after --force", p)
		}
	})

	t.Run("proxy serves traffic", func(t *testing.T) {
		// Local upstream that echoes 200 OK.
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintln(w, "ok")
		}))
		defer upstream.Close()
		upstreamHost := upstream.Listener.Addr().String()

		// Rewrite the config with :0 for all listeners and the upstream
		// host in the allowlist so we stay entirely local.
		rewriteConfig(t, configPath, configDir, "0", []string{upstreamHost})

		proxy := startProxy(t, binary, configPath, nil)

		// Allowed: request with Host matching the allowlist.
		req, err := http.NewRequest("GET", "http://"+proxy.HTTPAddr+"/test", nil)
		require.NoError(t, err)
		req.Host = upstreamHost

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// Blocked: request with Host not in the allowlist.
		req, err = http.NewRequest("GET", "http://"+proxy.HTTPAddr+"/test", nil)
		require.NoError(t, err)
		req.Host = "not-allowed.example.com"

		resp, err = http.DefaultClient.Do(req)
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	})
}

// TestInitRequiresRoot verifies that init exits with an error when not root.
func TestInitRequiresRoot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test must run as non-root")
	}

	binary := proxyBinary(t)
	cmd := exec.Command(binary, "init")
	out, err := cmd.CombinedOutput()
	require.Error(t, err)
	require.Contains(t, string(out), "requires root")
}

// freePort asks the OS for a free port and returns it as a string.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return fmt.Sprintf("%d", port)
}

// rewriteConfig rewrites the proxy.yaml with dynamic listen ports and the
// given allowlist domains so the test doesn't collide with other services.
func rewriteConfig(t *testing.T, configPath, configDir, tunnelPort string, domains []string) {
	t.Helper()
	var domainLines string
	for _, d := range domains {
		domainLines += fmt.Sprintf("        - %q\n", d)
	}
	cfg := fmt.Sprintf(`dns:
  listen: ":0"
  proxy_ip: "127.0.0.1"

proxy:
  http_listen: ":8080"
  https_listen: ":8443"
  tunnel_listen: ":%s"

tls:
  ca_cert: "%s/ca.crt"
  ca_key: "%s/ca.key"

transforms:
  - name: allowlist
    config:
      domains:
%s
log:
  level: "info"
`, tunnelPort, configDir, configDir, domainLines)
	require.NoError(t, os.WriteFile(configPath, []byte(cfg), 0o644))
}
