package integration_test

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"text/template"
	"time"

	"github.com/stretchr/testify/require"
)

// echoHeadersUpstream starts an httptest.Server that copies each named request
// header into a response header of the same name with "Got-" inserted after
// the leading "X-" (so "X-Foo-Secret" is echoed back as "X-Got-Foo-Secret").
// Returns the upstream's host:port. The server is closed on test cleanup.
func echoHeadersUpstream(t *testing.T, headers ...string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, h := range headers {
			w.Header().Set(echoedHeaderName(h), r.Header.Get(h))
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

// echoedHeaderName returns the response header name used by echoHeadersUpstream
// for a given request header: "X-Foo" -> "X-Got-Foo".
func echoedHeaderName(h string) string {
	if rest, ok := strings.CutPrefix(h, "X-"); ok {
		return "X-Got-" + rest
	}
	return "X-Got-" + h
}

// proxyGet sends a GET through proxyAddr with Host=upstreamHost and the given
// request headers, drains the body, and returns the status code and response
// headers. Fails the test on transport errors.
func proxyGet(t *testing.T, proxyAddr, upstreamHost string, reqHeaders map[string]string) (int, http.Header) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+proxyAddr+"/", nil)
	require.NoError(t, err)
	req.Host = upstreamHost
	for k, v := range reqHeaders {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, resp.Header
}

// requireEnv returns the value of envVar, calling t.Skip if it is empty.
func requireEnv(t *testing.T, envVar string) string {
	t.Helper()
	v := os.Getenv(envVar)
	if v == "" {
		t.Skipf("%s not set; skipping", envVar)
	}
	return v
}

// generateServiceAccountKeyPEM returns a freshly-minted RSA private key in
// PEM (PKCS#8) form, suitable for embedding in a service-account JSON keyfile.
// Used by tests that construct synthetic GCP credentials.
func generateServiceAccountKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// proxyInstance holds information about a running iron-proxy process.
type proxyInstance struct {
	HTTPAddr string
	cmd      *exec.Cmd

	addrsMu     sync.Mutex
	addrs       map[string]string
	namedAddrs  map[string]string // key: msg+"|"+name (for log lines that include a name field, like postgres servers).
}

// AddrFor blocks until a JSON log line with the given "starting" msg has been
// observed and returns its addr field. Useful for services configured with
// listen ":0" — the actual bound port is only known via the log.
func (p *proxyInstance) AddrFor(t *testing.T, msg string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		p.addrsMu.Lock()
		addr, ok := p.addrs[msg]
		p.addrsMu.Unlock()
		if ok {
			return addr
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for log line %q", msg)
			return ""
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// AddrForNamed blocks until a JSON log line with the given "starting" msg and
// name field has been observed and returns its addr. Used when multiple
// services share a starting message (e.g. the postgres listener writes one
// "postgres proxy starting" log line per configured server).
func (p *proxyInstance) AddrForNamed(t *testing.T, msg, name string) string {
	t.Helper()
	key := msg + "|" + name
	deadline := time.Now().Add(10 * time.Second)
	for {
		p.addrsMu.Lock()
		addr, ok := p.namedAddrs[key]
		p.addrsMu.Unlock()
		if ok {
			return addr
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for log line %q (name=%q)", msg, name)
			return ""
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// startProxy compiles (if needed) and starts the iron-proxy binary with the
// given config and environment. It scans the JSON log output to discover
// listen addresses (supports :0). The proxy is killed when the test completes.
func startProxy(t *testing.T, binary, cfgPath string, env []string) *proxyInstance {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())

	stderrR, stderrW := io.Pipe()

	cmd := exec.CommandContext(ctx, binary, "-config", cfgPath)
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), env...)
	cmd.Env = append(cmd.Env, "IRON_STATE_STORE="+t.TempDir())
	cmd.Stdout = os.Stderr
	cmd.Stderr = stderrW
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
		_ = stderrW.Close()
	})

	p := &proxyInstance{
		cmd:        cmd,
		addrs:      make(map[string]string),
		namedAddrs: make(map[string]string),
	}

	go scanLogs(stderrR, p)

	p.HTTPAddr = p.AddrFor(t, "http proxy starting")
	return p
}

// scanLogs reads the proxy's stderr line-by-line, tees raw bytes to os.Stderr
// for visibility, and records the addr field of every "X starting" log line
// for later lookup via AddrFor.
func scanLogs(r io.Reader, p *proxyInstance) {
	type logLine struct {
		Msg  string `json:"msg"`
		Addr string `json:"addr"`
		Name string `json:"name"`
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		_, _ = os.Stderr.Write(append(append([]byte{}, line...), '\n'))

		var entry logLine
		if json.Unmarshal(line, &entry) != nil {
			continue
		}
		if !strings.HasSuffix(entry.Msg, "starting") || entry.Addr == "" {
			continue
		}
		p.addrsMu.Lock()
		// Always record under the msg alone (last writer wins). Multi-listener
		// services (e.g. postgres with N configured servers) should look up by
		// (msg, name) via AddrForNamed instead.
		p.addrs[entry.Msg] = entry.Addr
		if entry.Name != "" {
			p.namedAddrs[entry.Msg+"|"+entry.Name] = entry.Addr
		}
		p.addrsMu.Unlock()
	}
}

// proxyBinary returns the path to the pre-built iron-proxy binary at the repo
// root. It fails the test immediately if the binary does not exist.
func proxyBinary(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(repoRoot(t), "iron-proxy")
	_, err := os.Stat(binary)
	if err != nil {
		t.Fatal("iron-proxy binary not found at repo root; build it first with: go build -o iron-proxy ./cmd/iron-proxy")
	}
	return binary
}

// brokerBinary returns the path to the pre-built iron-token-broker binary at
// the repo root. It fails the test immediately if the binary does not exist.
func brokerBinary(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(repoRoot(t), "iron-token-broker")
	_, err := os.Stat(binary)
	if err != nil {
		t.Fatal("iron-token-broker binary not found at repo root; build it first with: go build -o iron-token-broker ./cmd/iron-token-broker")
	}
	return binary
}

// startBroker compiles (if needed) and starts the iron-token-broker binary with
// the given config and environment. It scans the JSON log output to discover
// the bound HTTP API address (supports :0). The broker is killed when the
// test completes. Reuses proxyInstance because the address-discovery flow is
// identical to the proxy — only the binary, flag name, and starting-log
// message differ.
func startBroker(t *testing.T, binary, cfgPath string, env []string) *proxyInstance {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	stderrR, stderrW := io.Pipe()

	cmd := exec.CommandContext(ctx, binary, "--config", cfgPath)
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = stderrW
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
		_ = stderrW.Close()
	})

	p := &proxyInstance{
		cmd:        cmd,
		addrs:      make(map[string]string),
		namedAddrs: make(map[string]string),
	}

	go scanLogs(stderrR, p)

	p.HTTPAddr = p.AddrFor(t, "broker HTTP API starting")
	return p
}

// repoRoot walks up from the current directory to find the go.mod file.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (no go.mod)")
		}
		dir = parent
	}
}

// renderConfig parses a template from testdata/ and renders it with the given
// data, writing the result to a temporary config file. Returns the file path.
func renderConfig(t *testing.T, tmpDir, templateName string, data any) string {
	t.Helper()
	tmplPath := filepath.Join(repoRoot(t), "integration_test", "testdata", templateName)
	tmpl, err := template.ParseFiles(tmplPath)
	require.NoError(t, err)

	cfgPath := filepath.Join(tmpDir, "config.yaml")
	f, err := os.Create(cfgPath)
	require.NoError(t, err)
	defer f.Close()

	require.NoError(t, tmpl.Execute(f, data))
	return cfgPath
}
