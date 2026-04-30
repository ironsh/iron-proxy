package integration_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
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

// proxyInstance holds information about a running iron-proxy process.
type proxyInstance struct {
	HTTPAddr string
	cmd      *exec.Cmd

	addrsMu sync.Mutex
	addrs   map[string]string
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
		cmd:   cmd,
		addrs: make(map[string]string),
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
		p.addrs[entry.Msg] = entry.Addr
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
