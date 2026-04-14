package integration_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"text/template"
	"time"

	"github.com/stretchr/testify/require"
)

// proxyInstance holds information about a running iron-proxy process.
type proxyInstance struct {
	HTTPAddr string
	cmd      *exec.Cmd
}

// startProxy compiles (if needed) and starts the iron-proxy binary with the
// given config and environment. It parses the JSON log output to discover
// the actual HTTP listen address (supports :0). The proxy is killed when the
// test completes.
func startProxy(t *testing.T, binary, cfgPath string, env []string) *proxyInstance {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())

	// Pipe stderr so we can read JSON log lines.
	stderrR, stderrW := io.Pipe()

	cmd := exec.CommandContext(ctx, binary, "-config", cfgPath)
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

	// Tee stderr to os.Stderr so all log lines are visible while we scan
	// for the HTTP listen address.
	tee := io.TeeReader(stderrR, os.Stderr)
	httpAddr := parseHTTPAddr(t, tee)

	// Continue draining stderr after we have the address.
	go func() {
		_, _ = io.Copy(os.Stderr, tee)
	}()

	return &proxyInstance{
		HTTPAddr: httpAddr,
		cmd:      cmd,
	}
}

// parseHTTPAddr reads JSON log lines from r until it finds the
// "http proxy starting" message and returns the addr field.
func parseHTTPAddr(t *testing.T, r io.Reader) string {
	t.Helper()

	type logLine struct {
		Msg  string `json:"msg"`
		Addr string `json:"addr"`
	}

	scanner := bufio.NewScanner(r)
	deadline := time.After(10 * time.Second)
	found := make(chan string, 1)

	go func() {
		for scanner.Scan() {
			var line logLine
			if json.Unmarshal(scanner.Bytes(), &line) != nil {
				continue
			}
			if line.Msg == "http proxy starting" && line.Addr != "" {
				found <- line.Addr
				return
			}
		}
	}()

	select {
	case addr := <-found:
		return addr
	case <-deadline:
		t.Fatal("timed out waiting for proxy to log HTTP listen address")
		return ""
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
