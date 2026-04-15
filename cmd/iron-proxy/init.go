package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ironsh/iron-proxy/internal/cagen"
)

const (
	defaultConfigDir  = "/etc/iron-proxy"
	defaultTunnelPort = "1080"
	defaultAllowList  = "httpbin.org"
	defaultLogFile    = "/var/log/iron-proxy.log"
)

func runInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	configDir := fs.String("config-dir", defaultConfigDir, "directory for config, CA cert, and CA key")
	tunnelPort := fs.String("tunnel-port", defaultTunnelPort, "port for the CONNECT/SOCKS5 tunnel listener")
	proxyIP := fs.String("proxy-ip", "127.0.0.1", "IP address the DNS server returns for proxied domains")
	allow := fs.String("allow", defaultAllowList, "comma-separated domains for the initial allowlist")
	bootstrapToken := fs.String("bootstrap-token", "", "bootstrap token for control plane registration (managed mode)")
	noStart := fs.Bool("no-start", false, "generate config and unit file but don't start the service")
	force := fs.Bool("force", false, "overwrite existing config and CA")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Require root.
	if os.Getuid() != 0 {
		fmt.Fprintln(os.Stderr, "iron-proxy init requires root. Run: sudo iron-proxy init")
		os.Exit(1)
	}

	certPath := filepath.Join(*configDir, "ca.crt")
	keyPath := filepath.Join(*configDir, "ca.key")
	configPath := filepath.Join(*configDir, "proxy.yaml")

	// Check for existing files unless --force.
	if !*force {
		for _, p := range []string{configPath, certPath} {
			if _, err := os.Stat(p); err == nil {
				fmt.Fprintf(os.Stderr, "iron-proxy is already configured. Use --force to overwrite.\n")
				os.Exit(1)
			}
		}
	}

	// 1. Generate CA certificate and key.
	if *force {
		// Remove existing files so cagen.WriteFiles doesn't refuse.
		// Errors are ignored: the files may not exist, and any real
		// permission issue will surface in cagen.WriteFiles.
		_ = os.Remove(certPath)
		_ = os.Remove(keyPath)
	}

	result, err := cagen.Generate(cagen.Options{
		Name:        "iron-proxy CA",
		ExpiryHours: 2160, // 90 days
		Algorithm:   cagen.RSA4096,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error generating CA: %v\n", err)
		os.Exit(1)
	}

	if _, _, err := cagen.WriteFiles(*configDir, result); err != nil {
		fmt.Fprintf(os.Stderr, "error writing CA files: %v\n", err)
		os.Exit(1)
	}

	// 2. Write default config.
	managedMode := *bootstrapToken != ""
	var configYAML string
	if managedMode {
		configYAML = generateManagedConfig(*configDir, *tunnelPort, *proxyIP)
	} else {
		domains := parseDomainList(*allow)
		configYAML = generateConfig(*configDir, *tunnelPort, *proxyIP, domains)
	}
	if err := os.WriteFile(configPath, []byte(configYAML), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error writing config: %v\n", err)
		os.Exit(1)
	}

	// 3. Install and start the service.
	execPath := resolveExecPath()

	hasSystemd := hasSystemd()
	if hasSystemd {
		unitContent := generateSystemdUnit(execPath, configPath, *bootstrapToken)
		unitPath := "/etc/systemd/system/iron-proxy.service"
		if err := os.WriteFile(unitPath, []byte(unitContent), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing systemd unit: %v\n", err)
			os.Exit(1)
		}

		if err := runCommand("systemctl", "daemon-reload"); err != nil {
			fmt.Fprintf(os.Stderr, "error: systemctl daemon-reload: %v\n", err)
			os.Exit(1)
		}

		if err := runCommand("systemctl", "enable", "iron-proxy"); err != nil {
			fmt.Fprintf(os.Stderr, "error: systemctl enable: %v\n", err)
			os.Exit(1)
		}

		if !*noStart {
			if err := runCommand("systemctl", "start", "iron-proxy"); err != nil {
				fmt.Fprintf(os.Stderr, "error: systemctl start: %v\n", err)
				os.Exit(1)
			}

			if err := waitForService(); err != nil {
				fmt.Fprintf(os.Stderr, "error: iron-proxy failed to start\n")
				printLogTail()
				os.Exit(1)
			}
		}

		if managedMode {
			printSuccessManagedSystemd(*configDir, *tunnelPort, *noStart)
		} else {
			printSuccessSystemd(*configDir, *tunnelPort, *noStart)
		}
	} else {
		// Non-systemd fallback: start as a background process.
		if *noStart {
			printSuccessNoStart(*configDir, *tunnelPort)
			return
		}

		pid, err := startBackground(execPath, configPath, *bootstrapToken)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error starting iron-proxy: %v\n", err)
			os.Exit(1)
		}

		pidPath := filepath.Join(*configDir, "iron-proxy.pid")
		if err := os.WriteFile(pidPath, []byte(strconv.Itoa(pid)), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing PID file: %v\n", err)
			os.Exit(1)
		}

		printSuccessBackground(*configDir, *tunnelPort, pid)
	}
}

func parseDomainList(s string) []string {
	parts := strings.Split(s, ",")
	domains := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			domains = append(domains, p)
		}
	}
	return domains
}

// generateManagedConfig produces a YAML config for managed mode. It omits the
// transforms section since transforms come from the control plane.
func generateManagedConfig(configDir, tunnelPort, proxyIP string) string {
	return fmt.Sprintf(`proxy:
  http_listen: ":8080"
  https_listen: ":8443"
  tunnel_listen: ":%s"

dns:
  listen: ":8053"
  proxy_ip: "%s"

tls:
  ca_cert: "%s/ca.crt"
  ca_key: "%s/ca.key"

log:
  level: "info"
`, tunnelPort, proxyIP, configDir, configDir)
}

func generateConfig(configDir, tunnelPort, proxyIP string, domains []string) string {
	var domainLines string
	for _, d := range domains {
		domainLines += fmt.Sprintf("        - %q\n", d)
	}

	return fmt.Sprintf(`proxy:
  http_listen: ":8080"
  https_listen: ":8443"
  tunnel_listen: ":%s"

dns:
  listen: ":8053"
  proxy_ip: "%s"

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
`, tunnelPort, proxyIP, configDir, configDir, domainLines)
}

func generateSystemdUnit(execPath, configPath, bootstrapToken string) string {
	var envLine string
	if bootstrapToken != "" {
		envLine = fmt.Sprintf("Environment=IRON_BOOTSTRAP_TOKEN=%s\n", bootstrapToken)
	}

	return fmt.Sprintf(`[Unit]
Description=iron-proxy egress firewall
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s -config %s
Restart=on-failure
RestartSec=5
%sStandardOutput=append:/var/log/iron-proxy.log
StandardError=append:/var/log/iron-proxy.log

[Install]
WantedBy=multi-user.target
`, execPath, configPath, envLine)
}

func resolveExecPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "/usr/local/bin/iron-proxy"
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return exe
	}
	return resolved
}

func hasSystemd() bool {
	_, err := exec.LookPath("systemctl")
	if err != nil {
		return false
	}
	// systemctl may be installed but systemd might not be running as the init
	// system (e.g., in containers or WSL). Check that PID 1 is systemd.
	out, err := exec.Command("ps", "-p", "1", "-o", "comm=").Output()
	if err != nil {
		return false
	}
	comm := strings.TrimSpace(string(out))
	return comm == "systemd"
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func waitForService() error {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		out, err := exec.Command("systemctl", "is-active", "iron-proxy").Output()
		if err == nil && strings.TrimSpace(string(out)) == "active" {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("service did not become active within 3 seconds")
}

func printLogTail() {
	data, err := os.ReadFile(defaultLogFile)
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	start := 0
	if len(lines) > 10 {
		start = len(lines) - 10
	}
	fmt.Fprintln(os.Stderr, "\nLast log lines:")
	for _, line := range lines[start:] {
		if line != "" {
			fmt.Fprintln(os.Stderr, "  "+line)
		}
	}
}

func startBackground(execPath, configPath, bootstrapToken string) (int, error) {
	logFile, err := os.OpenFile(defaultLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return 0, fmt.Errorf("opening log file: %w", err)
	}

	cmd := exec.Command(execPath, "-config", configPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if bootstrapToken != "" {
		cmd.Env = append(os.Environ(), "IRON_BOOTSTRAP_TOKEN="+bootstrapToken)
	}

	if err := cmd.Start(); err != nil {
		logFile.Close()
		return 0, fmt.Errorf("starting process: %w", err)
	}

	// Close our handle to the log file; the child has its own.
	logFile.Close()

	return cmd.Process.Pid, nil
}

func printSuccessManagedSystemd(configDir, tunnelPort string, noStart bool) {
	fmt.Printf("✓ Generated CA certificate     %s/ca.crt\n", configDir)
	fmt.Printf("✓ Wrote config                 %s/proxy.yaml\n", configDir)
	if noStart {
		fmt.Println("✓ Installed systemd unit       systemctl start iron-proxy")
	} else {
		fmt.Println("✓ Started iron-proxy service   systemctl status iron-proxy")
	}

	fmt.Printf(`
iron-proxy is configured in managed mode (control plane).

Transforms and rules will be fetched from the control plane.

  # View audit logs
  tail -f /var/log/iron-proxy.log

Next steps:

  Config reference             https://docs.iron.sh/reference/configuration
  Control plane dashboard      https://console.iron.sh
`)
}

func printSuccessSystemd(configDir, tunnelPort string, noStart bool) {
	fmt.Printf("✓ Generated CA certificate     %s/ca.crt\n", configDir)
	fmt.Printf("✓ Wrote config                 %s/proxy.yaml\n", configDir)
	if noStart {
		fmt.Println("✓ Installed systemd unit       systemctl start iron-proxy")
	} else {
		fmt.Println("✓ Started iron-proxy service   systemctl status iron-proxy")
	}

	fmt.Printf(`
iron-proxy is running on :%s (CONNECT tunnel mode).

Try it:

  # Allowed (httpbin.org is in the allowlist)
  curl --cacert %s/ca.crt --proxy http://localhost:%s https://httpbin.org/get

  # Blocked (everything else returns 403)
  curl --cacert %s/ca.crt --proxy http://localhost:%s https://example.com

  # View audit logs
  tail -f /var/log/iron-proxy.log

Next steps:

  Config reference             https://docs.iron.sh/reference/configuration
  Enable secret proxying       https://docs.iron.sh/reference/secret-proxying
  Production deployment        https://docs.iron.sh/reference/deployment-methods
`, tunnelPort, configDir, tunnelPort, configDir, tunnelPort)
}

func printSuccessBackground(configDir, tunnelPort string, pid int) {
	fmt.Printf("✓ Generated CA certificate     %s/ca.crt\n", configDir)
	fmt.Printf("✓ Wrote config                 %s/proxy.yaml\n", configDir)
	fmt.Printf("✓ iron-proxy running           pid %d → /var/log/iron-proxy.log\n", pid)

	fmt.Printf(`
Try it:

  # Allowed (httpbin.org is in the allowlist)
  curl --cacert %s/ca.crt --proxy http://localhost:%s https://httpbin.org/get

  # Blocked (everything else returns 403)
  curl --cacert %s/ca.crt --proxy http://localhost:%s https://example.com

  # View audit logs
  tail -f /var/log/iron-proxy.log

  # Stop iron-proxy
  kill $(cat %s/iron-proxy.pid)

Next steps:

  Config reference             https://docs.iron.sh/reference/configuration
  Enable secret proxying       https://docs.iron.sh/reference/secret-proxying
  Production deployment        https://docs.iron.sh/reference/deployment-methods
`, configDir, tunnelPort, configDir, tunnelPort, configDir)
}

func printSuccessNoStart(configDir, tunnelPort string) {
	fmt.Println("✓ Generated CA certificate     " + configDir + "/ca.crt")
	fmt.Println("✓ Wrote config                 " + configDir + "/proxy.yaml")
	fmt.Printf("\nConfig written. Start iron-proxy manually:\n\n")
	fmt.Printf("  iron-proxy -config %s/proxy.yaml\n\n", configDir)
}
