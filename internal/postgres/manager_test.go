package postgres

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// staticDSN is a no-op secrets.Source used to build test policies. The
// manager tests never complete a postgres handshake; they only verify that
// the listener is accepting TCP connections, so the DSN value is never read.
type staticDSN struct{ name, value string }

func (s staticDSN) Name() string                       { return s.name }
func (s staticDSN) Get(context.Context) (string, error) { return s.value, nil }

func testPolicy(name, listen string) *Policy {
	return &Policy{
		name:           name,
		listen:         listen,
		upstreamDSN:    staticDSN{name: "test", value: "host=127.0.0.1"},
		clientUser:     "u",
		clientPassword: "p",
	}
}

// waitForListener returns the bound address once the first server in m is
// listening. Fails the test if the bind never completes in time.
func waitForListener(t *testing.T, m *Manager) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		if len(m.servers) > 0 {
			addr := m.servers[0].Addr()
			m.mu.Unlock()
			if addr != "" {
				return addr
			}
		} else {
			m.mu.Unlock()
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("listener never bound")
	return ""
}

func TestManagerReload(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := NewManager(logger)
	errc := make(chan error, 2)

	m.Start([]*Policy{testPolicy("initial", "127.0.0.1:0")}, errc)
	oldAddr := waitForListener(t, m)

	// Old listener is accepting connections.
	c, err := net.DialTimeout("tcp", oldAddr, time.Second)
	require.NoError(t, err)
	require.NoError(t, c.Close())

	// Reload swaps in a new policy. The old listener closes; a new one binds.
	m.Reload(context.Background(), []*Policy{testPolicy("reloaded", "127.0.0.1:0")})
	newAddr := waitForListener(t, m)
	require.NotEqual(t, oldAddr, newAddr)
	require.Equal(t, []string{"reloaded"}, m.Names())

	// New listener accepts.
	c, err = net.DialTimeout("tcp", newAddr, time.Second)
	require.NoError(t, err)
	require.NoError(t, c.Close())

	// Old address is no longer accepting connections.
	_, err = net.DialTimeout("tcp", oldAddr, 200*time.Millisecond)
	require.Error(t, err)

	require.NoError(t, m.Shutdown(context.Background()))

	select {
	case err := <-errc:
		t.Fatalf("unexpected fatal error from initial Start: %v", err)
	default:
	}
}

func TestManagerReloadToEmpty(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := NewManager(logger)
	errc := make(chan error, 1)

	m.Start([]*Policy{testPolicy("initial", "127.0.0.1:0")}, errc)
	oldAddr := waitForListener(t, m)

	m.Reload(context.Background(), nil)
	require.Empty(t, m.Names())

	_, err := net.DialTimeout("tcp", oldAddr, 200*time.Millisecond)
	require.Error(t, err)

	require.NoError(t, m.Shutdown(context.Background()))
}
