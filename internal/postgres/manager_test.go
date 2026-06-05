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

// staticDSN is a no-op secrets.Source used to build test listeners. The
// manager tests never complete a postgres handshake; they only verify that
// the listener is accepting TCP connections, so the DSN value is never read.
type staticDSN struct{ name, value string }

func (s staticDSN) Name() string                        { return s.name }
func (s staticDSN) Get(context.Context) (string, error) { return s.value, nil }

func testListener(listen string) *Listener {
	return &Listener{
		name:           listenerName,
		listen:         listen,
		clientUser:     "u",
		clientPassword: "p",
		upstreams: map[string]*Upstream{
			"appdb": {
				database: "appdb",
				dsn:      staticDSN{name: "test", value: "host=127.0.0.1"},
			},
		},
	}
}

// waitForListener returns the bound address once m's server is listening. Fails
// the test if the bind never completes in time.
func waitForListener(t *testing.T, m *Manager) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		srv := m.server
		m.mu.Unlock()
		if srv != nil {
			if addr := srv.Addr(); addr != "" {
				return addr
			}
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

	m.Start(testListener("127.0.0.1:0"), errc)
	oldAddr := waitForListener(t, m)

	// Old listener is accepting connections.
	c, err := net.DialTimeout("tcp", oldAddr, time.Second)
	require.NoError(t, err)
	require.NoError(t, c.Close())

	// Reload swaps in a new listener. The old listener closes; a new one binds.
	m.Reload(context.Background(), testListener("127.0.0.1:0"))
	newAddr := waitForListener(t, m)
	require.NotEqual(t, oldAddr, newAddr)
	require.True(t, m.Running())

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

	m.Start(testListener("127.0.0.1:0"), errc)
	oldAddr := waitForListener(t, m)

	m.Reload(context.Background(), nil)
	require.False(t, m.Running())

	_, err := net.DialTimeout("tcp", oldAddr, 200*time.Millisecond)
	require.Error(t, err)

	require.NoError(t, m.Shutdown(context.Background()))
}
