package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/postgres"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"

	_ "github.com/ironsh/iron-proxy/internal/transform/allowlist"
	_ "github.com/ironsh/iron-proxy/internal/transform/secrets"
)

// staticSource is a no-op secrets.Source for building local test listeners.
type staticSource struct{ name, value string }

func (s staticSource) Name() string                        { return s.name }
func (s staticSource) Get(context.Context) (string, error) { return s.value, nil }

func mapEnv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// localListener builds a single-upstream local listener for conflict/passthrough
// tests.
func localListener(t *testing.T, database string) *postgres.Listener {
	t.Helper()
	u, err := postgres.NewManagedUpstream(database, staticSource{name: "local", value: "host=local"}, "u", "p", "")
	require.NoError(t, err)
	l, err := postgres.NewListener("127.0.0.1:0", []*postgres.Upstream{u})
	require.NoError(t, err)
	return l
}

func TestPgEnv(t *testing.T) {
	cases := []struct {
		foreignID, suffix, want string
	}{
		{"pg-analytics", "CLIENT_USER", "IRON_PROXY_PG_PG_ANALYTICS_CLIENT_USER"},
		{"PG.Main", "CLIENT_USER", "IRON_PROXY_PG_PG_MAIN_CLIENT_USER"},
		{"warehouse~1", "CLIENT_PASSWORD", "IRON_PROXY_PG_WAREHOUSE_1_CLIENT_PASSWORD"},
		{"already_snake", "CLIENT_PASSWORD", "IRON_PROXY_PG_ALREADY_SNAKE_CLIENT_PASSWORD"},
		{"db123", "CLIENT_USER", "IRON_PROXY_PG_DB123_CLIENT_USER"},
	}
	for _, c := range cases {
		require.Equalf(t, c.want, pgEnv(c.foreignID, c.suffix), "pgEnv(%q,%q)", c.foreignID, c.suffix)
	}
}

func TestPostgresListenerFromSync_EnvPresent(t *testing.T) {
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-analytics","database":"pg-analytics","dsn":{"type":"env","var":"PG_ANALYTICS_DSN"},"role":"readonly"}]`)
	getenv := mapEnv(map[string]string{
		"IRON_PROXY_PG_LISTEN":                       "127.0.0.1:0",
		"IRON_PROXY_PG_PG_ANALYTICS_CLIENT_USER":     "app",
		"IRON_PROXY_PG_PG_ANALYTICS_CLIENT_PASSWORD": "s3cret",
	})

	listener, ok := postgresListenerFromSync(nil, getenv, discardLogger(), raw)
	require.True(t, ok)
	require.NotNil(t, listener)
	require.Equal(t, "127.0.0.1:0", listener.Listen())

	// Routed by the synced database (here equal to the foreign_id).
	upstream := listener.Upstream("pg-analytics")
	require.NotNil(t, upstream)
	require.Equal(t, "readonly", upstream.Role())
	require.True(t, upstream.VerifyClient("app", "s3cret"))
}

func TestPostgresListenerFromSync_ExplicitDatabase(t *testing.T) {
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-analytics","database":"analytics","dsn":{"type":"env","var":"PG_DSN"}}]`)
	getenv := mapEnv(map[string]string{
		"IRON_PROXY_PG_LISTEN":                       "127.0.0.1:0",
		"IRON_PROXY_PG_PG_ANALYTICS_CLIENT_USER":     "app",
		"IRON_PROXY_PG_PG_ANALYTICS_CLIENT_PASSWORD": "pw",
	})

	listener, ok := postgresListenerFromSync(nil, getenv, discardLogger(), raw)
	require.True(t, ok)
	require.NotNil(t, listener)
	// Routing key is the explicit database, not the foreign_id.
	require.NotNil(t, listener.Upstream("analytics"))
	require.Nil(t, listener.Upstream("pg-analytics"))
}

func TestPostgresListenerFromSync_NoRole(t *testing.T) {
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pgmain","database":"pgmain","dsn":{"type":"env","var":"PG_DSN"}}]`)
	getenv := mapEnv(map[string]string{
		"IRON_PROXY_PG_LISTEN":                 "127.0.0.1:0",
		"IRON_PROXY_PG_PGMAIN_CLIENT_USER":     "app",
		"IRON_PROXY_PG_PGMAIN_CLIENT_PASSWORD": "pw",
	})

	listener, ok := postgresListenerFromSync(nil, getenv, discardLogger(), raw)
	require.True(t, ok)
	require.NotNil(t, listener)
	require.Empty(t, listener.Upstream("pgmain").Role(), "absent role must be a no-op")
}

func TestPostgresListenerFromSync_MissingCredsSkipsUpstream(t *testing.T) {
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-analytics","database":"pg-analytics","dsn":{"type":"env","var":"PG_DSN"}}]`)
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))

	// IRON_PROXY_PG_LISTEN is set but client credentials are missing: the upstream
	// is skipped, and with no usable upstreams no listener is built.
	getenv := mapEnv(map[string]string{
		"IRON_PROXY_PG_LISTEN": "127.0.0.1:0",
	})

	listener, ok := postgresListenerFromSync(nil, getenv, logger, raw)
	require.True(t, ok)
	require.Nil(t, listener)
	require.Contains(t, logBuf.String(), "skipping synced postgres upstream")
}

func TestPostgresListenerFromSync_NoListenAddressDropsUpstreams(t *testing.T) {
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-analytics","database":"pg-analytics","dsn":{"type":"env","var":"PG_DSN"}}]`)
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))

	// Credentials present but no local listener and IRON_PROXY_PG_LISTEN unset:
	// there is no address to bind, so the synced upstreams are dropped.
	getenv := mapEnv(map[string]string{
		"IRON_PROXY_PG_PG_ANALYTICS_CLIENT_USER":     "app",
		"IRON_PROXY_PG_PG_ANALYTICS_CLIENT_PASSWORD": "pw",
	})

	listener, ok := postgresListenerFromSync(nil, getenv, logger, raw)
	require.True(t, ok)
	require.Nil(t, listener)
	require.Contains(t, logBuf.String(), "no listen address")
}

func TestPostgresListenerFromSync_MergesLocalAndSynced(t *testing.T) {
	local := localListener(t, "appdb")
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-analytics","database":"analytics","dsn":{"type":"env","var":"PG_DSN"}}]`)
	getenv := mapEnv(map[string]string{
		// No IRON_PROXY_PG_LISTEN: the bind address comes from the local listener.
		"IRON_PROXY_PG_PG_ANALYTICS_CLIENT_USER":     "app",
		"IRON_PROXY_PG_PG_ANALYTICS_CLIENT_PASSWORD": "pw",
	})

	listener, ok := postgresListenerFromSync(local, getenv, discardLogger(), raw)
	require.True(t, ok)
	require.NotNil(t, listener)
	require.Equal(t, local.Listen(), listener.Listen())
	require.NotNil(t, listener.Upstream("appdb"), "local upstream preserved")
	require.NotNil(t, listener.Upstream("analytics"), "synced upstream layered on")
}

func TestPostgresListenerFromSync_LocalWinsOnCollision(t *testing.T) {
	local := localListener(t, "shared")
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-analytics","database":"shared","dsn":{"type":"env","var":"PG_DSN"}}]`)
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))
	getenv := mapEnv(map[string]string{
		"IRON_PROXY_PG_PG_ANALYTICS_CLIENT_USER":     "app",
		"IRON_PROXY_PG_PG_ANALYTICS_CLIENT_PASSWORD": "pw",
	})

	listener, ok := postgresListenerFromSync(local, getenv, logger, raw)
	require.True(t, ok)
	require.NotNil(t, listener)
	// The local upstream (user "u") wins over the synced one (user "app").
	require.True(t, listener.Upstream("shared").VerifyClient("u", "p"))
	require.Contains(t, logBuf.String(), "duplicate database")
}

func TestPostgresListenerFromSync_DuplicateSyncedDatabaseDropped(t *testing.T) {
	raw := json.RawMessage(`[
		{"id":"pgs_1","foreign_id":"a","database":"shared","dsn":{"type":"env","var":"PG_DSN"}},
		{"id":"pgs_2","foreign_id":"b","database":"shared","dsn":{"type":"env","var":"PG_DSN"}}
	]`)
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))
	getenv := mapEnv(map[string]string{
		"IRON_PROXY_PG_LISTEN":            "127.0.0.1:0",
		"IRON_PROXY_PG_A_CLIENT_USER":     "app",
		"IRON_PROXY_PG_A_CLIENT_PASSWORD": "pw",
		"IRON_PROXY_PG_B_CLIENT_USER":     "app",
		"IRON_PROXY_PG_B_CLIENT_PASSWORD": "pw",
	})

	listener, ok := postgresListenerFromSync(nil, getenv, logger, raw)
	require.True(t, ok)
	require.NotNil(t, listener)
	require.Len(t, listener.Upstreams(), 1)
	require.NotNil(t, listener.Upstream("shared"))
	require.Contains(t, logBuf.String(), "duplicate database")
}

func TestPostgresListenerFromSync_InvalidPayload(t *testing.T) {
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))

	listener, ok := postgresListenerFromSync(nil, mapEnv(nil), logger, json.RawMessage(`{not an array`))
	require.False(t, ok, "invalid payload must signal keep-current")
	require.Nil(t, listener)
	require.Contains(t, logBuf.String(), "rejecting invalid postgres config")
}

func TestPostgresListenerFromSync_NullPayloadKeepsLocal(t *testing.T) {
	local := localListener(t, "appdb")

	listener, ok := postgresListenerFromSync(local, mapEnv(nil), discardLogger(), json.RawMessage("null"))
	require.True(t, ok)
	require.NotNil(t, listener)
	require.Equal(t, local.Listen(), listener.Listen())
	require.NotNil(t, listener.Upstream("appdb"))
}

func TestApplyPostgresSync_ReloadsListener(t *testing.T) {
	mgr := postgres.NewManager(discardLogger())
	t.Cleanup(func() { _ = mgr.Shutdown(context.Background()) })

	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-analytics","database":"pg-analytics","dsn":{"type":"env","var":"PG_DSN"}}]`)
	getenv := mapEnv(map[string]string{
		"IRON_PROXY_PG_LISTEN":                       "127.0.0.1:0",
		"IRON_PROXY_PG_PG_ANALYTICS_CLIENT_USER":     "app",
		"IRON_PROXY_PG_PG_ANALYTICS_CLIENT_PASSWORD": "pw",
	})

	applyPostgresSync(context.Background(), mgr, nil, getenv, discardLogger(), raw)
	require.True(t, mgr.Running())
}

var _ secrets.Source = staticSource{}

func TestApplyPipelineSync_ValidConfig_Swaps(t *testing.T) {
	original := transform.NewPipeline(nil, transform.BodyLimits{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	holder := transform.NewPipelineHolder(original)

	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))

	rules := json.RawMessage(`[{"host":"example.com","methods":["GET"],"paths":["/api/*"]}]`)
	applyPipelineSync(holder, transform.BodyLimits{}, logger, rules, nil, nil)

	require.NotSame(t, original, holder.Load(), "pipeline should have been swapped")
	require.Equal(t, "allowlist", holder.Load().Names())
	require.Contains(t, logBuf.String(), "pipeline reloaded")
}

func TestApplyPipelineSync_InvalidJSON_KeepsExistingPipeline(t *testing.T) {
	original := transform.NewPipeline(nil, transform.BodyLimits{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	holder := transform.NewPipelineHolder(original)

	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))

	applyPipelineSync(holder, transform.BodyLimits{}, logger, json.RawMessage(`{not json`), nil, nil)

	require.Same(t, original, holder.Load(), "pipeline must not be swapped on invalid config")
	require.Contains(t, logBuf.String(), "rejecting invalid pipeline config")
	require.Contains(t, logBuf.String(), "level=ERROR")
}

func TestApplyPipelineSync_InvalidRule_KeepsExistingPipeline(t *testing.T) {
	original := transform.NewPipeline(nil, transform.BodyLimits{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	holder := transform.NewPipelineHolder(original)

	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))

	// host and cidr are mutually exclusive — rule construction fails.
	rules := json.RawMessage(`[{"host":"example.com","cidr":"10.0.0.0/8"}]`)
	applyPipelineSync(holder, transform.BodyLimits{}, logger, rules, nil, nil)

	require.Same(t, original, holder.Load(), "pipeline must not be swapped when transform construction fails")
	require.Contains(t, logBuf.String(), "rejecting invalid pipeline config")
	require.Contains(t, logBuf.String(), "level=ERROR")
}

func TestApplyPipelineSync_PreservesAuditFunc(t *testing.T) {
	original := transform.NewPipeline(nil, transform.BodyLimits{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	called := false
	original.SetAuditFunc(func(*transform.PipelineResult) { called = true })
	holder := transform.NewPipelineHolder(original)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	rules := json.RawMessage(`[{"host":"example.com"}]`)
	applyPipelineSync(holder, transform.BodyLimits{}, logger, rules, nil, nil)

	holder.Load().EmitAudit(nil)
	require.True(t, called, "audit func should be carried over to the new pipeline")
}
