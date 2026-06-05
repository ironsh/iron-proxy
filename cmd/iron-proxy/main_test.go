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

func TestPostgresListenerFromSync_Basic(t *testing.T) {
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-analytics","database":"analytics","dsn":{"type":"env","var":"PG_ANALYTICS_DSN"},"client_user":"app","client_password":"s3cret","role":"readonly"}]`)
	// The single bind address is the only thing read from the environment.
	getenv := mapEnv(map[string]string{"IRON_PROXY_PG_LISTEN": "127.0.0.1:0"})

	listener, ok := postgresListenerFromSync(nil, getenv, discardLogger(), raw)
	require.True(t, ok)
	require.NotNil(t, listener)
	require.Equal(t, "127.0.0.1:0", listener.Listen())

	// Routed by the synced database, which is independent of the foreign_id.
	upstream := listener.Upstream("analytics")
	require.NotNil(t, upstream)
	require.Nil(t, listener.Upstream("pg-analytics"))
	require.Equal(t, "readonly", upstream.Role())
	require.True(t, upstream.VerifyClient("app", "s3cret"))
}

func TestPostgresListenerFromSync_NoRole(t *testing.T) {
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pgmain","database":"maindb","dsn":{"type":"env","var":"PG_DSN"},"client_user":"app","client_password":"pw"}]`)
	getenv := mapEnv(map[string]string{"IRON_PROXY_PG_LISTEN": "127.0.0.1:0"})

	listener, ok := postgresListenerFromSync(nil, getenv, discardLogger(), raw)
	require.True(t, ok)
	require.NotNil(t, listener)
	require.Empty(t, listener.Upstream("maindb").Role(), "absent role must be a no-op")
}

func TestPostgresListenerFromSync_MissingCredsRejectsPayload(t *testing.T) {
	// Client credentials now come from the sync payload, so an entry missing
	// them is an invalid payload, not a skip.
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-analytics","database":"analytics","dsn":{"type":"env","var":"PG_DSN"}}]`)
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))
	getenv := mapEnv(map[string]string{"IRON_PROXY_PG_LISTEN": "127.0.0.1:0"})

	listener, ok := postgresListenerFromSync(nil, getenv, logger, raw)
	require.False(t, ok, "an entry missing client credentials is an invalid payload")
	require.Nil(t, listener)
	require.Contains(t, logBuf.String(), "rejecting invalid postgres config")
}

func TestPostgresListenerFromSync_NoListenAddressDropsUpstreams(t *testing.T) {
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-analytics","database":"analytics","dsn":{"type":"env","var":"PG_DSN"},"client_user":"app","client_password":"pw"}]`)
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))

	// No local listener and IRON_PROXY_PG_LISTEN unset: there is no address to
	// bind, so the synced upstreams are dropped.
	listener, ok := postgresListenerFromSync(nil, mapEnv(nil), logger, raw)
	require.True(t, ok)
	require.Nil(t, listener)
	require.Contains(t, logBuf.String(), "no listen address")
}

func TestPostgresListenerFromSync_MergesLocalAndSynced(t *testing.T) {
	local := localListener(t, "appdb")
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-analytics","database":"analytics","dsn":{"type":"env","var":"PG_DSN"},"client_user":"app","client_password":"pw"}]`)
	// No IRON_PROXY_PG_LISTEN: the bind address comes from the local listener.
	listener, ok := postgresListenerFromSync(local, mapEnv(nil), discardLogger(), raw)
	require.True(t, ok)
	require.NotNil(t, listener)
	require.Equal(t, local.Listen(), listener.Listen())
	require.NotNil(t, listener.Upstream("appdb"), "local upstream preserved")
	require.NotNil(t, listener.Upstream("analytics"), "synced upstream layered on")
}

func TestPostgresListenerFromSync_LocalWinsOnCollision(t *testing.T) {
	local := localListener(t, "shared")
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-analytics","database":"shared","dsn":{"type":"env","var":"PG_DSN"},"client_user":"app","client_password":"pw"}]`)
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))

	listener, ok := postgresListenerFromSync(local, mapEnv(nil), logger, raw)
	require.True(t, ok)
	require.NotNil(t, listener)
	// The local upstream (user "u") wins over the synced one (user "app").
	require.True(t, listener.Upstream("shared").VerifyClient("u", "p"))
	require.Contains(t, logBuf.String(), "duplicate database")
}

func TestPostgresListenerFromSync_DuplicateSyncedDatabaseDropped(t *testing.T) {
	raw := json.RawMessage(`[
		{"id":"pgs_1","foreign_id":"a","database":"shared","dsn":{"type":"env","var":"PG_DSN"},"client_user":"app","client_password":"pw"},
		{"id":"pgs_2","foreign_id":"b","database":"shared","dsn":{"type":"env","var":"PG_DSN"},"client_user":"app","client_password":"pw"}
	]`)
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))
	getenv := mapEnv(map[string]string{"IRON_PROXY_PG_LISTEN": "127.0.0.1:0"})

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

	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-analytics","database":"analytics","dsn":{"type":"env","var":"PG_DSN"},"client_user":"app","client_password":"pw"}]`)
	getenv := mapEnv(map[string]string{"IRON_PROXY_PG_LISTEN": "127.0.0.1:0"})

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
