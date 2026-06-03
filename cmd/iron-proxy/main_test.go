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

// staticSource is a no-op secrets.Source for building local test policies.
type staticSource struct{ name, value string }

func (s staticSource) Name() string                        { return s.name }
func (s staticSource) Get(context.Context) (string, error) { return s.value, nil }

func mapEnv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestPgEnv(t *testing.T) {
	cases := []struct {
		foreignID, suffix, want string
	}{
		{"pg-analytics", "LISTEN", "IRON_PROXY_PG_PG_ANALYTICS_LISTEN"},
		{"PG.Main", "CLIENT_USER", "IRON_PROXY_PG_PG_MAIN_CLIENT_USER"},
		{"warehouse~1", "CLIENT_PASSWORD", "IRON_PROXY_PG_WAREHOUSE_1_CLIENT_PASSWORD"},
		{"already_snake", "LISTEN", "IRON_PROXY_PG_ALREADY_SNAKE_LISTEN"},
		{"db123", "LISTEN", "IRON_PROXY_PG_DB123_LISTEN"},
	}
	for _, c := range cases {
		require.Equalf(t, c.want, pgEnv(c.foreignID, c.suffix), "pgEnv(%q,%q)", c.foreignID, c.suffix)
	}
}

func TestPostgresPoliciesFromSync_EnvPresent(t *testing.T) {
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-analytics","dsn":{"type":"env","var":"PG_ANALYTICS_DSN"},"role":"readonly"}]`)
	getenv := mapEnv(map[string]string{
		"IRON_PROXY_PG_PG_ANALYTICS_LISTEN":          "127.0.0.1:0",
		"IRON_PROXY_PG_PG_ANALYTICS_CLIENT_USER":     "app",
		"IRON_PROXY_PG_PG_ANALYTICS_CLIENT_PASSWORD": "s3cret",
	})

	policies, ok := postgresPoliciesFromSync(nil, getenv, discardLogger(), raw)
	require.True(t, ok)
	require.Len(t, policies, 1)
	require.Equal(t, "pg-analytics", policies[0].Name())
	require.Equal(t, "127.0.0.1:0", policies[0].Listen())
	require.Equal(t, "readonly", policies[0].Role())
	require.True(t, policies[0].VerifyClient("app", "s3cret"))
}

func TestPostgresPoliciesFromSync_NoRole(t *testing.T) {
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pgmain","dsn":{"type":"env","var":"PG_DSN"}}]`)
	getenv := mapEnv(map[string]string{
		"IRON_PROXY_PG_PGMAIN_LISTEN":          "127.0.0.1:0",
		"IRON_PROXY_PG_PGMAIN_CLIENT_USER":     "app",
		"IRON_PROXY_PG_PGMAIN_CLIENT_PASSWORD": "pw",
	})

	policies, ok := postgresPoliciesFromSync(nil, getenv, discardLogger(), raw)
	require.True(t, ok)
	require.Len(t, policies, 1)
	require.Empty(t, policies[0].Role(), "absent role must be a no-op")
}

func TestPostgresPoliciesFromSync_MissingEnvSkipped(t *testing.T) {
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-analytics","dsn":{"type":"env","var":"PG_DSN"}}]`)
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))

	// LISTEN is set but client credentials are missing: the entry is skipped,
	// not an error.
	getenv := mapEnv(map[string]string{
		"IRON_PROXY_PG_PG_ANALYTICS_LISTEN": "127.0.0.1:0",
	})

	policies, ok := postgresPoliciesFromSync(nil, getenv, logger, raw)
	require.True(t, ok)
	require.Empty(t, policies)
	require.Contains(t, logBuf.String(), "skipping synced postgres listener")
}

func TestPostgresPoliciesFromSync_LocalWinsOnConflict(t *testing.T) {
	local, err := postgres.NewManagedPolicy("pg-analytics", "127.0.0.1:0",
		staticSource{name: "local", value: "host=local"}, "localuser", "localpw", "")
	require.NoError(t, err)

	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-analytics","dsn":{"type":"env","var":"PG_DSN"},"role":"readonly"}]`)
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))
	getenv := mapEnv(map[string]string{
		"IRON_PROXY_PG_PG_ANALYTICS_LISTEN":          "127.0.0.1:0",
		"IRON_PROXY_PG_PG_ANALYTICS_CLIENT_USER":     "app",
		"IRON_PROXY_PG_PG_ANALYTICS_CLIENT_PASSWORD": "pw",
	})

	policies, ok := postgresPoliciesFromSync([]*postgres.Policy{local}, getenv, logger, raw)
	require.True(t, ok)
	require.Len(t, policies, 1, "synced entry colliding with local must be dropped")
	require.Same(t, local, policies[0])
	require.Empty(t, policies[0].Role(), "the local policy (no role) must win")
	require.Contains(t, logBuf.String(), "defined in both local config and control plane")
}

func TestPostgresPoliciesFromSync_InvalidPayload(t *testing.T) {
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))

	policies, ok := postgresPoliciesFromSync(nil, mapEnv(nil), logger, json.RawMessage(`{not an array`))
	require.False(t, ok, "invalid payload must signal keep-current")
	require.Nil(t, policies)
	require.Contains(t, logBuf.String(), "rejecting invalid postgres config")
}

func TestPostgresPoliciesFromSync_NullPayloadKeepsLocal(t *testing.T) {
	local, err := postgres.NewManagedPolicy("pgmain", "127.0.0.1:0",
		staticSource{name: "local", value: "host=local"}, "u", "p", "")
	require.NoError(t, err)

	policies, ok := postgresPoliciesFromSync([]*postgres.Policy{local}, mapEnv(nil), discardLogger(), json.RawMessage("null"))
	require.True(t, ok)
	require.Equal(t, []*postgres.Policy{local}, policies)
}

func TestApplyPostgresSync_ReloadsListeners(t *testing.T) {
	mgr := postgres.NewManager(discardLogger())
	t.Cleanup(func() { _ = mgr.Shutdown(context.Background()) })

	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-analytics","dsn":{"type":"env","var":"PG_DSN"}}]`)
	getenv := mapEnv(map[string]string{
		"IRON_PROXY_PG_PG_ANALYTICS_LISTEN":          "127.0.0.1:0",
		"IRON_PROXY_PG_PG_ANALYTICS_CLIENT_USER":     "app",
		"IRON_PROXY_PG_PG_ANALYTICS_CLIENT_PASSWORD": "pw",
	})

	applyPostgresSync(context.Background(), mgr, nil, getenv, discardLogger(), raw)
	require.Equal(t, []string{"pg-analytics"}, mgr.Names())
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
