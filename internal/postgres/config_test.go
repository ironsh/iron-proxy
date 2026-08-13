package postgres

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

// dsnNode builds a non-zero yaml.Node so the dsn presence check (Kind != 0)
// passes. The stub buildSource ignores its contents.
func dsnNode(t *testing.T) yaml.Node {
	t.Helper()
	var n yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte("{type: env, var: X}"), &n))
	// Unmarshal yields a DocumentNode wrapping the mapping; unwrap it.
	require.NotEmpty(t, n.Content)
	return *n.Content[0]
}

// stubSource returns a no-op secrets.Source for every node, so Compile never
// touches a real backend.
func stubSource(yaml.Node, *slog.Logger) (secrets.Source, error) {
	return staticDSN{name: "stub", value: "host=db"}, nil
}

func TestCompile(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Setenv("PG_PW", "secret")

	upstream := func(database string) UpstreamConfig {
		return UpstreamConfig{Database: database, DSN: dsnNode(t), Role: "r"}
	}
	client := ClientConfig{User: "u", PasswordEnv: "PG_PW"}
	cfg := func(upstreams ...UpstreamConfig) ListenerConfig {
		return ListenerConfig{Listen: "127.0.0.1:0", Client: client, Upstreams: upstreams}
	}

	t.Run("valid single listener many upstreams", func(t *testing.T) {
		l, err := Compile(cfg(upstream("analytics"), upstream("reporting")), logger, stubSource)
		require.NoError(t, err)
		require.NotNil(t, l)
		require.Equal(t, "127.0.0.1:0", l.Listen())
		require.Equal(t, "analytics", l.Upstream("analytics").Database())
		require.Equal(t, "reporting", l.Upstream("reporting").Database())
		require.Nil(t, l.Upstream("missing"))
		// The client credential is shared across the listener, not per-upstream.
		require.True(t, l.VerifyClient("u", "secret"))
		require.False(t, l.VerifyClient("u", "wrong"))
	})

	t.Run("empty block is a no-op", func(t *testing.T) {
		l, err := Compile(ListenerConfig{}, logger, stubSource)
		require.NoError(t, err)
		require.Nil(t, l)
	})

	t.Run("listen is required", func(t *testing.T) {
		c := cfg(upstream("a"))
		c.Listen = ""
		_, err := Compile(c, logger, stubSource)
		require.ErrorContains(t, err, "listen is required")
	})

	t.Run("client fields required", func(t *testing.T) {
		c := cfg(upstream("a"))
		c.Client.User = ""
		_, err := Compile(c, logger, stubSource)
		require.ErrorContains(t, err, "client.user is required")

		c = cfg(upstream("a"))
		c.Client.PasswordEnv = ""
		_, err = Compile(c, logger, stubSource)
		require.ErrorContains(t, err, "client.password_env is required")
	})

	t.Run("unset password env rejected", func(t *testing.T) {
		c := cfg(upstream("a"))
		c.Client.PasswordEnv = "PG_PW_UNSET"
		_, err := Compile(c, logger, stubSource)
		require.ErrorContains(t, err, "is not set in the environment")
	})

	t.Run("at least one upstream is required", func(t *testing.T) {
		_, err := Compile(cfg(), logger, stubSource)
		require.ErrorContains(t, err, "at least one upstream is required")
	})

	t.Run("duplicate upstream route rejected", func(t *testing.T) {
		_, err := Compile(cfg(upstream("dup"), upstream("dup")), logger, stubSource)
		require.ErrorContains(t, err, `duplicate upstream route "dup"`)
	})

	t.Run("multiple routes require selectors", func(t *testing.T) {
		legacy := upstream("shared")
		named := upstream("shared")
		named.Route = "reader"
		_, err := Compile(cfg(legacy, named), logger, stubSource)
		require.ErrorContains(t, err, `database "shared" has multiple upstreams`)
	})

	t.Run("upstream database is required", func(t *testing.T) {
		_, err := Compile(cfg(upstream("")), logger, stubSource)
		require.ErrorContains(t, err, "database is required")
	})

	t.Run("upstream dsn is required", func(t *testing.T) {
		u := upstream("a")
		u.DSN = yaml.Node{}
		_, err := Compile(cfg(u), logger, stubSource)
		require.ErrorContains(t, err, "dsn is required")
	})

	t.Run("settings compiled and pinned", func(t *testing.T) {
		u := upstream("centaur")
		u.Settings = []Setting{
			{Name: "centaur.slack_channel_id", Value: "C123"},
			{Name: "centaur.tenant", Value: ""},
		}
		l, err := Compile(cfg(u), logger, stubSource)
		require.NoError(t, err)
		up := l.Upstream("centaur")
		require.Equal(t, u.Settings, up.Settings())
		require.Contains(t, up.PinnedGUCs(), "centaur.slack_channel_id")
		require.Contains(t, up.PinnedGUCs(), "centaur.tenant")
	})

	t.Run("setting name is required", func(t *testing.T) {
		u := upstream("a")
		u.Settings = []Setting{{Name: "", Value: "x"}}
		_, err := Compile(cfg(u), logger, stubSource)
		require.ErrorContains(t, err, "name is required")
	})

	t.Run("invalid setting name rejected", func(t *testing.T) {
		u := upstream("a")
		u.Settings = []Setting{{Name: "bad name!", Value: "x"}}
		_, err := Compile(cfg(u), logger, stubSource)
		require.ErrorContains(t, err, "invalid setting name")
	})

	t.Run("reserved setting name rejected", func(t *testing.T) {
		u := upstream("a")
		u.Settings = []Setting{{Name: "Role", Value: "x"}}
		_, err := Compile(cfg(u), logger, stubSource)
		require.ErrorContains(t, err, "managed by the proxy")
	})

	t.Run("duplicate setting name rejected", func(t *testing.T) {
		u := upstream("a")
		u.Settings = []Setting{
			{Name: "app.x", Value: "1"},
			{Name: "APP.X", Value: "2"},
		}
		_, err := Compile(cfg(u), logger, stubSource)
		require.ErrorContains(t, err, "duplicate setting")
	})
}

func TestLoadFromNodeAllowsDistinctRoutesForOneDatabase(t *testing.T) {
	t.Setenv("PG_PW", "secret")
	t.Setenv("PG_DSN", "host=127.0.0.1 port=1 dbname=appdb")

	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(`
listen: "127.0.0.1:0"
client:
  user: app
  password_env: PG_PW
upstreams:
  - database: appdb
    route: audit
    dsn:
      type: env
      var: PG_DSN
  - database: appdb
    route: company-context
    dsn:
      type: env
      var: PG_DSN
    role: company_context_reader
`), &node))

	listener, err := LoadFromNode(*node.Content[0], slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	require.Len(t, listener.Upstreams(), 2)
	require.Nil(t, listener.Upstream("appdb"))
	audit, err := listener.SelectUpstream("appdb", "audit")
	require.NoError(t, err)
	require.Empty(t, audit.Role())
	companyContext, err := listener.SelectUpstream("appdb", "company-context")
	require.NoError(t, err)
	require.Equal(t, "company_context_reader", companyContext.Role())
	_, err = listener.SelectUpstream("appdb", "")
	require.ErrorIs(t, err, ErrRouteRequired)
	_, err = listener.SelectUpstream("appdb", "unknown")
	require.ErrorIs(t, err, ErrUnknownRoute)
}
