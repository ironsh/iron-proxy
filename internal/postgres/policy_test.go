package postgres

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClassifyClientStatement(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		allowed bool
		reason  RejectReason
	}{
		{name: "select allowed", sql: "SELECT 1", allowed: true},
		{name: "update allowed", sql: "UPDATE t SET x = 1 WHERE id = 2", allowed: true},
		{name: "begin allowed", sql: "BEGIN", allowed: true},
		{name: "commit allowed", sql: "COMMIT", allowed: true},
		{name: "rollback allowed", sql: "ROLLBACK", allowed: true},
		{name: "empty allowed", sql: "", allowed: true},

		{name: "set role rejected", sql: "SET ROLE other", reason: RejectClientRoleChange},
		{name: "set local role rejected", sql: "SET LOCAL ROLE other", reason: RejectClientRoleChange},
		{name: "set session role rejected", sql: "SET SESSION ROLE other", reason: RejectClientRoleChange},
		{name: "reset role rejected", sql: "RESET ROLE", reason: RejectClientRoleChange},
		{name: "set session authorization rejected", sql: "SET SESSION AUTHORIZATION admin", reason: RejectClientRoleChange},
		{name: "reset session authorization rejected", sql: "RESET SESSION AUTHORIZATION", reason: RejectClientRoleChange},

		// Multi-statement batches are allowed when every statement passes the
		// role policy, and rejected per-statement otherwise.
		{name: "clean multi statement allowed", sql: "SELECT 1; SELECT 2", allowed: true},
		{name: "multi statement with set role rejected", sql: "SET ROLE x; SELECT 1", reason: RejectClientRoleChange},
		{name: "multi statement with trailing set role rejected", sql: "SELECT 1; SET ROLE x", reason: RejectClientRoleChange},
		{name: "multi statement with do block rejected", sql: "SELECT 1; DO $$ BEGIN END $$", reason: RejectDoBlock},

		// SET of other GUCs is fine — only role-changing statements are rejected.
		{name: "set search_path allowed", sql: "SET search_path = public", allowed: true},
		{name: "set local search_path allowed", sql: "SET LOCAL search_path = public", allowed: true},

		// Function-call bypass attempts — caught by AST walker.
		{name: "set_config role rejected", sql: "SELECT set_config('role', 'admin', false)", reason: RejectClientRoleChange},
		{name: "pg_catalog set_config role rejected", sql: "SELECT pg_catalog.set_config('role', 'admin', false)", reason: RejectClientRoleChange},
		{name: "set_config session_authorization rejected", sql: "SELECT set_config('session_authorization', 'admin', false)", reason: RejectClientRoleChange},
		{name: "set_config role in cte rejected", sql: "WITH x AS (SELECT set_config('role', 'admin', false)) SELECT * FROM x", reason: RejectClientRoleChange},
		{name: "current_setting role allowed", sql: "SELECT current_setting('role')", allowed: true},
		{name: "set_config search_path allowed", sql: "SELECT set_config('search_path', 'public', false)", allowed: true},

		// DO blocks rejected outright.
		{name: "do block rejected", sql: "DO $$ BEGIN END $$", reason: RejectDoBlock},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := ClassifyClientStatement(tt.sql)
			if tt.allowed {
				require.Truef(t, allowed, "ClassifyClientStatement(%q) returned (false, %v); want allowed", tt.sql, reason)
				return
			}
			require.Falsef(t, allowed, "ClassifyClientStatement(%q) returned (true, _); want reject reason %v", tt.sql, tt.reason)
			require.Equalf(t, tt.reason, reason, "ClassifyClientStatement(%q) reason", tt.sql)
		})
	}
}

func TestNewManagedUpstream(t *testing.T) {
	dsn := staticDSN{name: "dsn", value: "host=db"}

	u, err := NewManagedUpstream("analytics", dsn, "app", "pw", "readonly")
	require.NoError(t, err)
	require.Equal(t, "analytics", u.Database())
	require.Equal(t, "readonly", u.Role())
	require.True(t, u.VerifyClient("app", "pw"))
	require.False(t, u.VerifyClient("app", "wrong"))

	// Absent role is allowed (no SET ROLE issued).
	u, err = NewManagedUpstream("main", dsn, "app", "pw", "")
	require.NoError(t, err)
	require.Empty(t, u.Role())

	// Required fields.
	_, err = NewManagedUpstream("", dsn, "app", "pw", "")
	require.ErrorContains(t, err, "database is required")
	_, err = NewManagedUpstream("d", nil, "app", "pw", "")
	require.ErrorContains(t, err, "dsn source is required")
	_, err = NewManagedUpstream("d", dsn, "", "pw", "")
	require.ErrorContains(t, err, "client user is required")
	_, err = NewManagedUpstream("d", dsn, "app", "", "")
	require.ErrorContains(t, err, "client password is required")
}

func TestNewListener(t *testing.T) {
	dsn := staticDSN{name: "dsn", value: "host=db"}
	mustUpstream := func(database string) *Upstream {
		u, err := NewManagedUpstream(database, dsn, "app", "pw", "")
		require.NoError(t, err)
		return u
	}

	l, err := NewListener("127.0.0.1:0", []*Upstream{mustUpstream("a"), mustUpstream("b")})
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1:0", l.Listen())
	require.Equal(t, "a", l.Upstream("a").Database())
	require.Equal(t, "b", l.Upstream("b").Database())
	require.Nil(t, l.Upstream("missing"))
	require.Len(t, l.Upstreams(), 2)

	// Required fields and duplicate-database guard.
	_, err = NewListener("", []*Upstream{mustUpstream("a")})
	require.ErrorContains(t, err, "listen is required")
	_, err = NewListener("127.0.0.1:0", nil)
	require.ErrorContains(t, err, "at least one upstream is required")
	_, err = NewListener("127.0.0.1:0", []*Upstream{mustUpstream("a"), mustUpstream("a")})
	require.ErrorContains(t, err, `duplicate upstream database "a"`)
}

func TestQuoteIdent(t *testing.T) {
	cases := []struct {
		in, out string
	}{
		{"tenant_role", `"tenant_role"`},
		{"Tenant Role", `"Tenant Role"`},
		{`weird"name`, `"weird""name"`},
		{"", `""`},
	}
	for _, c := range cases {
		require.Equalf(t, c.out, QuoteIdent(c.in), "QuoteIdent(%q)", c.in)
	}
}
