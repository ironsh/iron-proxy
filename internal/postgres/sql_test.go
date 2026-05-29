package postgres

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		want OpKind
	}{
		// Empty / whitespace / comments
		{name: "empty", sql: "", want: OpEmpty},
		{name: "whitespace only", sql: "   \n\t", want: OpEmpty},
		{name: "comment only", sql: "-- nothing\n", want: OpEmpty},

		// Direct SET ROLE / SESSION AUTHORIZATION (the regex classifier's
		// core cases — must still work after the AST swap).
		{name: "set role unquoted", sql: "SET ROLE tenant_a", want: OpSetRole},
		{name: "set role lowercase", sql: "set role tenant_a", want: OpSetRole},
		{name: "set role quoted", sql: `SET ROLE "Tenant-A"`, want: OpSetRole},
		{name: "set local role", sql: "SET LOCAL ROLE tenant_a", want: OpSetRole},
		{name: "set session role", sql: "SET SESSION ROLE tenant_a", want: OpSetRole},
		{name: "set session authorization", sql: "SET SESSION AUTHORIZATION admin", want: OpSetSessionAuthorization},
		{name: "set local session auth", sql: "SET LOCAL SESSION AUTHORIZATION admin", want: OpSetSessionAuthorization},
		{name: "reset role", sql: "RESET ROLE", want: OpResetRole},
		{name: "reset session authorization", sql: "RESET SESSION AUTHORIZATION", want: OpResetSessionAuthorization},

		// Non-role SET / RESET — must not be classified as role change.
		{name: "set search_path is other", sql: "SET search_path = public", want: OpOther},
		{name: "reset search_path is other", sql: "RESET search_path", want: OpOther},
		{name: "set local search_path is other", sql: "SET LOCAL search_path = public", want: OpOther},

		// Plain user queries
		{name: "select is other", sql: "SELECT 1", want: OpOther},
		{name: "update is other", sql: "UPDATE t SET x = 1", want: OpOther},
		{name: "insert is other", sql: "INSERT INTO t VALUES (1)", want: OpOther},

		// Transaction control — not a role change; the relay forwards.
		{name: "begin", sql: "BEGIN", want: OpOther},
		{name: "commit", sql: "COMMIT", want: OpOther},
		{name: "rollback", sql: "ROLLBACK", want: OpOther},
		{name: "start transaction", sql: "START TRANSACTION", want: OpOther},
		{name: "savepoint", sql: "SAVEPOINT a", want: OpOther},

		// Multi-statement — classified per statement; the batch takes the
		// verdict of its first rejectable statement, else OpOther.
		{name: "multi set then select rejects on set role", sql: "SET ROLE tenant; SELECT 1", want: OpSetRole},
		{name: "multi select then select allowed", sql: "SELECT 1; SELECT 2", want: OpOther},
		{name: "multi benign then set role", sql: "SELECT 1; SET ROLE tenant", want: OpSetRole},
		{name: "multi benign then do block", sql: "SELECT 1; DO $$ BEGIN END $$", want: OpDoBlock},
		{name: "multi benign then set_config role", sql: "SELECT 1; SELECT set_config('role', 'admin', false)", want: OpSetRole},
		{name: "multi non-role sets allowed", sql: "SET search_path = public; SELECT 1", want: OpOther},
		// Trailing semicolon alone is *not* multi (pg_query collapses it).
		{name: "trailing semicolon not multi", sql: "SET ROLE tenant;", want: OpSetRole},

		// set_config function-call bypass attempts
		{name: "set_config role top level", sql: "SELECT set_config('role', 'admin', false)", want: OpSetRole},
		{name: "set_config role local flag", sql: "SELECT set_config('role', 'admin', true)", want: OpSetRole},
		{name: "pg_catalog set_config role", sql: "SELECT pg_catalog.set_config('role', 'admin', false)", want: OpSetRole},
		{name: "set_config session_authorization", sql: "SELECT set_config('session_authorization', 'admin', false)", want: OpSetSessionAuthorization},
		{name: "set_config case insensitive name", sql: "SELECT set_config('ROLE', 'admin', false)", want: OpSetRole},
		{name: "set_config nested in select", sql: "SELECT 1, set_config('role', 'admin', false), 2", want: OpSetRole},
		{name: "set_config in subquery", sql: "SELECT * FROM (SELECT set_config('role', 'admin', false)) s", want: OpSetRole},
		{name: "set_config in cte", sql: "WITH x AS (SELECT set_config('role', 'admin', false)) SELECT * FROM x", want: OpSetRole},
		{name: "set_config in where clause", sql: "SELECT 1 WHERE set_config('role', 'admin', false) = 'admin'", want: OpSetRole},
		{name: "set_config inside insert", sql: "INSERT INTO t SELECT set_config('role', 'admin', false)", want: OpSetRole},

		// set_config for safe parameters — allowed.
		{name: "set_config search_path allowed", sql: "SELECT set_config('search_path', 'public', false)", want: OpOther},
		{name: "current_setting role is read only", sql: "SELECT current_setting('role')", want: OpOther},

		// PREPARE wrapping a SELECT that calls set_config — caught by the
		// walker through the nested SelectStmt.
		{name: "prepare wrapping set_config caught", sql: "PREPARE p AS SELECT set_config('role', 'admin', false)", want: OpSetRole},

		// DO blocks — rejected regardless of contents.
		{name: "do block empty", sql: "DO $$ BEGIN END $$", want: OpDoBlock},
		{name: "do block with set role", sql: "DO $$ BEGIN EXECUTE 'SET ROLE admin'; END $$", want: OpDoBlock},

		// Parse errors — forwarded.
		{name: "syntax error", sql: "INSERT FROM WHERE", want: OpParseError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := Classify(tt.sql)
			require.Equalf(t, tt.want, op.Kind, "Classify(%q).Kind", tt.sql)
		})
	}
}
