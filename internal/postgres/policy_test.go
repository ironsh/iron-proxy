package postgres

import "testing"

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

		{name: "multi statement rejected", sql: "SELECT 1; SELECT 2", reason: RejectMultiStatement},
		{name: "multi statement with set role rejected as multi", sql: "SET ROLE x; SELECT 1", reason: RejectMultiStatement},

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
				if !allowed {
					t.Fatalf("ClassifyClientStatement(%q) = (false, %v), want (true, _)", tt.sql, reason)
				}
				return
			}
			if allowed {
				t.Fatalf("ClassifyClientStatement(%q) = (true, _), want (false, %v)", tt.sql, tt.reason)
			}
			if reason != tt.reason {
				t.Fatalf("ClassifyClientStatement(%q) reason = %v, want %v", tt.sql, reason, tt.reason)
			}
		})
	}
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
		got := QuoteIdent(c.in)
		if got != c.out {
			t.Fatalf("QuoteIdent(%q) = %q, want %q", c.in, got, c.out)
		}
	}
}
