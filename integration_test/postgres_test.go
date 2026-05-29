package integration_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

const (
	pgImage          = "postgres:16-alpine"
	pgUpstreamUser   = "iron_test"
	pgUpstreamPass   = "iron_test_pw"
	pgUpstreamDB     = "appdb"
	pgClientUser     = "app_user"
	pgClientPassword = "proxy_secret"
	pgRole           = "tenant_role"
)

// TestPostgresPolicy boots a real PostgreSQL container via testcontainers-go
// and an iron-proxy with the postgres listener configured, then drives real
// pgconn and pgx clients through the proxy to assert the v3 design:
//
//   - The proxy SETs ROLE upstream at session start so clients don't have to.
//   - Both Simple and Extended Query protocols pass through transparently.
//   - Client-issued role-change statements are rejected.
//   - Multi-statement Simple Queries are rejected.
//   - Auth failures are rejected before any upstream contact.
//
// Skipped when no Docker daemon is reachable.
func TestPostgresPolicy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	initScript, err := filepath.Abs(filepath.Join("testdata", "postgres_init.sql"))
	require.NoError(t, err)

	container, err := tcpostgres.Run(ctx, pgImage,
		tcpostgres.WithDatabase(pgUpstreamDB),
		tcpostgres.WithUsername(pgUpstreamUser),
		tcpostgres.WithPassword(pgUpstreamPass),
		tcpostgres.WithInitScripts(initScript),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Skipf("postgres testcontainers unavailable (is Docker running?): %v", err)
	}
	testcontainers.CleanupContainer(t, container)

	upstreamHost, err := container.Host(ctx)
	require.NoError(t, err)
	upstreamPort, err := container.MappedPort(ctx, "5432/tcp")
	require.NoError(t, err)

	cfgPath := renderConfig(t, t.TempDir(), "postgres_pipeline.yaml", nil)

	upstreamDSN := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		pgUpstreamUser, pgUpstreamPass, upstreamHost, upstreamPort.Num(), pgUpstreamDB)
	env := []string{
		"PG_UPSTREAM_DSN=" + upstreamDSN,
		"PG_PROXY_PASSWORD=" + pgClientPassword,
	}
	proxy := startProxy(t, proxyBinary(t), cfgPath, env)
	pgAddr := proxy.AddrFor(t, "postgres proxy starting")

	connStr := func(password string) string {
		host, port, _ := net.SplitHostPort(pgAddr)
		return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
			pgClientUser, password, host, port, pgUpstreamDB)
	}

	dial := func(t *testing.T, password string) *pgconn.PgConn {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := pgconn.Connect(ctx, connStr(password))
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close(context.Background()) })
		return conn
	}

	exec := func(t *testing.T, conn *pgconn.PgConn, sql string) error {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := conn.Exec(ctx, sql).ReadAll()
		return err
	}

	currentRole := func(t *testing.T, conn *pgconn.PgConn) string {
		t.Helper()
		results, err := conn.Exec(context.Background(), "SELECT current_role").ReadAll()
		require.NoError(t, err)
		require.Len(t, results, 1)
		require.Len(t, results[0].Rows, 1)
		return string(results[0].Rows[0][0])
	}

	t.Run("role is set at session start", func(t *testing.T) {
		// Client did nothing special; the proxy injected SET ROLE during
		// handshake, so the very first query already sees the right role.
		conn := dial(t, pgClientPassword)
		require.Equal(t, pgRole, currentRole(t, conn))
	})

	t.Run("rls scopes rows to the proxy-injected role", func(t *testing.T) {
		// This is the load-bearing test: the whole reason this feature exists
		// is so that PostgreSQL row-level security can use current_role to
		// scope access per tenant, even though the application connects as a
		// shared service-account superuser. The init script enables RLS on
		// `items` with a policy of `USING (owner = current_role)`; we assert
		// the client only sees rows where owner='tenant_role'.

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Sanity: connect directly to the container (no proxy) as the
		// superuser and confirm all 5 rows are present. This rules out a
		// fixture problem if the through-proxy assertion later sees 0 rows.
		directURL := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
			pgUpstreamUser, pgUpstreamPass, upstreamHost, upstreamPort.Num(), pgUpstreamDB)
		direct, err := pgx.Connect(ctx, directURL)
		require.NoError(t, err)
		t.Cleanup(func() { _ = direct.Close(ctx) })
		var total int
		require.NoError(t, direct.QueryRow(ctx, "SELECT count(*) FROM items").Scan(&total))
		require.Equal(t, 5, total, "fixture: items table should contain 5 rows directly")

		// Through the proxy: SET ROLE tenant_role was injected at handshake,
		// so RLS scopes us to tenant_role's rows.
		client, err := pgx.Connect(ctx, connStr(pgClientPassword))
		require.NoError(t, err)
		t.Cleanup(func() { _ = client.Close(ctx) })

		var visible int
		require.NoError(t, client.QueryRow(ctx, "SELECT count(*) FROM items").Scan(&visible))
		require.Equal(t, 2, visible, "RLS should hide other_role's rows from tenant_role")

		rows, err := client.Query(ctx, "SELECT owner FROM items ORDER BY id")
		require.NoError(t, err)
		var owners []string
		for rows.Next() {
			var owner string
			require.NoError(t, rows.Scan(&owner))
			owners = append(owners, owner)
		}
		require.NoError(t, rows.Err())
		require.Equal(t, []string{"tenant_role", "tenant_role"}, owners,
			"every visible row's owner must be the proxy-injected role")

		// WITH CHECK on the policy must block inserts that try to write rows
		// belonging to another tenant.
		_, err = client.Exec(ctx, "INSERT INTO items (owner, data) VALUES ('other_role', 'sneaky')")
		require.Error(t, err, "RLS WITH CHECK should reject insert with owner = other_role")
		var pgErr *pgconn.PgError
		require.True(t, errors.As(err, &pgErr), "want PgError, got %T: %v", err, err)
		require.Equal(t, "42501", pgErr.Code,
			"WITH CHECK violation should surface as insufficient_privilege (42501)")

		// And inserting a row belonging to the right tenant works.
		_, err = client.Exec(ctx, "INSERT INTO items (owner, data) VALUES ('tenant_role', 'mine-new')")
		require.NoError(t, err)
		require.NoError(t, client.QueryRow(ctx, "SELECT count(*) FROM items").Scan(&visible))
		require.Equal(t, 3, visible)

		// Cross-tenant rows remain invisible (and untouched) — UPDATE
		// targeting another tenant's data affects zero rows.
		tag, err := client.Exec(ctx, "UPDATE items SET data = 'pwned' WHERE owner = 'other_role'")
		require.NoError(t, err)
		require.EqualValues(t, 0, tag.RowsAffected(),
			"UPDATE through proxy must not be able to touch other tenants' rows")

		// Confirm directly that other_role's data is unchanged.
		require.NoError(t, direct.QueryRow(ctx, "SELECT count(*) FROM items WHERE owner = 'other_role' AND data = 'pwned'").Scan(&visible))
		require.Equal(t, 0, visible, "other tenant's rows should be untouched")
	})

	t.Run("autocommit simple query works", func(t *testing.T) {
		conn := dial(t, pgClientPassword)
		results, err := conn.Exec(context.Background(), "SELECT 1").ReadAll()
		require.NoError(t, err)
		require.Len(t, results, 1)
		require.Equal(t, "1", string(results[0].Rows[0][0]))
		// Role still correct.
		require.Equal(t, pgRole, currentRole(t, conn))
	})

	t.Run("extended query parameterized works", func(t *testing.T) {
		// pgx by default uses Extended Query with prepared-statement caching,
		// which is the path nearly every modern driver takes. Verify it works
		// end-to-end through the proxy.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := pgx.Connect(ctx, connStr(pgClientPassword))
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close(context.Background()) })

		var n int
		require.NoError(t, conn.QueryRow(ctx, "SELECT $1::int", 42).Scan(&n))
		require.Equal(t, 42, n)

		var role string
		require.NoError(t, conn.QueryRow(ctx, "SELECT current_role").Scan(&role))
		require.Equal(t, pgRole, role)
	})

	t.Run("explicit transaction works and keeps role", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := pgx.Connect(ctx, connStr(pgClientPassword))
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close(context.Background()) })

		tx, err := conn.Begin(ctx)
		require.NoError(t, err)
		var role string
		require.NoError(t, tx.QueryRow(ctx, "SELECT current_role").Scan(&role))
		require.Equal(t, pgRole, role)
		var sum int
		require.NoError(t, tx.QueryRow(ctx, "SELECT 1 + 2").Scan(&sum))
		require.Equal(t, 3, sum)
		require.NoError(t, tx.Commit(ctx))

		// After commit, still correct.
		require.NoError(t, conn.QueryRow(ctx, "SELECT current_role").Scan(&role))
		require.Equal(t, pgRole, role)
	})

	t.Run("client set role is rejected", func(t *testing.T) {
		conn := dial(t, pgClientPassword)
		err := exec(t, conn, "SET ROLE other_role")
		require.Error(t, err)
		var pgErr *pgconn.PgError
		require.True(t, errors.As(err, &pgErr), "want PgError, got %T: %v", err, err)
		require.Contains(t, pgErr.Message, "managed by the proxy")
		// Subsequent query still works with the configured role.
		require.Equal(t, pgRole, currentRole(t, conn))
	})

	t.Run("client reset role is rejected", func(t *testing.T) {
		conn := dial(t, pgClientPassword)
		err := exec(t, conn, "RESET ROLE")
		require.Error(t, err)
		var pgErr *pgconn.PgError
		require.True(t, errors.As(err, &pgErr))
		require.Contains(t, pgErr.Message, "managed by the proxy")
		require.Equal(t, pgRole, currentRole(t, conn))
	})

	t.Run("client set session authorization is rejected", func(t *testing.T) {
		conn := dial(t, pgClientPassword)
		err := exec(t, conn, "SET SESSION AUTHORIZATION other_role")
		require.Error(t, err)
		var pgErr *pgconn.PgError
		require.True(t, errors.As(err, &pgErr))
		require.Contains(t, pgErr.Message, "managed by the proxy")
	})

	t.Run("clean multi statement is allowed", func(t *testing.T) {
		conn := dial(t, pgClientPassword)
		err := exec(t, conn, "SELECT 1; SELECT 2")
		require.NoError(t, err)
		// Role policy still holds after a batch executes.
		require.Equal(t, pgRole, currentRole(t, conn))
	})

	t.Run("multi statement with role change is rejected", func(t *testing.T) {
		conn := dial(t, pgClientPassword)
		err := exec(t, conn, "SELECT 1; SET ROLE other_role")
		require.Error(t, err)
		var pgErr *pgconn.PgError
		require.True(t, errors.As(err, &pgErr))
		require.Contains(t, pgErr.Message, "managed by the proxy")
		// The batch was rejected before forwarding, so nothing took effect.
		require.Equal(t, pgRole, currentRole(t, conn))
	})

	t.Run("set_config function call bypass is rejected", func(t *testing.T) {
		// The headline case for the AST-based classifier: a client trying to
		// change the role via SELECT set_config('role', 'x', false) must be
		// rejected. Without parsing this would slip through because the wire
		// shows a SELECT, not a SET.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := pgx.Connect(ctx, connStr(pgClientPassword))
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close(context.Background()) })

		_, err = conn.Exec(ctx, "SELECT set_config('role', 'other_role', false)")
		require.Error(t, err)
		var pgErr *pgconn.PgError
		require.True(t, errors.As(err, &pgErr), "want PgError, got %T: %v", err, err)
		require.Contains(t, pgErr.Message, "managed by the proxy")

		// Confirm the bypass didn't take effect upstream.
		var role string
		require.NoError(t, conn.QueryRow(ctx, "SELECT current_role").Scan(&role))
		require.Equal(t, pgRole, role)
	})

	t.Run("set_config for other gucs passes through", func(t *testing.T) {
		// Only role-mutating GUCs trigger the rejection; set_config for benign
		// parameters should pass through.
		conn := dial(t, pgClientPassword)
		results, err := conn.Exec(context.Background(), "SELECT set_config('application_name', 'iron-test', false)").ReadAll()
		require.NoError(t, err)
		require.Len(t, results, 1)
	})

	t.Run("do block is rejected", func(t *testing.T) {
		conn := dial(t, pgClientPassword)
		err := exec(t, conn, "DO $$ BEGIN PERFORM 1; END $$")
		require.Error(t, err)
		var pgErr *pgconn.PgError
		require.True(t, errors.As(err, &pgErr))
		require.Contains(t, pgErr.Message, "DO blocks are not supported")
	})

	t.Run("client set role via extended query is rejected", func(t *testing.T) {
		// Verifies the Parse-SQL classifier path: pgx uses Extended Query, so
		// SET ROLE issued through it must hit ClassifyClientStatement on the
		// Parse message and get rejected before reaching upstream.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := pgx.Connect(ctx, connStr(pgClientPassword))
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close(context.Background()) })

		_, err = conn.Exec(ctx, "SET ROLE other_role")
		require.Error(t, err)
		var pgErr *pgconn.PgError
		require.True(t, errors.As(err, &pgErr), "want PgError, got %T: %v", err, err)
		require.Contains(t, pgErr.Message, "managed by the proxy")

		// Connection still usable, role still correct.
		var role string
		require.NoError(t, conn.QueryRow(ctx, "SELECT current_role").Scan(&role))
		require.Equal(t, pgRole, role)
	})

	t.Run("client auth failure", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := pgconn.Connect(ctx, connStr("wrong_password"))
		require.Error(t, err, "wrong proxy password must fail at the proxy")
		var pgErr *pgconn.PgError
		require.True(t, errors.As(err, &pgErr), "want PgError, got %T: %v", err, err)
		require.Equal(t, "28P01", pgErr.Code)
	})

	t.Run("hundred autocommit queries role stable", func(t *testing.T) {
		// Stress: simulates asyncpg-style pool.execute() usage. Same connection
		// running many autocommit queries; role must stay correct on every one.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := pgx.Connect(ctx, connStr(pgClientPassword))
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close(context.Background()) })

		for i := 0; i < 100; i++ {
			var role string
			require.NoError(t, conn.QueryRow(ctx, "SELECT current_role").Scan(&role))
			require.Equalf(t, pgRole, role, "iteration %d", i)
		}
	})
}

// TestPostgresMultipleServers boots one Postgres container and an iron-proxy
// with two postgres listeners pointing at it — each configured with a
// different injected role. Verifies they enforce their own roles
// independently, including RLS scoping.
func TestPostgresMultipleServers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	initScript, err := filepath.Abs(filepath.Join("testdata", "postgres_init.sql"))
	require.NoError(t, err)

	container, err := tcpostgres.Run(ctx, pgImage,
		tcpostgres.WithDatabase(pgUpstreamDB),
		tcpostgres.WithUsername(pgUpstreamUser),
		tcpostgres.WithPassword(pgUpstreamPass),
		tcpostgres.WithInitScripts(initScript),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Skipf("postgres testcontainers unavailable (is Docker running?): %v", err)
	}
	testcontainers.CleanupContainer(t, container)

	upstreamHost, err := container.Host(ctx)
	require.NoError(t, err)
	upstreamPort, err := container.MappedPort(ctx, "5432/tcp")
	require.NoError(t, err)

	cfgPath := renderConfig(t, t.TempDir(), "postgres_multi_pipeline.yaml", nil)

	upstreamDSN := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		pgUpstreamUser, pgUpstreamPass, upstreamHost, upstreamPort.Num(), pgUpstreamDB)
	env := []string{
		"PG_UPSTREAM_DSN=" + upstreamDSN,
		"PG_PROXY_PASSWORD=" + pgClientPassword,
	}
	proxy := startProxy(t, proxyBinary(t), cfgPath, env)

	primaryAddr := proxy.AddrForNamed(t, "postgres proxy starting", "primary")
	secondaryAddr := proxy.AddrForNamed(t, "postgres proxy starting", "secondary")
	require.NotEqual(t, primaryAddr, secondaryAddr, "each named server must bind a distinct port")

	connStrTo := func(addr string) string {
		host, port, _ := net.SplitHostPort(addr)
		return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
			pgClientUser, pgClientPassword, host, port, pgUpstreamDB)
	}

	queryRole := func(t *testing.T, addr string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := pgconn.Connect(ctx, connStrTo(addr))
		require.NoError(t, err)
		defer func() { _ = conn.Close(context.Background()) }()
		results, err := conn.Exec(ctx, "SELECT current_role").ReadAll()
		require.NoError(t, err)
		require.Len(t, results, 1)
		require.Len(t, results[0].Rows, 1)
		return string(results[0].Rows[0][0])
	}

	t.Run("each listener enforces its own role", func(t *testing.T) {
		require.Equal(t, "tenant_role", queryRole(t, primaryAddr))
		require.Equal(t, "other_role", queryRole(t, secondaryAddr))
	})

	t.Run("rls scopes rows differently per listener", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Through the primary listener: tenant_role sees only tenant_role's rows.
		primary, err := pgx.Connect(ctx, connStrTo(primaryAddr))
		require.NoError(t, err)
		t.Cleanup(func() { _ = primary.Close(ctx) })
		var primaryCount int
		require.NoError(t, primary.QueryRow(ctx, "SELECT count(*) FROM items").Scan(&primaryCount))
		require.Equal(t, 2, primaryCount, "primary listener should see only tenant_role's rows")

		// Through the secondary listener: other_role sees only other_role's rows.
		secondary, err := pgx.Connect(ctx, connStrTo(secondaryAddr))
		require.NoError(t, err)
		t.Cleanup(func() { _ = secondary.Close(ctx) })
		var secondaryCount int
		require.NoError(t, secondary.QueryRow(ctx, "SELECT count(*) FROM items").Scan(&secondaryCount))
		require.Equal(t, 3, secondaryCount, "secondary listener should see only other_role's rows")
	})
}
