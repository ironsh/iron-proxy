// Package postgres implements an iron-proxy listener that MITM-proxies
// PostgreSQL traffic so a static role policy is in effect on every query the
// upstream database sees.
//
// The listener accepts client connections, authenticates them against
// proxy-managed credentials, opens its own authenticated connection upstream
// (handling SCRAM/MD5 termination via pgconn), optionally issues a single
// `SET ROLE "<role>"` on the upstream session, then relays the PostgreSQL
// wire protocol bidirectionally.
//
// Deployment assumption: if PgBouncer (or any pooler) sits between the proxy
// and PostgreSQL, it must be configured in session-pool mode. Transaction or
// statement pooling silently rebinds backends between queries and would
// nullify the role injection. This is not probed at runtime — the constraint
// is enforced by deployment configuration.
//
// While the relay is running the proxy is mostly transparent: it rejects only
// client-issued role-changing statements (`SET ROLE`, `RESET ROLE`,
// `SET SESSION AUTHORIZATION`, `RESET SESSION AUTHORIZATION`), the function-
// call equivalents (`set_config('role', ...)`), and DO blocks. Multi-statement
// Simple Queries are allowed as long as every statement passes the role policy;
// a batch is rejected if any statement mutates the role or is a DO block.
// Extended Query, COPY, and prepared statements pass through unchanged.
//
// The proxy runs a single postgres listener fronting multiple upstream
// databases: the top-level postgres: block is one object with a listen address
// and a list of upstreams. An upstream is selected by the database name the
// client supplies in its startup message; each upstream has its own DSN, client
// credentials, and optional injected role. One listen address therefore serves
// many databases.
package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

// SourceBuilder is the signature of secrets.BuildSource. Pulled out so tests
// can inject a stub instead of constructing real source backends.
type SourceBuilder func(yaml.Node, *slog.Logger) (secrets.Source, error)

// listenerName is the fixed name of the single postgres listener, surfaced in
// logs. The proxy runs at most one listener, so the name is not configurable.
const listenerName = "postgres"

// ListenerConfig is the top-level postgres: block — a single bind address and
// one shared client credential fronting a set of database-keyed upstreams.
type ListenerConfig struct {
	// Listen is the proxy's bind address for client connections, e.g. ":5432".
	Listen string `yaml:"listen"`

	// Client describes the single credential clients present to the proxy. It is
	// shared across every upstream on the listener: routing is by database, so
	// per-database credentials add nothing. The proxy verifies one user/password
	// pair; per-user credentials are not supported.
	Client ClientConfig `yaml:"client"`

	// Upstreams is the set of upstream databases this listener fronts. An
	// upstream is selected by the database name the client sends in its startup
	// message. At least one upstream is required.
	Upstreams []UpstreamConfig `yaml:"upstreams"`
}

// UpstreamConfig describes one upstream database reachable through the listener.
// The client selects it by sending its Database value as the startup "database"
// parameter.
type UpstreamConfig struct {
	// Database is the routing key: the database name a client must request to
	// reach this upstream. Required and must be unique across upstreams. It must
	// also equal the database the DSN connects to (the dbname in the DSN); the
	// proxy rejects a connection whose upstream session would land on a
	// different database than the client named.
	Database string `yaml:"database"`

	// DSN is the upstream connection string, loaded from any registered secret
	// source (env, aws_sm, aws_ssm, 1password, 1password_connect) and passed
	// verbatim to pgconn.ParseConfig — both URL-style
	// (postgres://user:pw@host:port/db?sslmode=...) and keyword/value strings
	// (host=... port=... user=... password=... dbname=... sslmode=...) are
	// accepted.
	DSN yaml.Node `yaml:"dsn"`

	// Role is the Postgres role the proxy SETs at session start for this
	// upstream. When set, every query the client subsequently issues runs as
	// this role on the upstream database. Optional: when empty, the proxy issues
	// no SET ROLE and the upstream session runs as the connecting user.
	Role string `yaml:"role,omitempty"`
}

// ClientConfig describes the credentials the proxy demands from clients.
type ClientConfig struct {
	User        string `yaml:"user"`
	PasswordEnv string `yaml:"password_env"`
}

// Listener is the compiled, runtime form of a single ListenerConfig: a bind
// address, the shared client credential, and the database-keyed upstreams
// reachable through it.
type Listener struct {
	name   string
	listen string

	clientUser     string
	clientPassword string

	upstreams map[string]*Upstream
}

// Name returns the listener's name (a fixed identifier surfaced in logs).
func (l *Listener) Name() string { return l.name }

// Listen returns the bind address.
func (l *Listener) Listen() string { return l.listen }

// Upstream returns the upstream for the given database name, or nil if no
// upstream on this listener serves it.
func (l *Listener) Upstream(database string) *Upstream { return l.upstreams[database] }

// Upstreams returns all of the listener's upstreams. The order is unspecified.
func (l *Listener) Upstreams() []*Upstream {
	out := make([]*Upstream, 0, len(l.upstreams))
	for _, u := range l.upstreams {
		out = append(out, u)
	}
	return out
}

// ClientUser returns the user clients must present to the listener.
func (l *Listener) ClientUser() string { return l.clientUser }

// VerifyClient returns whether the given (user, password) pair matches the
// listener's shared client credential.
func (l *Listener) VerifyClient(user, password string) bool {
	return user == l.clientUser && password == l.clientPassword
}

// WithUpstreams returns a copy of the listener with extra upstreams added,
// keeping the listener's address and client credential. An extra upstream whose
// database already exists is skipped (the existing one wins); its database is
// returned in dropped so the caller can log it.
func (l *Listener) WithUpstreams(extra []*Upstream) (listener *Listener, dropped []string) {
	m := make(map[string]*Upstream, len(l.upstreams)+len(extra))
	for db, u := range l.upstreams {
		m[db] = u
	}
	for _, u := range extra {
		if _, ok := m[u.database]; ok {
			dropped = append(dropped, u.database)
			continue
		}
		m[u.database] = u
	}
	return &Listener{
		name:           l.name,
		listen:         l.listen,
		clientUser:     l.clientUser,
		clientPassword: l.clientPassword,
		upstreams:      m,
	}, dropped
}

// Upstream is the compiled, runtime form of a single UpstreamConfig: one
// upstream database with its DSN and optional injected role.
type Upstream struct {
	database string
	role     string

	dsn secrets.Source
}

// Database returns the upstream's routing key — the database name a client
// requests to reach it.
func (u *Upstream) Database() string { return u.database }

// Role returns the role the proxy SETs upstream at session start. Empty
// means no role is set (the upstream session runs as the connecting user).
func (u *Upstream) Role() string { return u.role }

// DSN returns the upstream connection string, fetched from the configured
// secret source. The result is cached by the source; repeated calls do not
// necessarily round-trip to the backend.
func (u *Upstream) DSN(ctx context.Context) (string, error) {
	return u.dsn.Get(ctx)
}

// LoadFromNode decodes the raw postgres: yaml.Node into a ListenerConfig and
// compiles it into a Listener. An empty node (the postgres: key absent from the
// source document) returns (nil, nil) so callers can treat "no postgres
// listener" as a normal case. An empty block (no listen and no upstreams)
// returns the same.
func LoadFromNode(node yaml.Node, logger *slog.Logger) (*Listener, error) {
	if node.Kind == 0 {
		return nil, nil
	}
	var c ListenerConfig
	if err := node.Decode(&c); err != nil {
		return nil, fmt.Errorf("decoding postgres config: %w", err)
	}
	return Compile(c, logger, secrets.BuildSource)
}

// Compile validates and compiles a ListenerConfig into a Listener. Returns
// (nil, nil) when the block is empty (no listen and no upstreams) so callers can
// treat "not configured" as a no-op without a sentinel error.
func Compile(c ListenerConfig, logger *slog.Logger, buildSource SourceBuilder) (*Listener, error) {
	if c.Listen == "" && len(c.Upstreams) == 0 && c.Client.User == "" && c.Client.PasswordEnv == "" {
		return nil, nil
	}
	if c.Listen == "" {
		return nil, fmt.Errorf("postgres: listen is required")
	}
	if c.Client.User == "" {
		return nil, fmt.Errorf("postgres: client.user is required")
	}
	if c.Client.PasswordEnv == "" {
		return nil, fmt.Errorf("postgres: client.password_env is required")
	}
	if len(c.Upstreams) == 0 {
		return nil, fmt.Errorf("postgres: at least one upstream is required")
	}

	clientPassword := os.Getenv(c.Client.PasswordEnv)
	if clientPassword == "" {
		return nil, fmt.Errorf("postgres: client.password_env %q is not set in the environment", c.Client.PasswordEnv)
	}

	upstreams := make(map[string]*Upstream, len(c.Upstreams))
	for j, uc := range c.Upstreams {
		uctx := fmt.Sprintf("postgres.upstreams[%d]", j)
		if uc.Database != "" {
			uctx = fmt.Sprintf("postgres.upstreams[%q]", uc.Database)
		}

		if uc.Database == "" {
			return nil, fmt.Errorf("%s: database is required", uctx)
		}
		if uc.DSN.Kind == 0 {
			return nil, fmt.Errorf("%s: dsn is required", uctx)
		}
		if _, ok := upstreams[uc.Database]; ok {
			return nil, fmt.Errorf("postgres: duplicate upstream database %q", uc.Database)
		}

		dsnSource, err := buildSource(uc.DSN, logger)
		if err != nil {
			return nil, fmt.Errorf("%s: building dsn source: %w", uctx, err)
		}

		upstreams[uc.Database] = &Upstream{
			database: uc.Database,
			role:     uc.Role,
			dsn:      dsnSource,
		}
	}

	return &Listener{
		name:           listenerName,
		listen:         c.Listen,
		clientUser:     c.Client.User,
		clientPassword: clientPassword,
		upstreams:      upstreams,
	}, nil
}

// NewListener builds the postgres listener from a bind address, the shared
// client credential, and a set of upstreams. It is the construction path for
// control-plane-synced listeners, whose upstreams are built one at a time via
// NewManagedUpstream. The listen address and client credential are required,
// and at least one upstream must be supplied; an upstream whose Database
// collides with an earlier one is an error.
func NewListener(listen, clientUser, clientPassword string, upstreams []*Upstream) (*Listener, error) {
	if listen == "" {
		return nil, fmt.Errorf("postgres: listen is required")
	}
	if clientUser == "" {
		return nil, fmt.Errorf("postgres: client user is required")
	}
	if clientPassword == "" {
		return nil, fmt.Errorf("postgres: client password is required")
	}
	if len(upstreams) == 0 {
		return nil, fmt.Errorf("postgres: at least one upstream is required")
	}
	m := make(map[string]*Upstream, len(upstreams))
	for _, u := range upstreams {
		if _, ok := m[u.database]; ok {
			return nil, fmt.Errorf("postgres: duplicate upstream database %q", u.database)
		}
		m[u.database] = u
	}
	return &Listener{
		name:           listenerName,
		listen:         listen,
		clientUser:     clientUser,
		clientPassword: clientPassword,
		upstreams:      m,
	}, nil
}

// NewManagedUpstream builds an Upstream for a control-plane-synced listener. The
// DSN source and optional role come from the control plane. Database is the
// routing key and is required; role is optional.
func NewManagedUpstream(database string, dsn secrets.Source, role string) (*Upstream, error) {
	if database == "" {
		return nil, fmt.Errorf("postgres: managed upstream database is required")
	}
	if dsn == nil {
		return nil, fmt.Errorf("postgres upstream[%q]: dsn source is required", database)
	}
	return &Upstream{
		database: database,
		role:     role,
		dsn:      dsn,
	}, nil
}

// QuoteIdent returns s formatted as a Postgres double-quoted identifier,
// suitable for safe interpolation into SQL like `SET ROLE "<ident>"`.
// Embedded `"` characters are doubled per Postgres lexical rules.
func QuoteIdent(s string) string {
	out := make([]byte, 0, len(s)+2)
	out = append(out, '"')
	for i := 0; i < len(s); i++ {
		if s[i] == '"' {
			out = append(out, '"', '"')
		} else {
			out = append(out, s[i])
		}
	}
	out = append(out, '"')
	return string(out)
}
