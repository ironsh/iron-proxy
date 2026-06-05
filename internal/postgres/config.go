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

// ListenerConfig is the top-level postgres: block — a single bind address
// fronting a set of database-keyed upstreams.
type ListenerConfig struct {
	// Listen is the proxy's bind address for client connections, e.g. ":5432".
	Listen string `yaml:"listen"`

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
	// reach this upstream. Required and must be unique across upstreams.
	Database string `yaml:"database"`

	// DSN is the upstream connection string, loaded from any registered secret
	// source (env, aws_sm, aws_ssm, 1password, 1password_connect) and passed
	// verbatim to pgconn.ParseConfig — both URL-style
	// (postgres://user:pw@host:port/db?sslmode=...) and keyword/value strings
	// (host=... port=... user=... password=... dbname=... sslmode=...) are
	// accepted.
	DSN yaml.Node `yaml:"dsn"`

	// Client describes the credentials clients must present to use this
	// upstream. The proxy verifies a single shared user/password pair per
	// upstream — per-user credentials are not supported.
	Client ClientConfig `yaml:"client"`

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
// address and the database-keyed upstreams reachable through it.
type Listener struct {
	name      string
	listen    string
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

// Upstream is the compiled, runtime form of a single UpstreamConfig: one
// upstream database with its own credentials and optional injected role.
type Upstream struct {
	database string
	role     string

	dsn secrets.Source

	clientUser     string
	clientPassword string
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

// VerifyClient returns whether the given (user, password) pair matches the
// upstream's configured client credentials.
func (u *Upstream) VerifyClient(user, password string) bool {
	return user == u.clientUser && password == u.clientPassword
}

// ClientUser returns the user clients must present to use this upstream.
func (u *Upstream) ClientUser() string { return u.clientUser }

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
	if c.Listen == "" && len(c.Upstreams) == 0 {
		return nil, nil
	}
	if c.Listen == "" {
		return nil, fmt.Errorf("postgres: listen is required")
	}
	if len(c.Upstreams) == 0 {
		return nil, fmt.Errorf("postgres: at least one upstream is required")
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
		if uc.Client.User == "" {
			return nil, fmt.Errorf("%s: client.user is required", uctx)
		}
		if uc.Client.PasswordEnv == "" {
			return nil, fmt.Errorf("%s: client.password_env is required", uctx)
		}
		if _, ok := upstreams[uc.Database]; ok {
			return nil, fmt.Errorf("postgres: duplicate upstream database %q", uc.Database)
		}

		dsnSource, err := buildSource(uc.DSN, logger)
		if err != nil {
			return nil, fmt.Errorf("%s: building dsn source: %w", uctx, err)
		}

		clientPassword := os.Getenv(uc.Client.PasswordEnv)
		if clientPassword == "" {
			return nil, fmt.Errorf("%s: client.password_env %q is not set in the environment", uctx, uc.Client.PasswordEnv)
		}

		upstreams[uc.Database] = &Upstream{
			database:       uc.Database,
			role:           uc.Role,
			dsn:            dsnSource,
			clientUser:     uc.Client.User,
			clientPassword: clientPassword,
		}
	}

	return &Listener{
		name:      listenerName,
		listen:    c.Listen,
		upstreams: upstreams,
	}, nil
}

// NewListener builds the postgres listener from a bind address and a set of
// upstreams. It is the construction path for control-plane-synced listeners,
// whose upstreams are built one at a time via NewManagedUpstream. The listen
// address is required, and at least one upstream must be supplied; an upstream
// whose Database collides with an earlier one is an error.
func NewListener(listen string, upstreams []*Upstream) (*Listener, error) {
	if listen == "" {
		return nil, fmt.Errorf("postgres: listen is required")
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
	return &Listener{name: listenerName, listen: listen, upstreams: m}, nil
}

// NewManagedUpstream builds an Upstream for a control-plane-synced listener. The
// DSN source and optional role come from the control plane; the client
// credentials come from the proxy's environment. Unlike the YAML path,
// clientPassword is the literal password value, not the name of an env var —
// managed mode has no second level of indirection. All fields except role are
// required.
func NewManagedUpstream(database string, dsn secrets.Source, clientUser, clientPassword, role string) (*Upstream, error) {
	if database == "" {
		return nil, fmt.Errorf("postgres: managed upstream database is required")
	}
	ctx := fmt.Sprintf("postgres upstream[%q]", database)
	if dsn == nil {
		return nil, fmt.Errorf("%s: dsn source is required", ctx)
	}
	if clientUser == "" {
		return nil, fmt.Errorf("%s: client user is required", ctx)
	}
	if clientPassword == "" {
		return nil, fmt.Errorf("%s: client password is required", ctx)
	}
	return &Upstream{
		database:       database,
		role:           role,
		dsn:            dsn,
		clientUser:     clientUser,
		clientPassword: clientPassword,
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
