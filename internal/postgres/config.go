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
// Multiple servers are supported: the top-level postgres: key is a list, so
// one proxy process can front several databases (each with its own listen
// address, upstream, client credentials, and optional injected role).
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

// ServerConfig is one entry in the top-level postgres: list — a single
// listener fronting a single upstream database.
type ServerConfig struct {
	// Name identifies the server in logs and error messages. Required and
	// must be unique across all postgres servers in the config.
	Name string `yaml:"name"`

	// Listen is the proxy's bind address for client connections, e.g. ":5432".
	// Must be unique across all postgres servers.
	Listen string `yaml:"listen"`

	// Upstream is the database the proxy connects to on behalf of clients.
	Upstream UpstreamConfig `yaml:"upstream"`

	// Client describes the credentials clients must present when authenticating
	// to the proxy. The proxy verifies a single shared user/password pair —
	// per-user credentials are not supported.
	Client ClientConfig `yaml:"client"`

	// Role is the Postgres role the proxy SETs at session start. When set,
	// every query the client subsequently issues runs as this role on the
	// upstream database. Optional: when empty, the proxy issues no SET ROLE
	// and the upstream session runs as the connecting user.
	Role string `yaml:"role,omitempty"`
}

// UpstreamConfig describes the database the proxy forwards to. The DSN is
// loaded from any registered secret source (env, aws_sm, aws_ssm, 1password,
// 1password_connect) and is passed verbatim to pgconn.ParseConfig — both
// URL-style (postgres://user:pw@host:port/db?sslmode=...) and keyword/value
// strings (host=... port=... user=... password=... dbname=... sslmode=...)
// are accepted.
type UpstreamConfig struct {
	DSN yaml.Node `yaml:"dsn"`
}

// ClientConfig describes the credentials the proxy demands from clients.
type ClientConfig struct {
	User        string `yaml:"user"`
	PasswordEnv string `yaml:"password_env"`
}

// Policy is the compiled, runtime form of a single ServerConfig.
type Policy struct {
	name   string
	listen string
	role   string

	upstreamDSN secrets.Source

	clientUser     string
	clientPassword string
}

// Name returns the server's configured name.
func (p *Policy) Name() string { return p.name }

// Listen returns the bind address.
func (p *Policy) Listen() string { return p.listen }

// Role returns the role the proxy SETs upstream at session start. Empty
// means no role is set (the upstream session runs as the connecting user).
func (p *Policy) Role() string { return p.role }

// UpstreamDSN returns the upstream connection string, fetched from the
// configured secret source. The result is cached by the source; repeated
// calls do not necessarily round-trip to the backend.
func (p *Policy) UpstreamDSN(ctx context.Context) (string, error) {
	return p.upstreamDSN.Get(ctx)
}

// VerifyClient returns whether the given (user, password) pair matches the
// configured client credentials.
func (p *Policy) VerifyClient(user, password string) bool {
	return user == p.clientUser && password == p.clientPassword
}

// ClientUser returns the user clients must present to the proxy.
func (p *Policy) ClientUser() string { return p.clientUser }

// LoadFromNode decodes a raw yaml.Node into a list of ServerConfigs and
// compiles each into a Policy. An empty node (the postgres: key absent from
// the source document) returns (nil, nil) so callers can treat "no postgres
// listeners" as a normal case. An empty list (`postgres: []`) returns the
// same.
func LoadFromNode(node yaml.Node, logger *slog.Logger) ([]*Policy, error) {
	if node.Kind == 0 {
		return nil, nil
	}
	var servers []ServerConfig
	if err := node.Decode(&servers); err != nil {
		return nil, fmt.Errorf("decoding postgres config: %w", err)
	}
	return Compile(servers, logger, secrets.BuildSource)
}

// Compile validates and compiles ServerConfigs into Policies. Returns
// (nil, nil) when the input list is empty so callers can treat "not
// configured" as a no-op without a sentinel error.
func Compile(servers []ServerConfig, logger *slog.Logger, buildSource SourceBuilder) ([]*Policy, error) {
	if len(servers) == 0 {
		return nil, nil
	}

	seenNames := make(map[string]bool, len(servers))
	policies := make([]*Policy, 0, len(servers))

	for i, s := range servers {
		p, err := compileOne(s, i, logger, buildSource)
		if err != nil {
			return nil, err
		}
		if seenNames[p.name] {
			return nil, fmt.Errorf("postgres[%d]: duplicate server name %q", i, p.name)
		}
		seenNames[p.name] = true
		policies = append(policies, p)
	}

	// We deliberately don't validate listen-address uniqueness here: ":0"
	// asks the OS to assign an ephemeral port, so two ":0" entries are
	// legitimate (and used by tests). Real conflicts surface as a clean
	// "address already in use" from net.Listen at startup.

	return policies, nil
}

func compileOne(c ServerConfig, idx int, logger *slog.Logger, buildSource SourceBuilder) (*Policy, error) {
	ctx := fmt.Sprintf("postgres[%d]", idx)
	if c.Name != "" {
		ctx = fmt.Sprintf("postgres[%q]", c.Name)
	}

	if c.Name == "" {
		return nil, fmt.Errorf("%s: name is required", ctx)
	}
	if c.Listen == "" {
		return nil, fmt.Errorf("%s: listen is required", ctx)
	}
	if c.Upstream.DSN.Kind == 0 {
		return nil, fmt.Errorf("%s: upstream.dsn is required", ctx)
	}
	if c.Client.User == "" {
		return nil, fmt.Errorf("%s: client.user is required", ctx)
	}
	if c.Client.PasswordEnv == "" {
		return nil, fmt.Errorf("%s: client.password_env is required", ctx)
	}

	dsnSource, err := buildSource(c.Upstream.DSN, logger)
	if err != nil {
		return nil, fmt.Errorf("%s: building upstream.dsn source: %w", ctx, err)
	}

	clientPassword := os.Getenv(c.Client.PasswordEnv)
	if clientPassword == "" {
		return nil, fmt.Errorf("%s: client.password_env %q is not set in the environment", ctx, c.Client.PasswordEnv)
	}

	return &Policy{
		name:           c.Name,
		listen:         c.Listen,
		role:           c.Role,
		upstreamDSN:    dsnSource,
		clientUser:     c.Client.User,
		clientPassword: clientPassword,
	}, nil
}

// NewManagedPolicy builds a Policy for a control-plane-synced listener. The
// upstream DSN source and optional role come from the control plane; the listen
// address and client credentials come from the proxy's environment. Unlike the
// YAML path, clientPassword is the literal password value, not the name of an
// env var — managed mode has no second level of indirection. All fields except
// role are required.
func NewManagedPolicy(name, listen string, dsn secrets.Source, clientUser, clientPassword, role string) (*Policy, error) {
	if name == "" {
		return nil, fmt.Errorf("postgres: managed policy name is required")
	}
	ctx := fmt.Sprintf("postgres[%q]", name)
	if listen == "" {
		return nil, fmt.Errorf("%s: listen is required", ctx)
	}
	if dsn == nil {
		return nil, fmt.Errorf("%s: dsn source is required", ctx)
	}
	if clientUser == "" {
		return nil, fmt.Errorf("%s: client user is required", ctx)
	}
	if clientPassword == "" {
		return nil, fmt.Errorf("%s: client password is required", ctx)
	}
	return &Policy{
		name:           name,
		listen:         listen,
		role:           role,
		upstreamDSN:    dsn,
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
