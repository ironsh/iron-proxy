// Package postgres implements an iron-proxy listener that MITM-proxies
// PostgreSQL traffic so a static role policy is in effect on every query the
// upstream database sees.
//
// The listener accepts client connections, authenticates them against
// proxy-managed credentials, opens its own authenticated connection upstream
// (handling SCRAM/MD5 termination via pgconn), and then relays the PostgreSQL
// wire protocol bidirectionally. Before handing control to the relay loop the
// proxy issues a single `SET ROLE "<role>"` to the upstream and verifies the
// role sticks across separate autocommit queries, which simultaneously sets
// the policy and guards against PgBouncer pool modes that would silently
// drop the role between queries (transaction / statement pooling).
//
// While the relay is running the proxy is mostly transparent: it rejects only
// client-issued role-changing statements (`SET ROLE`, `RESET ROLE`,
// `SET SESSION AUTHORIZATION`, `RESET SESSION AUTHORIZATION`) and
// multi-statement Simple Queries, so the configured role can't be overridden
// mid-session. Extended Query, COPY, and prepared statements pass through
// unchanged.
package postgres

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Upstream SSL modes accepted by the proxy→database connection.
const (
	UpstreamSSLDisable = "disable"
	UpstreamSSLRequire = "require"
)

// Config is the YAML shape of the top-level postgres: block.
type Config struct {
	// Listen is the proxy's bind address for client connections, e.g. ":5432".
	Listen string `yaml:"listen"`

	// Upstream is the database the proxy connects to on behalf of clients.
	Upstream UpstreamConfig `yaml:"upstream"`

	// Client describes the credentials clients must present when authenticating
	// to the proxy. The proxy verifies a single shared user/password pair —
	// per-user credentials are not supported.
	Client ClientConfig `yaml:"client"`

	// Role is the Postgres role the proxy SETs at session start. Every query
	// the client subsequently issues runs as this role on the upstream database.
	Role string `yaml:"role"`
}

// UpstreamConfig describes the database the proxy forwards to.
type UpstreamConfig struct {
	Host        string `yaml:"host"`
	Port        int    `yaml:"port"`
	SSLMode     string `yaml:"sslmode"`
	UserEnv     string `yaml:"user_env"`
	PasswordEnv string `yaml:"password_env"`
	Database    string `yaml:"database"`
}

// ClientConfig describes the credentials the proxy demands from clients.
type ClientConfig struct {
	User        string `yaml:"user"`
	PasswordEnv string `yaml:"password_env"`
}

// Policy is the compiled, runtime form of the postgres config.
type Policy struct {
	listen string
	role   string

	upstreamHost     string
	upstreamPort     int
	upstreamSSLMode  string
	upstreamUser     string
	upstreamPassword string
	upstreamDB       string

	clientUser     string
	clientPassword string
}

// Listen returns the bind address.
func (p *Policy) Listen() string { return p.listen }

// Role returns the role the proxy SETs upstream at session start.
func (p *Policy) Role() string { return p.role }

// UpstreamHost returns the upstream database host.
func (p *Policy) UpstreamHost() string { return p.upstreamHost }

// UpstreamPort returns the upstream database port.
func (p *Policy) UpstreamPort() int { return p.upstreamPort }

// UpstreamSSLMode returns the upstream sslmode (disable|require).
func (p *Policy) UpstreamSSLMode() string { return p.upstreamSSLMode }

// UpstreamUser returns the username the proxy uses to authenticate upstream.
func (p *Policy) UpstreamUser() string { return p.upstreamUser }

// UpstreamPassword returns the password the proxy uses to authenticate
// upstream. It is loaded from the env var named in UpstreamConfig.PasswordEnv.
func (p *Policy) UpstreamPassword() string { return p.upstreamPassword }

// UpstreamDatabase returns the dbname the proxy connects to upstream.
func (p *Policy) UpstreamDatabase() string { return p.upstreamDB }

// VerifyClient returns whether the given (user, password) pair matches the
// configured client credentials.
func (p *Policy) VerifyClient(user, password string) bool {
	return user == p.clientUser && password == p.clientPassword
}

// ClientUser returns the user clients must present to the proxy.
func (p *Policy) ClientUser() string { return p.clientUser }

// LoadFromNode decodes a raw yaml.Node into a Config and compiles it. An empty
// node (the postgres: block absent from the source document) returns
// (nil, nil) so callers can treat "no postgres listener" as a normal case.
func LoadFromNode(node yaml.Node) (*Policy, error) {
	if node.Kind == 0 {
		return nil, nil
	}
	var c Config
	if err := node.Decode(&c); err != nil {
		return nil, fmt.Errorf("decoding postgres config: %w", err)
	}
	return Compile(c)
}

// Compile validates and compiles a Config into a Policy. Returns (nil, nil)
// when the config is entirely empty so callers can treat "not configured" as
// a no-op without a sentinel error.
func Compile(c Config) (*Policy, error) {
	if isZero(c) {
		return nil, nil
	}

	if c.Listen == "" {
		return nil, errors.New("postgres.listen is required")
	}
	if c.Role == "" {
		return nil, errors.New("postgres.role is required")
	}
	if c.Upstream.Host == "" {
		return nil, errors.New("postgres.upstream.host is required")
	}
	if c.Upstream.Port == 0 {
		c.Upstream.Port = 5432
	}
	if c.Upstream.Database == "" {
		return nil, errors.New("postgres.upstream.database is required")
	}
	if c.Upstream.UserEnv == "" {
		return nil, errors.New("postgres.upstream.user_env is required")
	}
	if c.Upstream.PasswordEnv == "" {
		return nil, errors.New("postgres.upstream.password_env is required")
	}
	if c.Upstream.SSLMode == "" {
		c.Upstream.SSLMode = UpstreamSSLDisable
	}
	switch c.Upstream.SSLMode {
	case UpstreamSSLDisable, UpstreamSSLRequire:
	default:
		return nil, fmt.Errorf("postgres.upstream.sslmode must be %q or %q; got %q", UpstreamSSLDisable, UpstreamSSLRequire, c.Upstream.SSLMode)
	}
	if c.Client.User == "" {
		return nil, errors.New("postgres.client.user is required")
	}
	if c.Client.PasswordEnv == "" {
		return nil, errors.New("postgres.client.password_env is required")
	}

	upstreamUser := os.Getenv(c.Upstream.UserEnv)
	if upstreamUser == "" {
		return nil, fmt.Errorf("postgres.upstream.user_env %q is not set in the environment", c.Upstream.UserEnv)
	}
	upstreamPassword := os.Getenv(c.Upstream.PasswordEnv)
	if upstreamPassword == "" {
		return nil, fmt.Errorf("postgres.upstream.password_env %q is not set in the environment", c.Upstream.PasswordEnv)
	}
	clientPassword := os.Getenv(c.Client.PasswordEnv)
	if clientPassword == "" {
		return nil, fmt.Errorf("postgres.client.password_env %q is not set in the environment", c.Client.PasswordEnv)
	}

	return &Policy{
		listen:           c.Listen,
		role:             c.Role,
		upstreamHost:     c.Upstream.Host,
		upstreamPort:     c.Upstream.Port,
		upstreamSSLMode:  c.Upstream.SSLMode,
		upstreamUser:     upstreamUser,
		upstreamPassword: upstreamPassword,
		upstreamDB:       c.Upstream.Database,
		clientUser:       c.Client.User,
		clientPassword:   clientPassword,
	}, nil
}

func isZero(c Config) bool {
	return c.Listen == "" && c.Role == "" && c.Upstream == (UpstreamConfig{}) && c.Client == (ClientConfig{})
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
