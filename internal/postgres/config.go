// Package postgres implements an iron-proxy listener that MITM-proxies
// PostgreSQL traffic so a static role policy is in effect on every query the
// upstream database sees.
//
// The listener accepts client connections, authenticates them against
// proxy-managed credentials, opens its own authenticated connection upstream
// (handling SCRAM/MD5 termination via pgconn), applies the upstream's pinned
// session settings and optionally issues a single `SET ROLE "<role>"` on the
// upstream session, then relays the PostgreSQL wire protocol bidirectionally.
//
// Deployment assumption: if PgBouncer (or any pooler) sits between the proxy
// and PostgreSQL, it must be configured in session-pool mode. Transaction or
// statement pooling silently rebinds backends between queries and would
// nullify the role injection. This is not probed at runtime — the constraint
// is enforced by deployment configuration.
//
// While the relay is running the proxy is mostly transparent. It rejects
// client-issued role-changing statements (`SET ROLE`, `RESET ROLE`,
// `SET SESSION AUTHORIZATION`, `RESET SESSION AUTHORIZATION`) and their
// function-call equivalents (`set_config('role', ...)`); any `SET`, `RESET`, or
// `set_config` of a setting the upstream pins; the reset-everything statements
// `RESET ALL` and `DISCARD ALL` (which would clear the managed role and pinned
// settings); and DO blocks. Multi-statement Simple Queries are allowed as long
// as every statement passes; a batch is rejected if any statement is rejected.
// Extended Query, COPY, and prepared statements pass through unchanged.
//
// The proxy runs a single postgres listener fronting multiple upstream routes.
// A route is selected by the database name and optional iron.route value the
// client supplies in its startup message. The selector allows multiple policy
// routes to share one physical database without weakening role isolation.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"

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
// one shared client credential fronting a set of database-and-route upstreams.
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

// UpstreamConfig describes one upstream route reachable through the listener.
// The client selects it by sending its Database value as the startup "database"
// parameter and, when needed, its Route as the startup "iron.route" parameter.
type UpstreamConfig struct {
	// Database is the routing key: the database name a client must request to
	// reach this upstream. Required and must be unique across upstreams. It must
	// also equal the database the DSN connects to (the dbname in the DSN); the
	// proxy rejects a connection whose upstream session would land on a
	// different database than the client named.
	Database string `yaml:"database"`

	// Route distinguishes policy routes that share one physical database. It is
	// optional while Database has only one upstream, and required when multiple
	// upstreams use the same Database.
	Route string `yaml:"route,omitempty"`

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

	// Settings are session variables (GUCs) the proxy SETs at session start for
	// this upstream, in order, before the SET ROLE. Each is applied via
	// set_config(name, value, false) so the value is a session-level parameter.
	// The proxy also pins these names: a client may not SET, RESET, or
	// set_config them afterwards (nor RESET ALL / DISCARD ALL), so a setting
	// used as a security boundary (e.g. an RLS key) can't be overridden. The
	// name must be a bare or dotted GUC identifier; role and
	// session_authorization are reserved (use Role). Optional.
	Settings []Setting `yaml:"settings,omitempty"`
}

// Setting is one session variable the proxy injects at session start: a GUC
// name and the value it is set to. Values are applied verbatim through
// set_config, so no SQL quoting is required of the configuration.
type Setting struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
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

	upstreams map[upstreamKey]*Upstream
}

type upstreamKey struct {
	database string
	route    string
}

// Name returns the listener's name (a fixed identifier surfaced in logs).
func (l *Listener) Name() string { return l.name }

// Listen returns the bind address.
func (l *Listener) Listen() string { return l.listen }

// Upstream returns the sole upstream for a database. It returns nil when the
// database is missing or has multiple routes.
func (l *Listener) Upstream(database string) *Upstream {
	upstream, _ := l.SelectUpstream(database, "")
	return upstream
}

var (
	ErrNoUpstream    = errors.New("no postgres upstream")
	ErrRouteRequired = errors.New("postgres route selector required")
	ErrUnknownRoute  = errors.New("unknown postgres route selector")
)

// SelectUpstream resolves a physical database and optional logical route. A
// database with one route remains backward compatible when iron.route is
// absent. A database with multiple routes fails closed without a selector.
func (l *Listener) SelectUpstream(database, route string) (*Upstream, error) {
	if route != "" {
		upstream := l.upstreams[upstreamKey{database: database, route: route}]
		if upstream == nil {
			return nil, ErrUnknownRoute
		}
		return upstream, nil
	}

	var selected *Upstream
	for key, upstream := range l.upstreams {
		if key.database != database {
			continue
		}
		if selected != nil {
			return nil, ErrRouteRequired
		}
		selected = upstream
	}
	if selected == nil {
		return nil, ErrNoUpstream
	}
	return selected, nil
}

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
// keeping the listener's address and client credential. A local legacy route
// without a selector wins any same-database collision; otherwise only an exact
// database-and-route collision is dropped.
func (l *Listener) WithUpstreams(extra []*Upstream) (listener *Listener, dropped []string) {
	m := make(map[upstreamKey]*Upstream, len(l.upstreams)+len(extra))
	for key, upstream := range l.upstreams {
		m[key] = upstream
	}
	for _, upstream := range extra {
		if _, ok := m[upstreamKey{database: upstream.database, route: ""}]; ok {
			dropped = append(dropped, routeLabel(upstream.database, upstream.route))
			continue
		}
		key := upstreamKey{database: upstream.database, route: upstream.route}
		if _, ok := m[key]; ok {
			dropped = append(dropped, routeLabel(upstream.database, upstream.route))
			continue
		}
		m[key] = upstream
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
// upstream database with its DSN, optional injected role, and optional pinned
// session settings.
type Upstream struct {
	database string
	route    string
	role     string
	settings []Setting

	// pinnedGUCs is the lowercased set of setting names the relay forbids the
	// client from mutating. Derived from settings; never includes role or
	// session_authorization (those are always blocked by the role policy).
	pinnedGUCs map[string]struct{}

	dsn secrets.Source
}

// Database returns the upstream's routing key — the database name a client
// requests to reach it.
func (u *Upstream) Database() string { return u.database }

// Route returns the logical selector for this policy route.
func (u *Upstream) Route() string { return u.route }

// Role returns the role the proxy SETs upstream at session start. Empty
// means no role is set (the upstream session runs as the connecting user).
func (u *Upstream) Role() string { return u.role }

// Settings returns the session variables the proxy SETs at session start, in
// configuration order.
func (u *Upstream) Settings() []Setting { return u.settings }

// PinnedGUCs returns the lowercased set of setting names the client is forbidden
// from mutating for this upstream. The returned map must not be modified.
func (u *Upstream) PinnedGUCs() map[string]struct{} { return u.pinnedGUCs }

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

	upstreams := make(map[upstreamKey]*Upstream, len(c.Upstreams))
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
		key := upstreamKey{database: uc.Database, route: uc.Route}
		if _, ok := upstreams[key]; ok {
			return nil, fmt.Errorf("postgres: duplicate upstream route %q", routeLabel(uc.Database, uc.Route))
		}

		dsnSource, err := buildSource(uc.DSN, logger)
		if err != nil {
			return nil, fmt.Errorf("%s: building dsn source: %w", uctx, err)
		}

		settings, pinned, err := compileSettings(uctx, uc.Settings)
		if err != nil {
			return nil, err
		}

		upstreams[key] = &Upstream{
			database:   uc.Database,
			route:      uc.Route,
			role:       uc.Role,
			settings:   settings,
			pinnedGUCs: pinned,
			dsn:        dsnSource,
		}
	}
	if err := validateRoutes(upstreams); err != nil {
		return nil, err
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
// and at least one upstream must be supplied; an upstream whose database and
// route collide with an earlier one is an error.
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
	m := make(map[upstreamKey]*Upstream, len(upstreams))
	for _, u := range upstreams {
		key := upstreamKey{database: u.database, route: u.route}
		if _, ok := m[key]; ok {
			return nil, fmt.Errorf("postgres: duplicate upstream route %q", routeLabel(u.database, u.route))
		}
		m[key] = u
	}
	if err := validateRoutes(m); err != nil {
		return nil, err
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
// DSN source, route selector, optional role, and optional pinned session
// settings come from the control plane. Database is required; route, role, and
// settings are otherwise optional. Settings are validated identically to YAML.
func NewManagedUpstream(database string, dsn secrets.Source, role string, settings []Setting) (*Upstream, error) {
	return NewManagedRoute(database, "", dsn, role, settings)
}

// NewManagedRoute builds a control-plane upstream with an explicit logical
// selector. Distinct routes may share one physical database.
func NewManagedRoute(database, route string, dsn secrets.Source, role string, settings []Setting) (*Upstream, error) {
	if database == "" {
		return nil, fmt.Errorf("postgres: managed upstream database is required")
	}
	if dsn == nil {
		return nil, fmt.Errorf("postgres upstream[%q]: dsn source is required", database)
	}
	compiled, pinned, err := compileSettings(fmt.Sprintf("postgres upstream[%q]", database), settings)
	if err != nil {
		return nil, err
	}
	return &Upstream{
		database:   database,
		route:      route,
		role:       role,
		settings:   compiled,
		pinnedGUCs: pinned,
		dsn:        dsn,
	}, nil
}

func validateRoutes(upstreams map[upstreamKey]*Upstream) error {
	counts := make(map[string]int)
	unnamed := make(map[string]bool)
	for key := range upstreams {
		counts[key.database]++
		unnamed[key.database] = unnamed[key.database] || key.route == ""
	}
	for database, count := range counts {
		if count > 1 && unnamed[database] {
			return fmt.Errorf("postgres: database %q has multiple upstreams; every upstream must set route", database)
		}
	}
	return nil
}

func routeLabel(database, route string) string {
	if route == "" {
		return database
	}
	return database + "/" + route
}

// gucNameRe matches a Postgres GUC name: a bare identifier, or a dotted
// class.name custom variable. The strict charset lets the proxy treat validated
// names as trusted, and matches the form custom settings (e.g. centaur.foo)
// must take.
var gucNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$`)

// compileSettings validates a slice of session settings and returns the cleaned
// slice alongside the lowercased set of names to pin. ctx is a config-location
// prefix for error messages (e.g. `postgres.upstreams["centaur"]`). Names must
// be valid GUC identifiers, unique within the upstream, and may not be role or
// session_authorization (those are managed via the role field and always
// blocked by the role policy).
func compileSettings(ctx string, settings []Setting) ([]Setting, map[string]struct{}, error) {
	if len(settings) == 0 {
		return nil, nil, nil
	}
	out := make([]Setting, 0, len(settings))
	pinned := make(map[string]struct{}, len(settings))
	for i, s := range settings {
		if s.Name == "" {
			return nil, nil, fmt.Errorf("%s: settings[%d]: name is required", ctx, i)
		}
		if !gucNameRe.MatchString(s.Name) {
			return nil, nil, fmt.Errorf("%s: settings[%d]: invalid setting name %q", ctx, i, s.Name)
		}
		lower := strings.ToLower(s.Name)
		if lower == "role" || lower == "session_authorization" {
			return nil, nil, fmt.Errorf("%s: settings[%d]: %q is managed by the proxy; use the role field", ctx, i, s.Name)
		}
		if _, dup := pinned[lower]; dup {
			return nil, nil, fmt.Errorf("%s: duplicate setting %q", ctx, s.Name)
		}
		pinned[lower] = struct{}{}
		out = append(out, s)
	}
	return out, pinned, nil
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
