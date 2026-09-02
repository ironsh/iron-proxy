// Package secretbroker implements a transform that lets a sandboxed workload
// USE a credential without ever being able to READ it.
//
// The workload holds only a placeholder token. On requests to hosts the
// operator has allowed for that placeholder, secretbroker swaps the
// placeholder for the real credential just before the request leaves the
// proxy; on the way back it swaps any echoed credential back to the
// placeholder, so a workload cannot recover the secret by bouncing it off an
// echo endpoint. The real value only ever exists inside the proxy process and
// on the wire to the allowed upstream.
//
// Three properties are load-bearing and are what the tests pin down:
//
//   - Host scoping. A placeholder is only ever substituted on a request whose
//     host matches that entry's own rules. An entry never leaks its credential
//     to another entry's host, and never to an unlisted host.
//   - Fail closed. When the secrets file is missing or unreadable, the entry
//     performs no substitution at all: the placeholder travels upstream and the
//     upstream rejects it. One warning naming the path (never the contents) is
//     logged per distinct failure, not per request.
//   - Audit stays clean. secretbroker annotates the placeholder and the
//     secret_ref (both non-secret names) and never the credential, so the audit
//     stream continues to show the placeholder.
//
// Like all header-rewriting transforms this requires MITM mode; in sni-only
// mode there are no headers or body to rewrite and every entry no-ops.
//
// Pipeline ordering: place secretbroker last. Transforms that capture request
// headers into the audit stream (e.g. annotate) must run before it so they
// record the placeholder rather than the substituted credential.
package secretbroker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

const transformName = "secretbroker"

func init() {
	transform.Register(transformName, factory)
}

// config is the YAML config structure.
type config struct {
	// SecretsFile is a root-owned file holding a flat JSON object of
	// secret_ref -> credential. Required when any entry uses secret_ref.
	SecretsFile string `yaml:"secrets_file,omitempty"`

	Entries []entryConfig `yaml:"entries"`
}

type entryConfig struct {
	// Placeholder is the fake token the workload holds.
	Placeholder string `yaml:"placeholder"`

	// SecretRef names a key in the secrets file. Mutually exclusive with Source.
	SecretRef string `yaml:"secret_ref,omitempty"`

	// Source is any secrets-package source block ({type: env, var: FOO},
	// aws_sm, 1password, ...). Mutually exclusive with SecretRef.
	Source yaml.Node `yaml:"source,omitempty"`

	// Hosts is flat sugar for rules with no method/path restriction, matching
	// the shape the allowlist transform accepts.
	Hosts []string `yaml:"hosts,omitempty"`

	// Rules are full host/method/path rules. Combined with Hosts.
	Rules []hostmatch.RuleConfig `yaml:"rules,omitempty"`

	// Headers lists request headers to scan in addition to Authorization,
	// which is always scanned.
	Headers []string `yaml:"headers,omitempty"`

	// MatchBody opts the entry into scanning the request body.
	MatchBody bool `yaml:"match_body,omitempty"`

	// ScrubResponse controls swapping an echoed credential back to the
	// placeholder on the response. Defaults to true; set false to opt out.
	ScrubResponse *bool `yaml:"scrub_response,omitempty"`
}

// entry is a config entry compiled and ready to use.
type entry struct {
	placeholder string

	// ref is a non-secret display name for the credential — the secret_ref
	// key or the source's name. Safe to put in logs and audit annotations.
	ref string

	// get returns the real credential, or an error when it is unavailable.
	get func(ctx context.Context) (string, error)

	rules         []hostmatch.Rule
	headers       []string // canonical names; always includes Authorization
	matchBody     bool
	scrubResponse bool
}

// SecretBroker is the transform.
type SecretBroker struct {
	entries []entry
}

func factory(cfg yaml.Node, logger *slog.Logger) (transform.Transformer, error) {
	var c config
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing %s config: %w", transformName, err)
	}
	return newFromConfig(c, logger, secrets.BuildSource)
}

// sourceBuilder is the signature of secrets.BuildSource, pulled out so tests
// can inject a stub instead of constructing real source backends.
type sourceBuilder func(yaml.Node, *slog.Logger) (secrets.Source, error)

func newFromConfig(c config, logger *slog.Logger, buildSource sourceBuilder) (*SecretBroker, error) {
	if len(c.Entries) == 0 {
		return nil, fmt.Errorf("%s: at least one entry is required", transformName)
	}

	// The file store is created lazily so a config that only uses source
	// blocks does not need secrets_file at all. Creating it performs the
	// startup load, which is where a missing file logs its one warning.
	var store *fileStore
	fileStoreFor := func() (*fileStore, error) {
		if c.SecretsFile == "" {
			return nil, fmt.Errorf("secret_ref requires \"secrets_file\" to be set")
		}
		if store == nil {
			store = newFileStore(c.SecretsFile, logger)
		}
		return store, nil
	}

	entries := make([]entry, 0, len(c.Entries))
	seen := make(map[string]int, len(c.Entries))

	for i, ec := range c.Entries {
		ctxName := fmt.Sprintf("%s: entries[%d]", transformName, i)

		if ec.Placeholder == "" {
			return nil, fmt.Errorf("%s: placeholder is required", ctxName)
		}
		if prev, dup := seen[ec.Placeholder]; dup {
			// Two entries sharing a placeholder would substitute
			// different credentials depending on rule order, which is
			// never what an operator means.
			return nil, fmt.Errorf("%s: placeholder %q is already used by entries[%d]", ctxName, ec.Placeholder, prev)
		}
		// A placeholder that contains another is a silent-corruption hazard:
		// substituting the shorter one first mangles the longer one, and what
		// goes upstream is neither credential.
		for other := range seen {
			if strings.Contains(ec.Placeholder, other) || strings.Contains(other, ec.Placeholder) {
				return nil, fmt.Errorf("%s: placeholder %q overlaps placeholder %q from entries[%d]", ctxName, ec.Placeholder, other, seen[other])
			}
		}
		seen[ec.Placeholder] = i

		hasRef := ec.SecretRef != ""
		hasSource := ec.Source.Kind != 0
		if hasRef == hasSource {
			return nil, fmt.Errorf("%s: requires exactly one of \"secret_ref\" or \"source\"", ctxName)
		}

		var (
			ref string
			get func(context.Context) (string, error)
		)
		if hasRef {
			fs, err := fileStoreFor()
			if err != nil {
				return nil, fmt.Errorf("%s: %w", ctxName, err)
			}
			ref = ec.SecretRef
			get = func(context.Context) (string, error) { return fs.get(ec.SecretRef) }
		} else {
			src, err := buildSource(ec.Source, logger)
			if err != nil {
				return nil, fmt.Errorf("%s: building source: %w", ctxName, err)
			}
			ref = src.Name()
			get = src.Get
		}

		rules, err := compileRules(ec, ctxName)
		if err != nil {
			return nil, err
		}
		if len(rules) == 0 {
			// Unlike allowlist, an empty rule set is a config error rather
			// than "match everything": a credential that substitutes onto
			// every host is exactly what this transform exists to prevent.
			return nil, fmt.Errorf("%s: at least one entry in \"hosts\" or \"rules\" is required", ctxName)
		}

		entries = append(entries, entry{
			placeholder:   ec.Placeholder,
			ref:           ref,
			get:           get,
			rules:         rules,
			headers:       compileHeaders(ec.Headers),
			matchBody:     ec.MatchBody,
			scrubResponse: ec.ScrubResponse == nil || *ec.ScrubResponse,
		})
	}

	return &SecretBroker{entries: entries}, nil
}

// compileRules turns the flat hosts sugar and the explicit rules block into
// one compiled rule set.
func compileRules(ec entryConfig, ctxName string) ([]hostmatch.Rule, error) {
	var rules []hostmatch.Rule
	for _, h := range ec.Hosts {
		if h == "*" {
			return nil, fmt.Errorf("%s: host \"*\" is not allowed; list the hosts the credential may be sent to", ctxName)
		}
		m, err := hostmatch.New([]string{h}, nil)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ctxName, err)
		}
		rules = append(rules, hostmatch.Rule{Matcher: m})
	}
	for _, rc := range ec.Rules {
		if rc.Host == "*" {
			return nil, fmt.Errorf("%s: host \"*\" is not allowed; list the hosts the credential may be sent to", ctxName)
		}
	}
	compiled, err := hostmatch.CompileRules(ec.Rules, ctxName)
	if err != nil {
		return nil, err
	}
	return append(rules, compiled...), nil
}

// compileHeaders canonicalizes the header allowlist and guarantees
// Authorization is present, since that is where a credential lands by default.
func compileHeaders(names []string) []string {
	out := []string{"Authorization"}
	for _, n := range names {
		canonical := http.CanonicalHeaderKey(n)
		if canonical == "" || canonical == "Authorization" {
			continue
		}
		if !containsString(out, canonical) {
			out = append(out, canonical)
		}
	}
	return out
}

func containsString(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func (b *SecretBroker) Name() string { return transformName }

// substitution is the audit record for one entry. It deliberately carries the
// placeholder and the secret_ref — both non-secret — and never the credential.
type substitution struct {
	Placeholder string   `json:"placeholder"`
	SecretRef   string   `json:"secret_ref"`
	Locations   []string `json:"locations"`
}

// TransformRequest swaps each matching entry's placeholder for its real
// credential in the allowed request headers and, when the entry opts in, the
// request body.
func (b *SecretBroker) TransformRequest(ctx context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	cont := &transform.TransformResult{Action: transform.ActionContinue}
	if tctx.Mode == transform.ModeSNIOnly {
		return cont, nil
	}

	var substituted []substitution
	var unavailable []string

	for i := range b.entries {
		e := &b.entries[i]

		// Host scoping. Checked before the credential is even fetched, so a
		// request to a host this entry does not allow cannot pull the
		// credential into the process for any reason.
		if !hostmatch.MatchAnyRule(e.rules, req) {
			continue
		}

		secret, err := e.get(ctx)
		if err != nil || secret == "" {
			// Fail closed: no substitution. The placeholder travels upstream
			// and the upstream rejects it. e.ref is a name, not a value.
			unavailable = append(unavailable, e.ref)
			continue
		}

		locations := substituteHeaders(req.Header, e.headers, e.placeholder, secret)
		if e.matchBody {
			if loc := substituteRequestBody(req, e.placeholder, secret); loc != "" {
				locations = append(locations, loc)
			}
		}

		if len(locations) > 0 {
			substituted = append(substituted, substitution{
				Placeholder: e.placeholder,
				SecretRef:   e.ref,
				Locations:   locations,
			})
		}
	}

	if len(substituted) > 0 {
		tctx.Annotate("substituted", substituted)
	}
	if len(unavailable) > 0 {
		tctx.Annotate("secret_unavailable", unavailable)
	}
	return cont, nil
}

// TransformResponse swaps any echoed credential back to the placeholder before
// the response reaches the workload, so an echo endpoint cannot be used to read
// the credential.
//
// Response headers are scanned in full rather than through the entry's header
// allowlist: the allowlist says where the proxy is willing to *write* a
// credential, but a leak on the way back can surface in any header.
//
// Body scrubbing is bounded by the proxy's existing response body-capture
// limit (proxy.max_response_body_bytes): the body has already been wrapped in
// a size-capped BufferedBody by the time it reaches here, so a body past the
// cap is truncated by that mechanism rather than by anything here. SSE
// responses are left alone so per-chunk streaming is preserved.
func (b *SecretBroker) TransformResponse(ctx context.Context, tctx *transform.TransformContext, req *http.Request, resp *http.Response) (*transform.TransformResult, error) {
	cont := &transform.TransformResult{Action: transform.ActionContinue}
	if tctx.Mode == transform.ModeSNIOnly || resp == nil {
		return cont, nil
	}

	var scrubbed []substitution
	streaming := isSSE(resp)

	for i := range b.entries {
		e := &b.entries[i]
		if !e.scrubResponse || !hostmatch.MatchAnyRule(e.rules, req) {
			continue
		}

		secret, err := e.get(ctx)
		if err != nil || secret == "" {
			continue
		}

		locations := scrubHeaders(resp.Header, e.placeholder, secret)
		if !streaming {
			if loc := scrubResponseBody(resp, e.placeholder, secret); loc != "" {
				locations = append(locations, loc)
			}
		}

		if len(locations) > 0 {
			scrubbed = append(scrubbed, substitution{
				Placeholder: e.placeholder,
				SecretRef:   e.ref,
				Locations:   locations,
			})
		}
	}

	if len(scrubbed) > 0 {
		tctx.Annotate("scrubbed", scrubbed)
		if streaming {
			// Worth surfacing: a credential echoed inside an SSE stream is
			// not scrubbed, and the operator should know the entry matched a
			// streaming response.
			tctx.Annotate("scrub_skipped", "sse_body")
		}
	}
	return cont, nil
}

// substituteHeaders replaces the placeholder with the credential in the named
// headers only, and returns the locations touched.
func substituteHeaders(h http.Header, names []string, placeholder, secret string) []string {
	var locations []string
	for _, name := range names {
		vals := h.Values(name)
		if len(vals) == 0 {
			continue
		}
		hit := false
		replaced := make([]string, len(vals))
		for i, v := range vals {
			replaced[i] = secrets.ReplaceInHeader(name, v, placeholder, secret)
			if replaced[i] != v {
				hit = true
			}
		}
		if !hit {
			continue
		}
		h.Del(name)
		for _, v := range replaced {
			h.Add(name, v)
		}
		locations = append(locations, "header:"+name)
	}
	return locations
}

// scrubHeaders replaces the credential with the placeholder across every
// response header.
func scrubHeaders(h http.Header, placeholder, secret string) []string {
	var locations []string
	for name, vals := range h {
		hit := false
		for i, v := range vals {
			if replaced := secrets.ReplaceInHeader(name, v, secret, placeholder); replaced != v {
				vals[i] = replaced
				hit = true
			}
		}
		if hit {
			locations = append(locations, "header:"+name)
		}
	}
	return locations
}

// substituteRequestBody replaces the placeholder with the credential in the
// request body. Returns "body" when the body was rewritten.
func substituteRequestBody(req *http.Request, placeholder, secret string) string {
	if req.Body == nil {
		return ""
	}
	replaced, changed := replaceBody(req.Body, placeholder, secret)
	if !changed {
		return ""
	}
	req.Body = transform.NewBufferedBodyFromBytes(replaced)
	req.ContentLength = int64(len(replaced))
	return "body"
}

// scrubResponseBody replaces the credential with the placeholder in the
// response body. Returns "body" when the body was rewritten.
func scrubResponseBody(resp *http.Response, placeholder, secret string) string {
	if resp.Body == nil {
		return ""
	}
	replaced, changed := replaceBody(resp.Body, secret, placeholder)
	if !changed {
		return ""
	}
	resp.Body = transform.NewBufferedBodyFromBytes(replaced)
	resp.ContentLength = int64(len(replaced))
	return "body"
}

// replaceBody reads a pipeline body and returns the rewritten bytes. changed
// is false when the body could not be read or did not contain from, in which
// case the caller leaves the original body in place.
//
// The body is rewound after reading. The pipeline resets it between
// transforms, but not between entries within one pass: without this a second
// entry would read EOF whenever the first entry read the body and found
// nothing to rewrite.
func replaceBody(body io.ReadCloser, from, to string) (out []byte, changed bool) {
	data, err := io.ReadAll(body)
	if buf, ok := body.(*transform.BufferedBody); ok {
		buf.Reset()
	}
	if err != nil || !bytes.Contains(data, []byte(from)) {
		return nil, false
	}
	return bytes.ReplaceAll(data, []byte(from), []byte(to)), true
}

// isSSE mirrors the proxy's Server-Sent Events detection. Buffering an SSE
// body to scrub it would break per-chunk streaming, so those bodies are left
// untouched.
func isSSE(resp *http.Response) bool {
	return strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream")
}

// --- secrets file store ---

// fileStore reads a flat JSON object of secret_ref -> credential from a
// root-owned path.
//
// The file is loaded once at startup and re-read when the file changes on
// disk, detected by comparing size and mtime. That covers credential rotation
// in place; the fork's other reload vector, the management API's
// POST /v1/reload, rebuilds the whole pipeline and so re-reads the file too.
//
// A missing or unreadable file is not fatal: get returns an error, the caller
// skips substitution, and the credential is never at risk. One warning naming
// the path — never the contents — is logged per distinct failure, so a
// persistently missing file does not flood the log on every request.
type fileStore struct {
	path   string
	logger *slog.Logger

	// Injectable for tests.
	stat func(string) (os.FileInfo, error)
	read func(string) ([]byte, error)

	mu     sync.Mutex
	values map[string]string
	stamp  stamp

	// warnedFor is the error text of the last warning emitted, used to
	// collapse repeats of the same failure into a single log line.
	warnedFor string
}

// stamp identifies a file version cheaply enough to check on every request.
type stamp struct {
	size    int64
	modTime time.Time
}

func newFileStore(path string, logger *slog.Logger) *fileStore {
	fs := &fileStore{
		path:   path,
		logger: logger,
		stat:   os.Stat,
		read:   os.ReadFile,
	}
	// Startup load: surfaces a missing or malformed file at boot rather than
	// on the first request that needs it.
	fs.mu.Lock()
	fs.reload()
	fs.mu.Unlock()
	return fs
}

// get returns the credential for ref. Callers treat any error as "substitution
// disabled for this entry".
func (fs *fileStore) get(ref string) (string, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fs.changedOnDisk() {
		fs.reload()
	}
	if fs.values == nil {
		return "", fmt.Errorf("secrets file %q is unavailable", fs.path)
	}
	v, ok := fs.values[ref]
	if !ok || v == "" {
		return "", fmt.Errorf("secret_ref %q not present in secrets file %q", ref, fs.path)
	}
	return v, nil
}

// changedOnDisk reports whether the file's size or mtime differs from the last
// load. A stat failure counts as changed so the reload path emits the warning
// and drops any stale values.
//
// Callers must hold fs.mu.
func (fs *fileStore) changedOnDisk() bool {
	fi, err := fs.stat(fs.path)
	if err != nil {
		return true
	}
	return stamp{size: fi.Size(), modTime: fi.ModTime()} != fs.stamp
}

// reload re-reads and re-parses the file. On any failure the cached values are
// cleared, so a file that becomes unreadable disables substitution rather than
// serving a stale credential.
//
// Callers must hold fs.mu.
func (fs *fileStore) reload() {
	fi, err := fs.stat(fs.path)
	if err != nil {
		fs.fail(fmt.Sprintf("cannot stat secrets file: %v", err))
		return
	}

	data, err := fs.read(fs.path)
	if err != nil {
		fs.fail(fmt.Sprintf("cannot read secrets file: %v", err))
		return
	}

	var values map[string]string
	if err := json.Unmarshal(data, &values); err != nil {
		// Deliberately does not include err's text: a JSON syntax error
		// message can quote the offending bytes, which are credentials.
		fs.fail("secrets file is not a flat JSON object of secret_ref to value")
		return
	}

	fs.values = values
	fs.stamp = stamp{size: fi.Size(), modTime: fi.ModTime()}
	fs.warnedFor = ""
}

// fail records a load failure, clearing cached values and logging at most one
// warning per distinct reason. The message names the path only.
//
// Callers must hold fs.mu.
func (fs *fileStore) fail(reason string) {
	fs.values = nil
	fs.stamp = stamp{}
	if fs.warnedFor == reason {
		return
	}
	fs.warnedFor = reason
	if fs.logger != nil {
		fs.logger.Warn("secretbroker substitution disabled",
			slog.String("path", fs.path),
			slog.String("reason", reason),
		)
	}
}
