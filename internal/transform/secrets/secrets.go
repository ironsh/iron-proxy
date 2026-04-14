// Package secrets implements a transform that swaps proxy tokens for real
// secrets on outbound requests, scoped to allowed hosts.
package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"text/template"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func init() {
	transform.Register("secrets", factory)
}

// secretsConfig is the YAML config structure.
type secretsConfig struct {
	Secrets []secretEntry `yaml:"secrets"`
}

type secretEntry struct {
	Source  yaml.Node              `yaml:"source"`
	Rules   []hostmatch.RuleConfig `yaml:"rules"`
	Inject  *injectConfig          `yaml:"inject,omitempty"`
	Replace *replaceConfig         `yaml:"replace,omitempty"`

	// Deprecated top-level fields for backwards compatibility.
	// Users should migrate to the replace block.
	ProxyValue   string   `yaml:"proxy_value,omitempty"`
	MatchHeaders []string `yaml:"match_headers,omitempty"`
	MatchBody    bool     `yaml:"match_body,omitempty"`
	Require      bool     `yaml:"require,omitempty"`
}

type replaceConfig struct {
	ProxyValue   string   `yaml:"proxy_value"`
	MatchHeaders []string `yaml:"match_headers,omitempty"`
	MatchBody    bool     `yaml:"match_body,omitempty"`
	Require      bool     `yaml:"require,omitempty"`
}

type injectConfig struct {
	Header     string `yaml:"header,omitempty"`
	QueryParam string `yaml:"query_param,omitempty"`
	Formatter  string `yaml:"formatter,omitempty"`
}

// resolvedSecret is a secret ready for use after config parsing and source resolution.
type resolvedSecret struct {
	name     string // source name, for logging/metrics
	mode     string // "replace" or "inject"
	getValue func(ctx context.Context) (string, error)
	rules    []hostmatch.Rule

	// replace mode fields
	proxyValue   string
	matchHeaders []string // empty = all headers
	matchBody    bool
	require      bool

	// inject mode fields
	injectHeader     string
	injectQueryParam string
	formatter        *template.Template // nil = identity (raw value)
}

// formatterData is the template context for inject formatters.
type formatterData struct {
	Value string
}

var formatterFuncs = template.FuncMap{
	"base64": func(parts ...string) string {
		return base64.StdEncoding.EncodeToString([]byte(strings.Join(parts, "")))
	},
}

// Secrets is the transform that swaps proxy tokens for real secrets.
type Secrets struct {
	secrets []resolvedSecret
}

func factory(cfg yaml.Node, logger *slog.Logger) (transform.Transformer, error) {
	var c secretsConfig
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing secrets config: %w", err)
	}
	registry := resolverRegistry{
		"env":    newEnvResolver(),
		"aws_sm": newAWSSMResolver(logger),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return newFromConfig(ctx, c, registry)
}

// newFromConfig creates a Secrets transform from a parsed config.
func newFromConfig(ctx context.Context, cfg secretsConfig, registry resolverRegistry) (*Secrets, error) {
	resolved := make([]resolvedSecret, 0, len(cfg.Secrets))

	for i, entry := range cfg.Secrets {
		// Normalize legacy top-level fields into a replace block.
		replace, inject, err := normalizeEntry(i, &entry)
		if err != nil {
			return nil, err
		}

		// Peek at source type to dispatch to the right resolver.
		var hint sourceTypeHint
		if err := entry.Source.Decode(&hint); err != nil {
			return nil, fmt.Errorf("secrets[%d]: parsing source type: %w", i, err)
		}
		if hint.Type == "" {
			return nil, fmt.Errorf("secrets[%d]: source.type is required", i)
		}

		resolver, ok := registry[hint.Type]
		if !ok {
			return nil, fmt.Errorf("secrets[%d]: unsupported source type %q", i, hint.Type)
		}

		result, err := resolver.Resolve(ctx, entry.Source)
		if err != nil {
			return nil, fmt.Errorf("secrets[%d]: %w", i, err)
		}

		rules, err := hostmatch.CompileRules(entry.Rules, hostmatch.NullResolver{}, fmt.Sprintf("secrets[%d]", i))
		if err != nil {
			return nil, err
		}

		if inject != nil {
			sec := resolvedSecret{
				name:             result.Name,
				mode:             "inject",
				getValue:         result.GetValue,
				rules:            rules,
				injectHeader:     inject.Header,
				injectQueryParam: inject.QueryParam,
			}
			if inject.Formatter != "" {
				tmpl, err := template.New(fmt.Sprintf("secrets[%d]", i)).Funcs(formatterFuncs).Parse(inject.Formatter)
				if err != nil {
					return nil, fmt.Errorf("secrets[%d]: parsing formatter template: %w", i, err)
				}
				sec.formatter = tmpl
			}
			resolved = append(resolved, sec)
		} else {
			resolved = append(resolved, resolvedSecret{
				name:         result.Name,
				mode:         "replace",
				proxyValue:   replace.ProxyValue,
				getValue:     result.GetValue,
				matchHeaders: replace.MatchHeaders,
				matchBody:    replace.MatchBody,
				require:      replace.Require,
				rules:        rules,
			})
		}
	}

	return &Secrets{secrets: resolved}, nil
}

// normalizeEntry validates the entry and returns either a replaceConfig or injectConfig.
// It handles legacy top-level fields by normalizing them into a replaceConfig.
func normalizeEntry(i int, entry *secretEntry) (*replaceConfig, *injectConfig, error) {
	hasLegacy := entry.ProxyValue != "" || len(entry.MatchHeaders) > 0 || entry.MatchBody || entry.Require
	hasReplace := entry.Replace != nil
	hasInject := entry.Inject != nil

	// Count how many modes are specified.
	modeCount := 0
	if hasLegacy {
		modeCount++
	}
	if hasReplace {
		modeCount++
	}
	if hasInject {
		modeCount++
	}

	if modeCount == 0 {
		return nil, nil, fmt.Errorf("secrets[%d]: must specify either inject or replace", i)
	}
	if modeCount > 1 {
		if hasLegacy && hasReplace {
			return nil, nil, fmt.Errorf("secrets[%d]: cannot use both top-level proxy_value/match_headers and replace block", i)
		}
		if hasLegacy && hasInject {
			return nil, nil, fmt.Errorf("secrets[%d]: cannot use both top-level proxy_value/match_headers and inject block", i)
		}
		return nil, nil, fmt.Errorf("secrets[%d]: cannot specify both inject and replace", i)
	}

	if hasInject {
		if err := validateInject(i, entry.Inject); err != nil {
			return nil, nil, err
		}
		return nil, entry.Inject, nil
	}

	if hasReplace {
		if entry.Replace.ProxyValue == "" {
			return nil, nil, fmt.Errorf("secrets[%d]: replace.proxy_value is required", i)
		}
		return entry.Replace, nil, nil
	}

	// Legacy top-level fields: normalize into replaceConfig.
	if entry.ProxyValue == "" {
		return nil, nil, fmt.Errorf("secrets[%d]: proxy_value is required", i)
	}
	return &replaceConfig{
		ProxyValue:   entry.ProxyValue,
		MatchHeaders: entry.MatchHeaders,
		MatchBody:    entry.MatchBody,
		Require:      entry.Require,
	}, nil, nil
}

func validateInject(i int, cfg *injectConfig) error {
	hasHeader := cfg.Header != ""
	hasQuery := cfg.QueryParam != ""

	if !hasHeader && !hasQuery {
		return fmt.Errorf("secrets[%d]: inject must specify either header or query_param", i)
	}
	if hasHeader && hasQuery {
		return fmt.Errorf("secrets[%d]: inject cannot specify both header and query_param", i)
	}
	return nil
}

func (s *Secrets) Name() string { return "secrets" }

func (s *Secrets) TransformRequest(ctx context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	type secretRecord struct {
		Secret    string   `json:"secret"`
		Locations []string `json:"locations"`
	}
	var swapped, injected []secretRecord

	for _, sec := range s.secrets {
		if !hostmatch.MatchAnyRule(ctx, sec.rules, req) {
			continue
		}

		realValue, err := sec.getValue(ctx)
		if err != nil {
			return nil, fmt.Errorf("resolving secret %q: %w", sec.name, err)
		}

		if sec.mode == "inject" {
			locations, err := s.injectSecret(req, &sec, realValue)
			if err != nil {
				return nil, fmt.Errorf("injecting secret %q: %w", sec.name, err)
			}
			if len(locations) > 0 {
				injected = append(injected, secretRecord{Secret: sec.name, Locations: locations})
			}
			continue
		}

		var locations []string
		locations = append(locations, s.swapHeaders(req, &sec, realValue)...)
		locations = append(locations, s.swapQuery(req, &sec, realValue)...)

		if sec.matchBody {
			if loc := s.swapBody(req, &sec, realValue); loc != "" {
				locations = append(locations, loc)
			}
		}

		if len(locations) > 0 {
			swapped = append(swapped, secretRecord{Secret: sec.name, Locations: locations})
		} else if sec.require {
			tctx.Annotate("rejected", sec.name)
			return &transform.TransformResult{Action: transform.ActionReject}, nil
		}
	}

	if len(swapped) > 0 {
		tctx.Annotate("swapped", swapped)
	}
	if len(injected) > 0 {
		tctx.Annotate("injected", injected)
	}

	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (s *Secrets) injectSecret(req *http.Request, sec *resolvedSecret, realValue string) ([]string, error) {
	formatted, err := s.formatValue(sec, realValue)
	if err != nil {
		return nil, err
	}

	var locations []string
	if sec.injectHeader != "" {
		req.Header.Set(sec.injectHeader, formatted)
		locations = append(locations, "header:"+sec.injectHeader)
	}
	if sec.injectQueryParam != "" {
		q := req.URL.Query()
		q.Set(sec.injectQueryParam, formatted)
		req.URL.RawQuery = q.Encode()
		locations = append(locations, "query:"+sec.injectQueryParam)
	}
	return locations, nil
}

func (s *Secrets) formatValue(sec *resolvedSecret, realValue string) (string, error) {
	if sec.formatter == nil {
		return realValue, nil
	}
	var buf strings.Builder
	if err := sec.formatter.Execute(&buf, formatterData{Value: realValue}); err != nil {
		return "", fmt.Errorf("executing formatter: %w", err)
	}
	return buf.String(), nil
}

func (s *Secrets) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (s *Secrets) swapHeaders(req *http.Request, sec *resolvedSecret, realValue string) []string {
	var locations []string
	if len(sec.matchHeaders) > 0 {
		for _, name := range sec.matchHeaders {
			if vals := req.Header.Values(name); len(vals) > 0 {
				for _, v := range vals {
					if headerContains(name, v, sec.proxyValue) {
						locations = append(locations, "header:"+name)
						break
					}
				}
				req.Header.Del(name)
				for _, v := range vals {
					req.Header.Add(name, replaceInHeader(name, v, sec.proxyValue, realValue))
				}
			}
		}
	} else {
		for name, vals := range req.Header {
			for i, v := range vals {
				if headerContains(name, v, sec.proxyValue) {
					req.Header[name][i] = replaceInHeader(name, v, sec.proxyValue, realValue)
					locations = append(locations, "header:"+name)
				}
			}
		}
	}
	return locations
}

// replaceInHeader performs a secret replacement in a header value. For
// Authorization headers with HTTP Basic auth, the base64 payload is decoded
// before replacement and re-encoded after.
func replaceInHeader(headerName, value, proxyValue, realValue string) string {
	if strings.EqualFold(headerName, "Authorization") {
		if decoded, ok := decodeBasicAuth(value); ok {
			replaced := strings.ReplaceAll(decoded, proxyValue, realValue)
			return "Basic " + base64.StdEncoding.EncodeToString([]byte(replaced))
		}
	}
	return strings.ReplaceAll(value, proxyValue, realValue)
}

// headerContains checks whether a header value contains the proxy token.
// For Authorization headers with HTTP Basic auth, the base64 payload is
// decoded before checking.
func headerContains(headerName, value, proxyValue string) bool {
	if strings.EqualFold(headerName, "Authorization") {
		if decoded, ok := decodeBasicAuth(value); ok {
			return strings.Contains(decoded, proxyValue)
		}
	}
	return strings.Contains(value, proxyValue)
}

// decodeBasicAuth extracts and base64-decodes the payload from a "Basic ..."
// Authorization header value. Returns the decoded string and true on success.
func decodeBasicAuth(value string) (string, bool) {
	after, ok := strings.CutPrefix(value, "Basic ")
	if !ok {
		return "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(after)
	if err != nil {
		return "", false
	}
	return string(decoded), true
}

func (s *Secrets) swapQuery(req *http.Request, sec *resolvedSecret, realValue string) []string {
	raw := req.URL.RawQuery
	if raw == "" || !strings.Contains(raw, sec.proxyValue) {
		return nil
	}

	params, err := url.ParseQuery(raw)
	if err != nil {
		return nil
	}

	var locations []string
	for key, vals := range params {
		for i, v := range vals {
			if strings.Contains(v, sec.proxyValue) {
				params[key][i] = strings.ReplaceAll(v, sec.proxyValue, realValue)
				locations = append(locations, "query:"+key)
			}
		}
	}

	if len(locations) > 0 {
		req.URL.RawQuery = params.Encode()
	}
	return locations
}

func (s *Secrets) swapBody(req *http.Request, sec *resolvedSecret, realValue string) string {
	if req.Body == nil {
		return ""
	}

	data, err := io.ReadAll(req.Body)
	if err != nil {
		return ""
	}

	if !bytes.Contains(data, []byte(sec.proxyValue)) {
		return ""
	}

	replaced := bytes.ReplaceAll(data, []byte(sec.proxyValue), []byte(realValue))
	req.Body = transform.NewBufferedBodyFromBytes(replaced)
	return "body"
}
