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
	Source       yaml.Node              `yaml:"source"`
	ProxyValue   string                 `yaml:"proxy_value"`
	MatchHeaders []string               `yaml:"match_headers"`
	MatchBody    bool                   `yaml:"match_body"`
	Require      bool                   `yaml:"require"`
	Rules        []hostmatch.RuleConfig `yaml:"rules"`
}

// resolvedSecret is a secret ready for use after config parsing and source resolution.
type resolvedSecret struct {
	name         string // source name, for logging/metrics
	proxyValue   string
	getValue     func(ctx context.Context) (string, error)
	matchHeaders []string // empty = all headers
	matchBody    bool
	require      bool
	rules        []hostmatch.Rule
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
		if entry.ProxyValue == "" {
			return nil, fmt.Errorf("secrets[%d]: proxy_value is required", i)
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

		resolved = append(resolved, resolvedSecret{
			name:         result.Name,
			proxyValue:   entry.ProxyValue,
			getValue:     result.GetValue,
			matchHeaders: entry.MatchHeaders,
			matchBody:    entry.MatchBody,
			require:      entry.Require,
			rules:        rules,
		})
	}

	return &Secrets{secrets: resolved}, nil
}

func (s *Secrets) Name() string { return "secrets" }

func (s *Secrets) TransformRequest(ctx context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	type swapRecord struct {
		Secret    string   `json:"secret"`
		Locations []string `json:"locations"`
	}
	var swapped []swapRecord

	for _, sec := range s.secrets {
		if !hostmatch.MatchAnyRule(ctx, sec.rules, req) {
			continue
		}

		realValue, err := sec.getValue(ctx)
		if err != nil {
			return nil, fmt.Errorf("resolving secret %q: %w", sec.name, err)
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
			swapped = append(swapped, swapRecord{Secret: sec.name, Locations: locations})
		} else if sec.require {
			tctx.Annotate("rejected", sec.name)
			return &transform.TransformResult{Action: transform.ActionReject}, nil
		}
	}

	if len(swapped) > 0 {
		tctx.Annotate("swapped", swapped)
	}

	return &transform.TransformResult{Action: transform.ActionContinue}, nil
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
