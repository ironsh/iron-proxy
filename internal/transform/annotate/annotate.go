// Package annotate implements a transform that captures HTTP request headers
// into audit log annotations based on configurable host/method/path rules.
package annotate

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func init() {
	transform.Register("annotate", factory)
}

type annotateConfig struct {
	Annotations []annotationGroup `yaml:"annotations"`
}

type annotationGroup struct {
	Rules   []hostmatch.RuleConfig `yaml:"rules"`
	Headers []string               `yaml:"headers"`
}

type compiledGroup struct {
	rules   []hostmatch.Rule
	headers []string // canonical form
}

// Annotate captures request header values into audit annotations when
// requests match configured rules.
type Annotate struct {
	groups []compiledGroup
}

func factory(cfg yaml.Node, _ *slog.Logger) (transform.Transformer, error) {
	var c annotateConfig
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing annotate config: %w", err)
	}
	return newFromConfig(c, hostmatch.NullResolver{})
}

func newFromConfig(cfg annotateConfig, resolver hostmatch.Resolver) (*Annotate, error) {
	if len(cfg.Annotations) == 0 {
		return nil, fmt.Errorf("annotate: at least one annotation group is required")
	}

	groups := make([]compiledGroup, 0, len(cfg.Annotations))
	for i, ag := range cfg.Annotations {
		if len(ag.Rules) == 0 {
			return nil, fmt.Errorf("annotate: annotations[%d]: at least one rule is required", i)
		}
		if len(ag.Headers) == 0 {
			return nil, fmt.Errorf("annotate: annotations[%d]: at least one header is required", i)
		}

		compiled, err := hostmatch.CompileRules(ag.Rules, resolver, fmt.Sprintf("annotate annotations[%d]", i))
		if err != nil {
			return nil, err
		}

		headers := make([]string, len(ag.Headers))
		for j, h := range ag.Headers {
			headers[j] = http.CanonicalHeaderKey(h)
		}

		groups = append(groups, compiledGroup{rules: compiled, headers: headers})
	}

	return &Annotate{groups: groups}, nil
}

func (a *Annotate) Name() string { return "annotate" }

func (a *Annotate) TransformRequest(ctx context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	for _, g := range a.groups {
		if !hostmatch.MatchAnyRule(ctx, g.rules, req) {
			continue
		}
		for _, h := range g.headers {
			if v := req.Header.Get(h); v != "" {
				tctx.Annotate("header:"+h, v)
			}
		}
	}
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (a *Annotate) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}
