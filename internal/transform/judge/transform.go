// Package judge implements an LLM-backed allow/deny transform. Each instance
// is scoped to its own URL rules, carries its own natural-language policy, and
// has independent circuit breaker and semaphore state.
package judge

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/judge/llm"
)

func init() {
	transform.Register("judge", factory)
}

const (
	defaultMaxConcurrent = 100
	defaultTimeout       = 8 * time.Second
)

type fallbackMode int

const (
	fallbackDeny fallbackMode = iota
	fallbackSkip
)

const (
	decisionAllow         = "ALLOW"
	decisionDeny          = "DENY"
	decisionFallbackAllow = "FALLBACK_ALLOW"
	decisionFallbackDeny  = "FALLBACK_DENY"

	fallbackNameDeny = "deny"
	fallbackNameSkip = "skip"
)

// judgeConfig is the YAML shape of a single judge transform instance.
type judgeConfig struct {
	Name           string                 `yaml:"name"`
	Prompt         string                 `yaml:"prompt"`
	Fallback       string                 `yaml:"fallback"`
	MaxConcurrent  int                    `yaml:"max_concurrent"`
	Timeout        time.Duration          `yaml:"timeout"`
	CircuitBreaker breakerConfig          `yaml:"circuit_breaker"`
	Rules          []hostmatch.RuleConfig `yaml:"rules"`
	Provider       yaml.Node              `yaml:"provider"`
}

type providerTypeProbe struct {
	Type string `yaml:"type"`
}

// Judge is one instance of the LLM-backed allow/deny transform.
type Judge struct {
	name     string
	prompt   string
	fallback fallbackMode
	timeout  time.Duration
	rules    []hostmatch.Rule
	adapter  llm.Adapter
	breaker  *circuitBreaker
	sem      chan struct{}
	logger   *slog.Logger
}

func factory(cfg yaml.Node, logger *slog.Logger) (transform.Transformer, error) {
	var c judgeConfig
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing judge config: %w", err)
	}
	if c.Name == "" {
		return nil, fmt.Errorf("judge transform: name is required")
	}
	if c.Prompt == "" {
		return nil, fmt.Errorf("judge transform %q: prompt is required", c.Name)
	}
	if len(c.Rules) == 0 {
		return nil, fmt.Errorf("judge transform %q: at least one rule is required", c.Name)
	}
	if _, err := parseFallback(c.Fallback); err != nil {
		return nil, fmt.Errorf("judge transform %q: %w", c.Name, err)
	}

	var probe providerTypeProbe
	if err := c.Provider.Decode(&probe); err != nil {
		return nil, fmt.Errorf("judge transform %q: parsing provider: %w", c.Name, err)
	}

	adapter, err := llm.NewAdapter(probe.Type, c.Provider, logger)
	if err != nil {
		return nil, fmt.Errorf("judge transform %q: %w", c.Name, err)
	}

	rules, err := hostmatch.CompileRules(c.Rules, hostmatch.DefaultResolver(), fmt.Sprintf("judge transform %q", c.Name))
	if err != nil {
		return nil, err
	}

	return newFromConfig(c, adapter, rules, logger)
}

func parseFallback(s string) (fallbackMode, error) {
	switch s {
	case "", "deny":
		return fallbackDeny, nil
	case "skip":
		return fallbackSkip, nil
	default:
		return 0, fmt.Errorf("invalid fallback %q: must be \"deny\" or \"skip\"", s)
	}
}

// newFromConfig is the unexported constructor used by tests with a fake
// adapter and pre-compiled rules.
func newFromConfig(c judgeConfig, adapter llm.Adapter, rules []hostmatch.Rule, logger *slog.Logger) (*Judge, error) {
	fb, err := parseFallback(c.Fallback)
	if err != nil {
		return nil, fmt.Errorf("judge transform %q: %w", c.Name, err)
	}
	maxConc := c.MaxConcurrent
	if maxConc <= 0 {
		maxConc = defaultMaxConcurrent
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Judge{
		name:     c.Name,
		prompt:   c.Prompt,
		fallback: fb,
		timeout:  timeout,
		rules:    rules,
		adapter:  adapter,
		breaker:  newCircuitBreaker(c.CircuitBreaker),
		sem:      make(chan struct{}, maxConc),
		logger:   logger,
	}, nil
}

func (j *Judge) Name() string { return j.name }

// Close releases adapter-held resources when the pipeline is swapped. Matches
// the grpc transform pattern so managed-mode hot reload is safe when an
// adapter grows non-trivial state in the future.
func (j *Judge) Close() error {
	if c, ok := j.adapter.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func (j *Judge) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

// TransformRequest runs the judge over a request. See the package doc-style
// comment on the judge transform for the full control-flow description.
func (j *Judge) TransformRequest(ctx context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	if !hostmatch.MatchAnyRule(ctx, j.rules, req) {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}

	ann := &annotator{tctx: tctx, start: time.Now()}
	ann.set("judge.instance", j.name)
	ann.set("judge.model", j.adapter.Model())

	permit, ok := j.breaker.allow()
	if !ok {
		ann.set("judge.circuit_breaker_tripped", true)
		ann.emitFallback(j.fallback, "circuit breaker open")
		return j.applyFallback(), nil
	}

	select {
	case j.sem <- struct{}{}:
	case <-ctx.Done():
		permit(false)
		ann.emitDuration()
		return nil, ctx.Err()
	}
	defer func() { <-j.sem }()

	body, bodyTruncated, err := readCappedBody(req)
	if err != nil {
		permit(false)
		ann.emitFallback(j.fallback, "reading request body: "+err.Error())
		return j.applyFallback(), nil
	}

	envelope, err := buildEnvelope(req, body, bodyTruncated)
	if err != nil {
		permit(false)
		ann.emitFallback(j.fallback, "building envelope: "+err.Error())
		return j.applyFallback(), nil
	}

	callCtx, cancel := context.WithTimeout(ctx, j.timeout)
	defer cancel()

	resp, err := j.adapter.Complete(callCtx, llm.Request{
		SystemPrompt: buildSystemPrompt(j.prompt),
		UserContent:  string(envelope),
	})
	if err != nil {
		permit(false)
		j.logger.Warn("judge adapter error", "instance", j.name, "err", err)
		ann.emitFallback(j.fallback, "adapter error: "+err.Error())
		return j.applyFallback(), nil
	}

	ann.set("judge.input_tokens", resp.InputTokens)
	ann.set("judge.output_tokens", resp.OutputTokens)
	if resp.Model != "" {
		ann.set("judge.model", resp.Model)
	}

	decision, err := parseDecision(resp.RawOutput)
	if err != nil {
		permit(false)
		ann.set("judge.raw_output", capRawOutput(resp.RawOutput))
		ann.emitFallback(j.fallback, "parsing decision: "+err.Error())
		return j.applyFallback(), nil
	}

	permit(true)
	ann.set("judge.decision", decision.Decision)
	ann.set("judge.reason", capReason(decision.Reason))
	ann.emitDuration()

	if decision.Decision == decisionDeny {
		return &transform.TransformResult{Action: transform.ActionReject}, nil
	}
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (j *Judge) applyFallback() *transform.TransformResult {
	if j.fallback == fallbackDeny {
		return &transform.TransformResult{Action: transform.ActionReject}
	}
	return &transform.TransformResult{Action: transform.ActionContinue}
}

// readCappedBody reads up to MaxBodyBytes+1 from the buffered request body so
// the caller can detect overflow. The pipeline rewinds the body between
// transforms; this call does not need to Reset.
func readCappedBody(req *http.Request) ([]byte, bool, error) {
	if req.Body == nil {
		return nil, false, nil
	}
	data, err := io.ReadAll(io.LimitReader(req.Body, int64(MaxBodyBytes)+1))
	if err != nil {
		return nil, false, err
	}
	if len(data) > MaxBodyBytes {
		return data[:MaxBodyBytes], true, nil
	}
	return data, false, nil
}

// capRawOutput bounds audit log output to 2KB per spec.
func capRawOutput(s string) string {
	const max = 2048
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// capReason bounds the reason field to 512 chars per spec.
func capReason(s string) string {
	const max = 512
	if len(s) <= max {
		return s
	}
	return s[:max]
}

// annotator centralizes the audit-annotation writes. The pipeline drains
// annotations after TransformRequest returns, so callers must set every key
// before returning (no deferred writes).
type annotator struct {
	tctx  *transform.TransformContext
	start time.Time
}

func (a *annotator) set(key string, value any) {
	a.tctx.Annotate(key, value)
}

func (a *annotator) emitDuration() {
	ms := float64(time.Since(a.start).Microseconds()) / 1000.0
	a.tctx.Annotate("judge.duration_ms", ms)
}

func (a *annotator) emitFallback(mode fallbackMode, reason string) {
	a.set("judge.fallback_applied", fallbackString(mode))
	a.set("judge.decision", fallbackDecisionString(mode))
	a.set("judge.reason", capReason(reason))
	a.emitDuration()
}

func fallbackString(m fallbackMode) string {
	if m == fallbackDeny {
		return fallbackNameDeny
	}
	return fallbackNameSkip
}

func fallbackDecisionString(m fallbackMode) string {
	if m == fallbackDeny {
		return decisionFallbackDeny
	}
	return decisionFallbackAllow
}
