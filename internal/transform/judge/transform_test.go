package judge

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/judge/llm"
)

// fakeAdapter is an llm.Adapter stub whose behavior is controlled by fields.
type fakeAdapter struct {
	model    string
	raw      string
	err      error
	delay    time.Duration
	inTokens int
	outToks  int

	calls atomic.Int64
}

func (f *fakeAdapter) Name() string  { return "fake" }
func (f *fakeAdapter) Model() string { return f.model }

func (f *fakeAdapter) Complete(ctx context.Context, _ llm.Request) (llm.Response, error) {
	f.calls.Add(1)
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return llm.Response{}, ctx.Err()
		}
	}
	if f.err != nil {
		return llm.Response{}, f.err
	}
	return llm.Response{
		RawOutput:    f.raw,
		Model:        f.model,
		InputTokens:  f.inTokens,
		OutputTokens: f.outToks,
	}, nil
}

// panicAdapter fails the test if Complete is ever called.
type panicAdapter struct{ t *testing.T }

func (p *panicAdapter) Name() string  { return "panic" }
func (p *panicAdapter) Model() string { return "panic-model" }
func (p *panicAdapter) Complete(_ context.Context, _ llm.Request) (llm.Response, error) {
	p.t.Fatalf("panicAdapter.Complete should not be called")
	return llm.Response{}, nil
}

func makeJudge(t *testing.T, adapter llm.Adapter, overrides func(*judgeConfig)) *Judge {
	t.Helper()
	cfg := judgeConfig{
		Name:     "test-judge",
		Prompt:   "Allow only GET requests.",
		Fallback: "deny",
		Timeout:  500 * time.Millisecond,
		Rules: []hostmatch.RuleConfig{
			{Host: "example.com"},
		},
	}
	if overrides != nil {
		overrides(&cfg)
	}
	rules, err := hostmatch.CompileRules(cfg.Rules, hostmatch.NullResolver{}, "test")
	require.NoError(t, err)
	j, err := newFromConfig(cfg, adapter, rules, slog.Default())
	require.NoError(t, err)
	return j
}

func makeRequest(method, host, path string, body string) *http.Request {
	r := httptest.NewRequest(method, "http://"+host+path, strings.NewReader(body))
	r.Body = transform.NewBufferedBodyFromBytes([]byte(body))
	r.Host = host
	return r
}

func runRequest(t *testing.T, j *Judge, req *http.Request) (map[string]any, *transform.TransformResult, error) {
	t.Helper()
	tctx := &transform.TransformContext{}
	res, err := j.TransformRequest(context.Background(), tctx, req)
	return tctx.DrainAnnotations(), res, err
}

func TestJudge_NonMatchingRuleSkipsLLM(t *testing.T) {
	adapter := &panicAdapter{t: t}
	j := makeJudge(t, adapter, nil)

	ann, res, err := runRequest(t, j, makeRequest("GET", "other.com", "/", ""))
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Empty(t, ann, "no annotations should be emitted on non-match")
}

func TestJudge_AllowDecision(t *testing.T) {
	adapter := &fakeAdapter{
		model:    "test-model",
		raw:      `{"decision":"ALLOW","reason":"GET is fine"}`,
		inTokens: 100,
		outToks:  25,
	}
	j := makeJudge(t, adapter, nil)

	ann, res, err := runRequest(t, j, makeRequest("GET", "example.com", "/resource", ""))
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "ALLOW", ann["judge.decision"])
	require.Equal(t, "GET is fine", ann["judge.reason"])
	require.Equal(t, "test-judge", ann["judge.instance"])
	require.Equal(t, "test-model", ann["judge.model"])
	require.Equal(t, 100, ann["judge.input_tokens"])
	require.Equal(t, 25, ann["judge.output_tokens"])
	require.NotNil(t, ann["judge.duration_ms"])
	require.Equal(t, int64(1), adapter.calls.Load())
}

func TestJudge_DenyDecision(t *testing.T) {
	adapter := &fakeAdapter{
		model: "test-model",
		raw:   `{"decision":"DENY","reason":"writes not allowed"}`,
	}
	j := makeJudge(t, adapter, nil)

	ann, res, err := runRequest(t, j, makeRequest("POST", "example.com", "/resource", "body"))
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)
	require.Equal(t, "DENY", ann["judge.decision"])
}

func TestJudge_FallbackDenyOnAdapterError(t *testing.T) {
	adapter := &fakeAdapter{err: errors.New("upstream exploded"), model: "m"}
	j := makeJudge(t, adapter, nil)

	ann, res, err := runRequest(t, j, makeRequest("GET", "example.com", "/", ""))
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)
	require.Equal(t, "deny", ann["judge.fallback_applied"])
	require.Equal(t, "FALLBACK_DENY", ann["judge.decision"])
	require.Contains(t, ann["judge.reason"], "upstream exploded")
}

func TestJudge_FallbackSkipOnAdapterError(t *testing.T) {
	adapter := &fakeAdapter{err: errors.New("upstream exploded"), model: "m"}
	j := makeJudge(t, adapter, func(c *judgeConfig) { c.Fallback = "skip" })

	ann, res, err := runRequest(t, j, makeRequest("GET", "example.com", "/", ""))
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "skip", ann["judge.fallback_applied"])
	require.Equal(t, "FALLBACK_ALLOW", ann["judge.decision"])
}

func TestJudge_FallbackOnTimeout(t *testing.T) {
	adapter := &fakeAdapter{delay: 200 * time.Millisecond, model: "m"}
	j := makeJudge(t, adapter, func(c *judgeConfig) { c.Timeout = 20 * time.Millisecond })

	ann, res, err := runRequest(t, j, makeRequest("GET", "example.com", "/", ""))
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action, "deny fallback should reject on timeout")
	require.Equal(t, "deny", ann["judge.fallback_applied"])
}

func TestJudge_MalformedDecisionIsError(t *testing.T) {
	adapter := &fakeAdapter{raw: "this is not json", model: "m"}
	j := makeJudge(t, adapter, nil)

	ann, res, err := runRequest(t, j, makeRequest("GET", "example.com", "/", ""))
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)
	require.Equal(t, "this is not json", ann["judge.raw_output"])
	require.Equal(t, "deny", ann["judge.fallback_applied"])
}

func TestJudge_CircuitBreakerOpenShortCircuits(t *testing.T) {
	adapter := &fakeAdapter{err: errors.New("boom"), model: "m"}
	j := makeJudge(t, adapter, func(c *judgeConfig) {
		c.CircuitBreaker.ConsecutiveFailures = 3
		c.CircuitBreaker.Cooldown = time.Hour
	})

	// Trip the breaker with 3 failures.
	for i := 0; i < 3; i++ {
		_, _, err := runRequest(t, j, makeRequest("GET", "example.com", "/", ""))
		require.NoError(t, err)
	}
	require.Equal(t, int64(3), adapter.calls.Load())

	// Next call must not reach the adapter.
	ann, res, err := runRequest(t, j, makeRequest("GET", "example.com", "/", ""))
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)
	require.Equal(t, int64(3), adapter.calls.Load(), "adapter should not be invoked when breaker is open")
	require.Equal(t, true, ann["judge.circuit_breaker_tripped"])
	require.Equal(t, "deny", ann["judge.fallback_applied"])
}

func TestJudge_TwoInstancesIndependent(t *testing.T) {
	adapterA := &fakeAdapter{raw: `{"decision":"ALLOW","reason":"a"}`, model: "A"}
	adapterB := &fakeAdapter{raw: `{"decision":"ALLOW","reason":"b"}`, model: "B"}

	jA := makeJudge(t, adapterA, func(c *judgeConfig) {
		c.Name = "judgeA"
		c.Rules = []hostmatch.RuleConfig{{Host: "a.com"}}
	})
	jB := makeJudge(t, adapterB, func(c *judgeConfig) {
		c.Name = "judgeB"
		c.Rules = []hostmatch.RuleConfig{{Host: "b.com"}}
	})

	_, _, err := runRequest(t, jA, makeRequest("GET", "a.com", "/", ""))
	require.NoError(t, err)
	require.Equal(t, int64(1), adapterA.calls.Load())
	require.Equal(t, int64(0), adapterB.calls.Load(), "unrelated instance must not be invoked")

	_, _, err = runRequest(t, jB, makeRequest("GET", "b.com", "/", ""))
	require.NoError(t, err)
	require.Equal(t, int64(1), adapterA.calls.Load())
	require.Equal(t, int64(1), adapterB.calls.Load())
}

func TestJudge_TwoInstancesBreakerIndependent(t *testing.T) {
	failing := &fakeAdapter{err: errors.New("nope"), model: "A"}
	healthy := &fakeAdapter{raw: `{"decision":"ALLOW","reason":"ok"}`, model: "B"}

	jA := makeJudge(t, failing, func(c *judgeConfig) {
		c.Name = "judgeA"
		c.Rules = []hostmatch.RuleConfig{{Host: "a.com"}}
		c.CircuitBreaker.ConsecutiveFailures = 2
		c.CircuitBreaker.Cooldown = time.Hour
	})
	jB := makeJudge(t, healthy, func(c *judgeConfig) {
		c.Name = "judgeB"
		c.Rules = []hostmatch.RuleConfig{{Host: "b.com"}}
	})

	// Trip jA's breaker.
	for i := 0; i < 2; i++ {
		_, _, err := runRequest(t, jA, makeRequest("GET", "a.com", "/", ""))
		require.NoError(t, err)
	}

	// jB still healthy.
	_, res, err := runRequest(t, jB, makeRequest("GET", "b.com", "/", ""))
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
}

func TestJudge_ResponseIsNoop(t *testing.T) {
	adapter := &fakeAdapter{raw: `{"decision":"ALLOW","reason":"x"}`}
	j := makeJudge(t, adapter, nil)
	req := makeRequest("GET", "example.com", "/", "")
	resp := &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(""))}
	res, err := j.TransformResponse(context.Background(), &transform.TransformContext{}, req, resp)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
}

func TestJudge_Name(t *testing.T) {
	adapter := &fakeAdapter{raw: `{"decision":"ALLOW","reason":"x"}`}
	j := makeJudge(t, adapter, nil)
	require.Equal(t, "test-judge", j.Name())
}

func TestJudge_ConfigValidation(t *testing.T) {
	// These tests go through newFromConfig to bypass the yaml.Node plumbing.
	rules, err := hostmatch.CompileRules([]hostmatch.RuleConfig{{Host: "x"}}, hostmatch.NullResolver{}, "test")
	require.NoError(t, err)

	_, err = newFromConfig(judgeConfig{Name: "j", Prompt: "p", Fallback: "maybe"}, &fakeAdapter{}, rules, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid fallback")
}

func TestJudge_Factory_MissingName(t *testing.T) {
	f, err := transform.Lookup("judge")
	require.NoError(t, err)

	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(`prompt: "p"
rules:
  - host: "example.com"
provider:
  type: anthropic`), &node))
	_, err = f(*node.Content[0], slog.Default())
	require.Error(t, err)
	require.Contains(t, err.Error(), "name is required")
}

func TestJudge_Factory_MissingPrompt(t *testing.T) {
	f, err := transform.Lookup("judge")
	require.NoError(t, err)

	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(`name: "j"
rules:
  - host: "example.com"
provider:
  type: anthropic`), &node))
	_, err = f(*node.Content[0], slog.Default())
	require.Error(t, err)
	require.Contains(t, err.Error(), "prompt is required")
}

func TestJudge_Factory_MissingRules(t *testing.T) {
	f, err := transform.Lookup("judge")
	require.NoError(t, err)

	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(`name: "j"
prompt: "p"
provider:
  type: anthropic`), &node))
	_, err = f(*node.Content[0], slog.Default())
	require.Error(t, err)
	require.Contains(t, err.Error(), "at least one rule is required")
}

func TestJudge_Factory_MissingProviderType(t *testing.T) {
	f, err := transform.Lookup("judge")
	require.NoError(t, err)

	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(`name: "j"
prompt: "p"
rules:
  - host: "example.com"
provider:
  model: claude-test`), &node))
	_, err = f(*node.Content[0], slog.Default())
	require.Error(t, err)
	require.Contains(t, err.Error(), "type is required")
}

func TestJudge_Factory_ValidConfig(t *testing.T) {
	t.Setenv("JUDGE_TEST_KEY", "sk-test")

	f, err := transform.Lookup("judge")
	require.NoError(t, err)

	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(`name: "my-judge"
prompt: "allow only GET"
fallback: deny
rules:
  - host: "example.com"
provider:
  type: anthropic
  model: claude-haiku-4-5-20251001
  api_key_env: JUDGE_TEST_KEY`), &node))

	tr, err := f(*node.Content[0], slog.Default())
	require.NoError(t, err)
	require.Equal(t, "my-judge", tr.Name())
}
