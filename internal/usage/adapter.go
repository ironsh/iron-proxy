package usage

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"strings"
)

const maxParseBytes = 1 << 20

type adapter interface {
	Provider() string
	Matches(host, path string) bool
	NewParser(req *http.Request) parser
}

type parser interface {
	FeedRequest([]byte)
	FeedResponse([]byte)
	Finalize() parsed
}

type parsed struct {
	Model                    string
	InputTokens              *int64
	OutputTokens             *int64
	CacheCreationInputTokens *int64
	CacheReadInputTokens     *int64
	UnavailableReason        string
}

func defaultAdapters() []adapter {
	return []adapter{
		anthropicAdapter{},
		openAIAdapter{},
	}
}

type anthropicAdapter struct{}

func (anthropicAdapter) Provider() string { return "anthropic" }

func (anthropicAdapter) Matches(host, path string) bool {
	return hostOnly(host) == "api.anthropic.com" && strings.HasPrefix(path, "/v1/")
}

func (a anthropicAdapter) NewParser(req *http.Request) parser {
	return newJSONUsageParser(a.Provider())
}

type openAIAdapter struct{}

func (openAIAdapter) Provider() string { return "openai" }

func (openAIAdapter) Matches(host, path string) bool {
	return hostOnly(host) == "api.openai.com" && strings.HasPrefix(path, "/v1/")
}

func (a openAIAdapter) NewParser(req *http.Request) parser {
	return newJSONUsageParser(a.Provider())
}

type jsonUsageParser struct {
	provider string

	request  boundedBuffer
	response boundedBuffer

	line []byte
	seen bool
	out  parsed
}

func newJSONUsageParser(provider string) *jsonUsageParser {
	return &jsonUsageParser{provider: provider}
}

func (p *jsonUsageParser) FeedRequest(chunk []byte) {
	p.request.Write(chunk)
}

func (p *jsonUsageParser) FeedResponse(chunk []byte) {
	p.response.Write(chunk)
	p.feedSSE(chunk)
}

func (p *jsonUsageParser) Finalize() parsed {
	if p.out.Model == "" {
		p.out.Model = modelFromJSON(p.request.Bytes())
	}
	if !p.seen && !p.response.Truncated() {
		p.parseResponseObject(p.response.Bytes())
	}
	if !hasUsage(p.out) {
		if p.response.Truncated() {
			p.out.UnavailableReason = "response_too_large"
		} else if p.out.UnavailableReason == "" {
			p.out.UnavailableReason = "usage_unavailable"
		}
	}
	return p.out
}

func (p *jsonUsageParser) feedSSE(chunk []byte) {
	for _, b := range chunk {
		if b == '\n' {
			p.parseSSELine(bytes.TrimSpace(p.line))
			p.line = p.line[:0]
			continue
		}
		if len(p.line) < maxParseBytes {
			p.line = append(p.line, b)
		}
	}
}

func (p *jsonUsageParser) parseSSELine(line []byte) {
	line = bytes.TrimPrefix(line, []byte("data:"))
	line = bytes.TrimSpace(line)
	if len(line) == 0 || bytes.Equal(line, []byte("[DONE]")) {
		return
	}
	p.parseResponseObject(line)
}

func (p *jsonUsageParser) parseResponseObject(data []byte) {
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		return
	}
	p.applyObject(obj)
}

func (p *jsonUsageParser) applyObject(obj map[string]any) {
	if p.out.Model == "" {
		if model, _ := obj["model"].(string); model != "" {
			p.out.Model = model
		}
	}

	if usageObj, _ := obj["usage"].(map[string]any); usageObj != nil {
		p.applyUsage(usageObj)
	}

	if msg, _ := obj["message"].(map[string]any); msg != nil {
		if p.out.Model == "" {
			if model, _ := msg["model"].(string); model != "" {
				p.out.Model = model
			}
		}
		if usageObj, _ := msg["usage"].(map[string]any); usageObj != nil {
			p.applyUsage(usageObj)
		}
	}

	if resp, _ := obj["response"].(map[string]any); resp != nil {
		if p.out.Model == "" {
			if model, _ := resp["model"].(string); model != "" {
				p.out.Model = model
			}
		}
		if usageObj, _ := resp["usage"].(map[string]any); usageObj != nil {
			p.applyUsage(usageObj)
		}
	}
}

func (p *jsonUsageParser) applyUsage(obj map[string]any) {
	p.seen = true
	setIfPresent(&p.out.InputTokens, obj, "input_tokens", "prompt_tokens")
	setIfPresent(&p.out.OutputTokens, obj, "output_tokens", "completion_tokens")
	setIfPresent(&p.out.CacheCreationInputTokens, obj, "cache_creation_input_tokens")
	setIfPresent(&p.out.CacheReadInputTokens, obj, "cache_read_input_tokens")
}

func setIfPresent(dst **int64, obj map[string]any, names ...string) {
	for _, name := range names {
		if v, ok := intValue(obj[name]); ok {
			*dst = &v
			return
		}
	}
}

func intValue(v any) (int64, bool) {
	switch x := v.(type) {
	case float64:
		return int64(x), true
	case int64:
		return x, true
	case int:
		return int64(x), true
	default:
		return 0, false
	}
}

func modelFromJSON(data []byte) string {
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		return ""
	}
	model, _ := obj["model"].(string)
	return model
}

func hasUsage(p parsed) bool {
	return p.InputTokens != nil || p.OutputTokens != nil ||
		p.CacheCreationInputTokens != nil || p.CacheReadInputTokens != nil
}

func hostOnly(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

type boundedBuffer struct {
	buf       bytes.Buffer
	truncated bool
}

func (b *boundedBuffer) Write(p []byte) {
	if b.truncated {
		return
	}
	remaining := maxParseBytes - b.buf.Len()
	if remaining <= 0 {
		b.truncated = true
		return
	}
	if len(p) > remaining {
		_, _ = b.buf.Write(p[:remaining])
		b.truncated = true
		return
	}
	_, _ = b.buf.Write(p)
}

func (b *boundedBuffer) Bytes() []byte {
	return b.buf.Bytes()
}

func (b *boundedBuffer) Truncated() bool {
	return b.truncated
}
