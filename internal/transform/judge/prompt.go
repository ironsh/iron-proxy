package judge

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"unicode/utf8"
)

// Envelope byte caps.
const (
	MaxBodyBytes        = 16384
	MaxURLBytes         = 2048
	MaxHeaderBytes      = 4096
	MaxHeaderValueBytes = 512
)

//go:embed system_prompt.md
var systemPromptTemplate string

// priorityHeaders defeats header-inflation attacks: even when the envelope
// budget is exhausted by junk headers, security-relevant headers are emitted
// first so the LLM sees them. Order groups identity/routing, then content
// shape, then credentials.
var priorityHeaders = []string{
	"Host",
	"Origin",
	"Referer",
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"Content-Type",
	"Content-Length",
	"Content-Encoding",
	"Transfer-Encoding",
	"Authorization",
	"Cookie",
}

var (
	priorityHeadersCanonical = func() []string {
		out := make([]string, len(priorityHeaders))
		for i, h := range priorityHeaders {
			out[i] = http.CanonicalHeaderKey(h)
		}
		return out
	}()
	prioritySet = func() map[string]bool {
		s := make(map[string]bool, len(priorityHeadersCanonical))
		for _, h := range priorityHeadersCanonical {
			s[h] = true
		}
		return s
	}()
)

// headerKV is an ordered header entry. A slice preserves priority ordering in
// the marshaled JSON, which a map would not.
type headerKV struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// requestEnvelope is the JSON payload sent to the LLM describing the HTTP request.
type requestEnvelope struct {
	Method           string     `json:"method"`
	URL              string     `json:"url"`
	Host             string     `json:"host"`
	Headers          []headerKV `json:"headers"`
	Body             string     `json:"body,omitempty"`
	Warnings         []string   `json:"warnings,omitempty"`
	MultipartSummary string     `json:"multipart_summary,omitempty"`
}

// Decision is the parsed JSON object returned by the LLM.
type Decision struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

// buildSystemPrompt renders the embedded template with the operator's policy
// JSON-escaped. The escape is the primary defense against a policy that
// contains quotes, braces, newlines, or prompt-injection-shaped text.
func buildSystemPrompt(policy string) string {
	escaped, err := json.Marshal(policy)
	if err != nil {
		// json.Marshal of a string cannot fail.
		escaped = []byte(`""`)
	}
	return fmt.Sprintf(systemPromptTemplate, string(escaped))
}

// buildEnvelope serializes the request into the JSON envelope sent to the LLM.
// bodyTruncated must be true if the caller read up to MaxBodyBytes and there
// was more body available beyond the cap.
func buildEnvelope(req *http.Request, body []byte, bodyTruncated bool) ([]byte, error) {
	env := requestEnvelope{
		Method: req.Method,
		Host:   req.Host,
	}

	urlStr := ""
	if req.URL != nil {
		urlStr = req.URL.String()
	}
	if truncated, origLen := truncateString(&urlStr, MaxURLBytes); truncated {
		env.Warnings = append(env.Warnings, fmt.Sprintf("url truncated from %d to %d bytes", origLen, MaxURLBytes))
	}
	env.URL = urlStr

	env.Headers, env.Warnings = collectHeaders(req.Header, env.Warnings)

	if len(body) > 0 {
		if utf8.Valid(body) {
			env.Body = string(body)
		} else {
			env.Warnings = append(env.Warnings, "body omitted: contains non-UTF-8 bytes")
		}
	}
	if bodyTruncated {
		env.Warnings = append(env.Warnings, fmt.Sprintf("body truncated to %d bytes; content beyond this cap was not shown", MaxBodyBytes))
		// Multipart stub: full summarization is v0.14.
		// TODO(v0.14): produce a structured summary of multipart parts that fit the cap.
		if ct := req.Header.Get("Content-Type"); strings.HasPrefix(strings.ToLower(ct), "multipart/") {
			env.MultipartSummary = "<truncated multipart body; full parsing in v0.14>"
		}
	}

	return json.Marshal(env)
}

func collectHeaders(h http.Header, warnings []string) ([]headerKV, []string) {
	if len(h) == 0 {
		return nil, warnings
	}

	var out []headerKV
	used := 0
	truncated := false

	emit := func(name, value string) bool {
		cost := len(name) + len(value)
		if used+cost > MaxHeaderBytes {
			truncated = true
			return false
		}
		used += cost
		out = append(out, headerKV{Name: name, Value: value})
		return true
	}

	canonical := make(map[string][]string, len(h))
	for k, vs := range h {
		canonical[http.CanonicalHeaderKey(k)] = vs
	}

	for _, cname := range priorityHeadersCanonical {
		vs, ok := canonical[cname]
		if !ok || len(vs) == 0 {
			continue
		}
		value := capHeaderValue(joinHeader(vs))
		if !emit(cname, value) {
			break
		}
	}

	// Phase 2: remaining headers, alphabetical.
	if !truncated {
		var remaining []string
		for k := range canonical {
			if prioritySet[k] {
				continue
			}
			remaining = append(remaining, k)
		}
		sort.Strings(remaining)
		for _, k := range remaining {
			value := capHeaderValue(joinHeader(canonical[k]))
			if !emit(k, value) {
				break
			}
		}
	}

	if truncated {
		warnings = append(warnings, fmt.Sprintf("headers truncated to fit %d byte budget", MaxHeaderBytes))
	}

	return out, warnings
}

func capHeaderValue(v string) string {
	if len(v) <= MaxHeaderValueBytes {
		return v
	}
	return v[:MaxHeaderValueBytes] + fmt.Sprintf("... [truncated, original %d bytes]", len(v))
}

// joinHeader joins multi-valued headers with ", " so the canonical form is
// preserved when we emit a single slot per header name.
func joinHeader(vs []string) string {
	return strings.Join(vs, ", ")
}

// truncateString caps *s at max bytes in place. Returns (truncated, origLen).
func truncateString(s *string, max int) (bool, int) {
	orig := len(*s)
	if orig <= max {
		return false, orig
	}
	*s = (*s)[:max]
	return true, orig
}

// parseDecision strips optional Markdown code fences, unmarshals the JSON, and
// validates the decision value. Unknown decision values or malformed JSON
// return an error so the caller applies the configured fallback.
func parseDecision(raw string) (Decision, error) {
	s := strings.TrimSpace(raw)
	s = stripCodeFence(s)

	var d Decision
	if err := json.Unmarshal([]byte(s), &d); err != nil {
		return Decision{}, fmt.Errorf("parsing decision: %w", err)
	}

	d.Decision = strings.ToUpper(strings.TrimSpace(d.Decision))
	switch d.Decision {
	case decisionAllow, decisionDeny:
		return d, nil
	default:
		return Decision{}, fmt.Errorf("unknown decision value: %q", d.Decision)
	}
}

// stripCodeFence removes optional triple-backtick fences, including the
// ```json variant. Returns the inner content unchanged if no fence is present.
func stripCodeFence(s string) string {
	if !strings.HasPrefix(s, "```") {
		return s
	}
	s = strings.TrimPrefix(s, "```")
	if rest, ok := trimPrefixFold(s, "json"); ok {
		s = rest
	}
	s = strings.TrimLeft(s, " \t\r\n")
	s = strings.TrimSuffix(s, "```")
	return strings.TrimSpace(s)
}

func trimPrefixFold(s, prefix string) (string, bool) {
	if len(s) < len(prefix) {
		return s, false
	}
	if strings.EqualFold(s[:len(prefix)], prefix) {
		return s[len(prefix):], true
	}
	return s, false
}
