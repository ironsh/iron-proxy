package mcp

import (
	"encoding/json"
	"sync"
)

// Trace is the per-request MCP audit record attached to a PipelineResult. It
// collects one Message entry per JSON-RPC message observed on either side of
// the proxy, in the order they were processed.
type Trace struct {
	Server   string    `json:"server"`
	Messages []Message `json:"messages,omitempty"`

	mu sync.Mutex
	// toolsListIDs is the set of JSON-RPC request IDs whose method was
	// tools/list, used to correlate request → response so that the response
	// filter only rewrites tool lists. Without this, a tools/call result
	// that happens to contain a top-level tools array would have entries
	// stripped by the allowlist.
	toolsListIDs map[string]bool
}

// Message is a single JSON-RPC message audit record.
type Message struct {
	Direction string `json:"direction"`
	Method    string `json:"method,omitempty"`
	Tool      string `json:"tool,omitempty"`
	Decision  string `json:"decision"`
	Reason    string `json:"reason,omitempty"`
	// Filtered counts items removed from a tools/list response when this
	// message represents a response-side filter event.
	Filtered int `json:"filtered,omitempty"`
}

// Append records a message on the trace.
func (t *Trace) Append(m Message) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.Messages = append(t.Messages, m)
	t.mu.Unlock()
}

// recordToolsListID notes that this trace saw a request with method
// tools/list and the supplied id, so the response-side filter knows to
// rewrite the matching response. Notification ids (absent or null) are
// ignored: notifications cannot have responses, and a null id cannot be
// distinguished from another null id at correlation time.
func (t *Trace) recordToolsListID(id json.RawMessage) {
	if t == nil {
		return
	}
	key, ok := canonicalIDKey(id)
	if !ok {
		return
	}
	t.mu.Lock()
	if t.toolsListIDs == nil {
		t.toolsListIDs = make(map[string]bool)
	}
	t.toolsListIDs[key] = true
	t.mu.Unlock()
}

// isToolsListResponse reports whether a response with the supplied id
// corresponds to a previously recorded tools/list request.
func (t *Trace) isToolsListResponse(id json.RawMessage) bool {
	if t == nil {
		return false
	}
	key, ok := canonicalIDKey(id)
	if !ok {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.toolsListIDs[key]
}

// canonicalIDKey returns a stable string key for a JSON-RPC id. Returns
// ("", false) for absent or null ids since those cannot be correlated to a
// specific request.
func canonicalIDKey(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		// Fall back to raw bytes when the id is not valid JSON; the worst
		// case is a missed correlation, which means we conservatively pass
		// the response through unfiltered.
		return string(raw), true
	}
	if v == nil {
		return "", false
	}
	out, err := json.Marshal(v)
	if err != nil {
		return string(raw), true
	}
	return string(out), true
}

// MessagesSnapshot returns a copy of the recorded messages safe for use after
// the trace is still being mutated.
func (t *Trace) MessagesSnapshot() []Message {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Message, len(t.Messages))
	copy(out, t.Messages)
	return out
}

// MCPServer implements transform.MCPAudit.
func (t *Trace) MCPServer() string {
	if t == nil {
		return ""
	}
	return t.Server
}

// MCPMessages implements transform.MCPAudit by flattening Message values into
// JSON-friendly maps. Returning maps avoids creating an import cycle between
// transform and mcp.
func (t *Trace) MCPMessages() []map[string]any {
	if t == nil {
		return nil
	}
	snap := t.MessagesSnapshot()
	out := make([]map[string]any, 0, len(snap))
	for _, m := range snap {
		entry := map[string]any{
			"direction": m.Direction,
			"decision":  m.Decision,
		}
		if m.Method != "" {
			entry["method"] = m.Method
		}
		if m.Tool != "" {
			entry["tool"] = m.Tool
		}
		if m.Reason != "" {
			entry["reason"] = m.Reason
		}
		if m.Filtered > 0 {
			entry["filtered"] = m.Filtered
		}
		out = append(out, entry)
	}
	return out
}
