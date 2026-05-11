package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// MCP JSON-RPC method names that the policy handles structurally.
const (
	MethodToolsCall = "tools/call"
	MethodToolsList = "tools/list"
)

// rpcMessage is a permissive view of a JSON-RPC 2.0 message. A message is a
// request when Method is set, a response otherwise. ID is a raw message so we
// preserve numeric/string/null distinctions when echoing it back.
type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc,omitempty"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// errMalformedJSONRPC indicates the body did not parse as a JSON-RPC message
// or batch.
var errMalformedJSONRPC = errors.New("malformed JSON-RPC")

// decodeJSONRPC parses a request body that may be a single JSON-RPC message
// or a batch (array). Returns the messages and a bool indicating whether the
// input was a batch.
func decodeJSONRPC(body []byte) ([]rpcMessage, bool, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, false, errMalformedJSONRPC
	}
	if trimmed[0] == '[' {
		var batch []rpcMessage
		if err := json.Unmarshal(trimmed, &batch); err != nil {
			return nil, true, fmt.Errorf("%w: %v", errMalformedJSONRPC, err)
		}
		if len(batch) == 0 {
			return nil, true, errMalformedJSONRPC
		}
		return batch, true, nil
	}
	var single rpcMessage
	if err := json.Unmarshal(trimmed, &single); err != nil {
		return nil, false, fmt.Errorf("%w: %v", errMalformedJSONRPC, err)
	}
	return []rpcMessage{single}, false, nil
}

// errorResponseBody builds a JSON-RPC error response body for a single
// request id and error code/message. Notification ids (absent or null) are
// preserved as JSON null.
func errorResponseBody(id json.RawMessage, code int, message string) ([]byte, error) {
	resp := rpcMessage{
		JSONRPC: "2.0",
		ID:      id,
		Error: &rpcError{
			Code:    code,
			Message: message,
		},
	}
	if len(resp.ID) == 0 {
		resp.ID = json.RawMessage("null")
	}
	return json.Marshal(resp)
}

// batchErrorResponseBody builds a JSON-RPC batch error response with one error
// entry per supplied id. ids that are nil/empty are emitted as null.
func batchErrorResponseBody(ids []json.RawMessage, code int, message string) ([]byte, error) {
	resps := make([]rpcMessage, len(ids))
	for i, id := range ids {
		if len(id) == 0 {
			id = json.RawMessage("null")
		}
		resps[i] = rpcMessage{
			JSONRPC: "2.0",
			ID:      id,
			Error: &rpcError{
				Code:    code,
				Message: message,
			},
		}
	}
	return json.Marshal(resps)
}

// extractToolCallName pulls the tool name, decoded arguments, and the raw
// arguments JSON from a tools/call params payload. Returns ("", nil, nil,
// false) when the params do not carry a recognizable tool name (caller treats
// this as malformed). rawArgs may be non-nil even when args is nil (e.g. the
// arguments field is present but not a JSON object the policy can evaluate).
func extractToolCallName(params json.RawMessage) (string, any, json.RawMessage, bool) {
	if len(params) == 0 {
		return "", nil, nil, false
	}
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return "", nil, nil, false
	}
	if p.Name == "" {
		return "", nil, nil, false
	}
	if len(p.Arguments) == 0 {
		return p.Name, nil, nil, true
	}
	var args any
	if err := json.Unmarshal(p.Arguments, &args); err != nil {
		return p.Name, nil, p.Arguments, true
	}
	return p.Name, args, p.Arguments, true
}

// filterToolsListResult takes a tools/list result payload and returns a new
// payload with the tools array filtered to allowed names. Returns the
// re-encoded result and the number of removed entries. If the result does not
// contain a tools array, the input is returned unchanged with removed=0.
func filterToolsListResult(result json.RawMessage, allowed map[string]bool) (json.RawMessage, int, error) {
	if len(result) == 0 {
		return result, 0, nil
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(result, &decoded); err != nil {
		return result, 0, nil
	}
	rawTools, ok := decoded["tools"]
	if !ok {
		return result, 0, nil
	}
	var tools []map[string]json.RawMessage
	if err := json.Unmarshal(rawTools, &tools); err != nil {
		return result, 0, nil
	}
	kept := make([]map[string]json.RawMessage, 0, len(tools))
	removed := 0
	for _, t := range tools {
		nameRaw, hasName := t["name"]
		if !hasName {
			kept = append(kept, t)
			continue
		}
		var name string
		if err := json.Unmarshal(nameRaw, &name); err != nil {
			kept = append(kept, t)
			continue
		}
		if allowed[name] {
			kept = append(kept, t)
		} else {
			removed++
		}
	}
	if removed == 0 {
		return result, 0, nil
	}
	newTools, err := json.Marshal(kept)
	if err != nil {
		return result, 0, err
	}
	decoded["tools"] = newTools
	out, err := json.Marshal(decoded)
	if err != nil {
		return result, 0, err
	}
	return out, removed, nil
}
