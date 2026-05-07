package mcp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeJSONRPCSingle(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}`)
	msgs, batch, err := decodeJSONRPC(body)
	require.NoError(t, err)
	require.False(t, batch)
	require.Len(t, msgs, 1)
	require.Equal(t, "tools/call", msgs[0].Method)
}

func TestDecodeJSONRPCBatch(t *testing.T) {
	body := []byte(`[{"jsonrpc":"2.0","id":1,"method":"a"},{"jsonrpc":"2.0","id":2,"method":"b"}]`)
	msgs, batch, err := decodeJSONRPC(body)
	require.NoError(t, err)
	require.True(t, batch)
	require.Len(t, msgs, 2)
}

func TestDecodeJSONRPCMalformed(t *testing.T) {
	cases := [][]byte{
		nil,
		[]byte(""),
		[]byte("not-json"),
		[]byte("[]"),
		[]byte("[{not json}]"),
	}
	for _, c := range cases {
		_, _, err := decodeJSONRPC(c)
		require.Error(t, err)
	}
}

func TestExtractToolCallName(t *testing.T) {
	params := json.RawMessage(`{"name":"create_issue","arguments":{"owner":"ironsh"}}`)
	name, args, ok := extractToolCallName(params)
	require.True(t, ok)
	require.Equal(t, "create_issue", name)
	m, ok := args.(map[string]any)
	require.True(t, ok)
	require.Equal(t, "ironsh", m["owner"])

	_, _, ok = extractToolCallName(json.RawMessage(`{}`))
	require.False(t, ok)

	_, _, ok = extractToolCallName(nil)
	require.False(t, ok)
}

func TestErrorResponseBody(t *testing.T) {
	body, err := errorResponseBody(json.RawMessage(`42`), -32001, "blocked")
	require.NoError(t, err)
	var msg rpcMessage
	require.NoError(t, json.Unmarshal(body, &msg))
	require.Equal(t, "2.0", msg.JSONRPC)
	require.Equal(t, "42", string(msg.ID))
	require.NotNil(t, msg.Error)
	require.Equal(t, -32001, msg.Error.Code)
	require.Equal(t, "blocked", msg.Error.Message)

	// nil id becomes JSON null.
	body, err = errorResponseBody(nil, -1, "x")
	require.NoError(t, err)
	var raw map[string]any
	require.NoError(t, json.Unmarshal(body, &raw))
	require.Nil(t, raw["id"])
	_, hasID := raw["id"]
	require.True(t, hasID, "id field must be present even when null")
}

func TestBatchErrorResponseBody(t *testing.T) {
	ids := []json.RawMessage{json.RawMessage(`1`), nil, json.RawMessage(`"x"`)}
	body, err := batchErrorResponseBody(ids, -32001, "blocked")
	require.NoError(t, err)
	var msgs []rpcMessage
	require.NoError(t, json.Unmarshal(body, &msgs))
	require.Len(t, msgs, 3)
	require.Equal(t, "1", string(msgs[0].ID))
	require.Equal(t, "null", string(msgs[1].ID))
	require.Equal(t, `"x"`, string(msgs[2].ID))
}

func TestFilterToolsListResult(t *testing.T) {
	result := json.RawMessage(`{"tools":[{"name":"keep","description":"a"},{"name":"drop"},{"name":"keep2"}]}`)
	filtered, removed, err := filterToolsListResult(result, map[string]bool{"keep": true, "keep2": true})
	require.NoError(t, err)
	require.Equal(t, 1, removed)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(filtered, &decoded))
	tools := decoded["tools"].([]any)
	require.Len(t, tools, 2)
}

func TestFilterToolsListResultNoMatchPassthrough(t *testing.T) {
	result := json.RawMessage(`{"tools":[{"name":"a"}]}`)
	filtered, removed, err := filterToolsListResult(result, map[string]bool{"a": true})
	require.NoError(t, err)
	require.Equal(t, 0, removed)
	require.Equal(t, string(result), string(filtered))
}

func TestFilterToolsListResultNoToolsField(t *testing.T) {
	result := json.RawMessage(`{"other":"value"}`)
	filtered, removed, err := filterToolsListResult(result, map[string]bool{"a": true})
	require.NoError(t, err)
	require.Equal(t, 0, removed)
	require.Equal(t, string(result), string(filtered))
}
