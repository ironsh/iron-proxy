package mcp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolvePath(t *testing.T) {
	root := map[string]any{
		"a": map[string]any{
			"b": []any{"first", "second", map[string]any{"c": 42}},
		},
	}
	cases := []struct {
		path string
		want any
		ok   bool
	}{
		{"a.b.0", "first", true},
		{"a.b.1", "second", true},
		{"a.b.2.c", 42, true},
		{"a.missing", nil, false},
		{"a.b.99", nil, false},
		{"a.b.x", nil, false},
		{"a.b", []any{"first", "second", map[string]any{"c": 42}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			got, ok := resolvePath(root, splitPath(tc.path))
			require.Equal(t, tc.ok, ok)
			if tc.ok {
				require.Equal(t, tc.want, got)
			}
		})
	}
}

func TestClauseEvaluateScalarTypes(t *testing.T) {
	// JSON-decoded values use float64 for numbers; YAML may decode int.
	// The clause must equate the two.
	clauses, err := compileClauses([]ClauseConfig{
		{Path: "n", Equals: 5},
	}, "test")
	require.NoError(t, err)
	require.Len(t, clauses, 1)

	require.True(t, clauses[0].evaluate(map[string]any{"n": float64(5)}))
	require.False(t, clauses[0].evaluate(map[string]any{"n": float64(6)}))
	require.False(t, clauses[0].evaluate(map[string]any{"n": "5"}))
}

func TestClauseEvaluateRegex(t *testing.T) {
	clauses, err := compileClauses([]ClauseConfig{{Path: "name", Matches: "^foo-"}}, "test")
	require.NoError(t, err)
	require.True(t, clauses[0].evaluate(map[string]any{"name": "foo-bar"}))
	require.False(t, clauses[0].evaluate(map[string]any{"name": "bar"}))
	require.False(t, clauses[0].evaluate(map[string]any{"name": 123})) // not a string
}

func TestClauseEvaluateIn(t *testing.T) {
	clauses, err := compileClauses([]ClauseConfig{{Path: "env", In: []any{"prod", "stage"}}}, "test")
	require.NoError(t, err)
	require.True(t, clauses[0].evaluate(map[string]any{"env": "prod"}))
	require.True(t, clauses[0].evaluate(map[string]any{"env": "stage"}))
	require.False(t, clauses[0].evaluate(map[string]any{"env": "dev"}))
}
