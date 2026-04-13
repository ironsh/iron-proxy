package hostmatch

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCompileRules_WildcardMethodMatchesAll(t *testing.T) {
	rules, err := CompileRules([]RuleConfig{
		{Host: "example.com", Methods: []string{"*"}},
	}, NullResolver{}, "test")
	require.NoError(t, err)
	require.Len(t, rules, 1)
	require.Nil(t, rules[0].Methods, "wildcard method should result in nil Methods (match all)")

	ctx := context.Background()
	for _, method := range []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"} {
		require.True(t, rules[0].Matches(ctx, "example.com", method, "/"), "method %s should match", method)
	}
}

func TestCompileRules_ExplicitMethodsFiltered(t *testing.T) {
	rules, err := CompileRules([]RuleConfig{
		{Host: "example.com", Methods: []string{"GET", "post"}},
	}, NullResolver{}, "test")
	require.NoError(t, err)
	require.Len(t, rules, 1)
	require.NotNil(t, rules[0].Methods)

	ctx := context.Background()
	require.True(t, rules[0].Matches(ctx, "example.com", "GET", "/"))
	require.True(t, rules[0].Matches(ctx, "example.com", "POST", "/"))
	require.False(t, rules[0].Matches(ctx, "example.com", "DELETE", "/"))
}

func TestCompileRules_NoMethodsMatchesAll(t *testing.T) {
	rules, err := CompileRules([]RuleConfig{
		{Host: "example.com"},
	}, NullResolver{}, "test")
	require.NoError(t, err)
	require.Len(t, rules, 1)
	require.Nil(t, rules[0].Methods)

	ctx := context.Background()
	require.True(t, rules[0].Matches(ctx, "example.com", "GET", "/"))
	require.True(t, rules[0].Matches(ctx, "example.com", "DELETE", "/"))
}
