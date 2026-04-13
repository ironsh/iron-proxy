package config

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTransformsFromSync_RulesPresent(t *testing.T) {
	rules := json.RawMessage(`{"domains": ["*.example.com"], "warn": true}`)

	transforms, err := TransformsFromSync(rules)
	require.NoError(t, err)
	require.Len(t, transforms, 1)
	require.Equal(t, "allowlist", transforms[0].Name)
}

func TestTransformsFromSync_Nil(t *testing.T) {
	transforms, err := TransformsFromSync(nil)
	require.NoError(t, err)
	require.Empty(t, transforms)
}

func TestTransformsFromSync_NullJSON(t *testing.T) {
	transforms, err := TransformsFromSync(json.RawMessage("null"))
	require.NoError(t, err)
	require.Empty(t, transforms)
}

func TestTransformsFromSync_InvalidJSON(t *testing.T) {
	_, err := TransformsFromSync(json.RawMessage(`{bad json`))
	require.ErrorContains(t, err, "parsing rules")
}

func TestTransformsFromSync_RoundTrip_Allowlist(t *testing.T) {
	rules := json.RawMessage(`{"domains": ["*.example.com", "api.test.io"], "warn": false}`)

	transforms, err := TransformsFromSync(rules)
	require.NoError(t, err)
	require.Len(t, transforms, 1)

	var decoded struct {
		Domains []string `yaml:"domains"`
		Warn    bool     `yaml:"warn"`
	}
	require.NoError(t, transforms[0].Config.Decode(&decoded))
	require.Equal(t, []string{"*.example.com", "api.test.io"}, decoded.Domains)
	require.False(t, decoded.Warn)
}
