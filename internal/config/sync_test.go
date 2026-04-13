package config

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTransformsFromSync_RulesPresent(t *testing.T) {
	rules := json.RawMessage(`[{"host":"example.com","methods":["GET"],"paths":["/api/*"]}]`)

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

func TestTransformsFromSync_RoundTrip(t *testing.T) {
	rules := json.RawMessage(`[{"host":"*.example.com","methods":["GET","POST"],"paths":["/api/*"]},{"host":"api.test.io","methods":["*"],"paths":["*"]}]`)

	transforms, err := TransformsFromSync(rules)
	require.NoError(t, err)
	require.Len(t, transforms, 1)

	var decoded struct {
		Rules []struct {
			Host    string   `yaml:"host"`
			Methods []string `yaml:"methods"`
			Paths   []string `yaml:"paths"`
		} `yaml:"rules"`
	}
	require.NoError(t, transforms[0].Config.Decode(&decoded))
	require.Len(t, decoded.Rules, 2)
	require.Equal(t, "*.example.com", decoded.Rules[0].Host)
	require.Equal(t, []string{"GET", "POST"}, decoded.Rules[0].Methods)
	require.Equal(t, []string{"/api/*"}, decoded.Rules[0].Paths)
	require.Equal(t, "api.test.io", decoded.Rules[1].Host)
}

func TestTransformsFromSync_EmptyRules(t *testing.T) {
	rules := json.RawMessage(`[]`)

	transforms, err := TransformsFromSync(rules)
	require.NoError(t, err)
	require.Len(t, transforms, 1)

	var decoded struct {
		Rules []struct {
			Host string `yaml:"host"`
		} `yaml:"rules"`
	}
	require.NoError(t, transforms[0].Config.Decode(&decoded))
	require.Empty(t, decoded.Rules)
}
