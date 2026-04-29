package config

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTransformsFromSync_RulesPresent(t *testing.T) {
	rules := json.RawMessage(`[{"host":"example.com","methods":["GET"],"paths":["/api/*"]}]`)

	transforms, err := TransformsFromSync(rules, nil)
	require.NoError(t, err)
	require.Len(t, transforms, 1)
	require.Equal(t, "allowlist", transforms[0].Name)
}

func TestTransformsFromSync_Nil(t *testing.T) {
	transforms, err := TransformsFromSync(nil, nil)
	require.NoError(t, err)
	require.Empty(t, transforms)
}

func TestTransformsFromSync_NullJSON(t *testing.T) {
	transforms, err := TransformsFromSync(json.RawMessage("null"), json.RawMessage("null"))
	require.NoError(t, err)
	require.Empty(t, transforms)
}

func TestTransformsFromSync_InvalidRules(t *testing.T) {
	_, err := TransformsFromSync(json.RawMessage(`{bad json`), nil)
	require.ErrorContains(t, err, "parsing rules")
}

func TestTransformsFromSync_InvalidSecrets(t *testing.T) {
	_, err := TransformsFromSync(nil, json.RawMessage(`{bad json`))
	require.ErrorContains(t, err, "parsing secrets")
}

func TestTransformsFromSync_RoundTrip(t *testing.T) {
	rules := json.RawMessage(`[{"host":"*.example.com","methods":["GET","POST"],"paths":["/api/*"]},{"host":"api.test.io","methods":["*"],"paths":["*"]}]`)

	transforms, err := TransformsFromSync(rules, nil)
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

	transforms, err := TransformsFromSync(rules, nil)
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

func TestTransformsFromSync_SecretsPresent(t *testing.T) {
	secrets := json.RawMessage(`[{"source":{"type":"env","var":"OPENAI_API_KEY"},"inject":{"header":"Authorization","formatter":"Bearer {{ .Value }}"},"rules":[{"host":"api.openai.com"}]}]`)

	transforms, err := TransformsFromSync(nil, secrets)
	require.NoError(t, err)
	require.Len(t, transforms, 1)
	require.Equal(t, "secrets", transforms[0].Name)

	var decoded struct {
		Secrets []struct {
			Source struct {
				Type string `yaml:"type"`
				Var  string `yaml:"var"`
			} `yaml:"source"`
			Inject struct {
				Header    string `yaml:"header"`
				Formatter string `yaml:"formatter"`
			} `yaml:"inject"`
			Rules []struct {
				Host string `yaml:"host"`
			} `yaml:"rules"`
		} `yaml:"secrets"`
	}
	require.NoError(t, transforms[0].Config.Decode(&decoded))
	require.Len(t, decoded.Secrets, 1)
	require.Equal(t, "env", decoded.Secrets[0].Source.Type)
	require.Equal(t, "OPENAI_API_KEY", decoded.Secrets[0].Source.Var)
	require.Equal(t, "Authorization", decoded.Secrets[0].Inject.Header)
	require.Equal(t, "Bearer {{ .Value }}", decoded.Secrets[0].Inject.Formatter)
	require.Equal(t, "api.openai.com", decoded.Secrets[0].Rules[0].Host)
}

func TestTransformsFromSync_RulesAndSecretsOrder(t *testing.T) {
	rules := json.RawMessage(`[{"host":"example.com"}]`)
	secrets := json.RawMessage(`[{"source":{"type":"env","var":"X"},"inject":{"header":"Authorization"},"rules":[{"host":"example.com"}]}]`)

	transforms, err := TransformsFromSync(rules, secrets)
	require.NoError(t, err)
	require.Len(t, transforms, 2)
	require.Equal(t, "allowlist", transforms[0].Name)
	require.Equal(t, "secrets", transforms[1].Name)
}

func TestTransformsFromSync_EmptySecrets(t *testing.T) {
	transforms, err := TransformsFromSync(nil, json.RawMessage(`[]`))
	require.NoError(t, err)
	require.Len(t, transforms, 1)
	require.Equal(t, "secrets", transforms[0].Name)
}
