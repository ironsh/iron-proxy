package config

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

func syncTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestPostgresFromSync_NilAndNull(t *testing.T) {
	entries, err := PostgresFromSync(nil, syncTestLogger())
	require.NoError(t, err)
	require.Empty(t, entries)

	entries, err = PostgresFromSync(json.RawMessage("null"), syncTestLogger())
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestPostgresFromSync_ParsesEntries(t *testing.T) {
	t.Setenv("PG_ANALYTICS_DSN", "host=analytics")
	t.Setenv("PG_MAIN_DSN", "host=main")

	raw := json.RawMessage(`[
		{"id":"pgs_1","foreign_id":"pg-analytics","dsn":{"type":"env","var":"PG_ANALYTICS_DSN"},"role":"readonly"},
		{"id":"pgs_2","foreign_id":"pg-main","dsn":{"type":"env","var":"PG_MAIN_DSN"}}
	]`)

	entries, err := PostgresFromSync(raw, syncTestLogger())
	require.NoError(t, err)
	require.Len(t, entries, 2)

	require.Equal(t, "pg-analytics", entries[0].ForeignID)
	require.Equal(t, "readonly", entries[0].Role)
	require.NotNil(t, entries[0].DSN)
	got, err := entries[0].DSN.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "host=analytics", got)

	require.Equal(t, "pg-main", entries[1].ForeignID)
	require.Empty(t, entries[1].Role)
}

func TestPostgresFromSync_SkipsNullElements(t *testing.T) {
	t.Setenv("PG_DSN", "host=x")
	raw := json.RawMessage(`[null,{"id":"pgs_1","foreign_id":"pg-x","dsn":{"type":"env","var":"PG_DSN"}},null]`)

	entries, err := PostgresFromSync(raw, syncTestLogger())
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, "pg-x", entries[0].ForeignID)
}

func TestPostgresFromSync_MissingForeignID(t *testing.T) {
	raw := json.RawMessage(`[{"id":"pgs_1","dsn":{"type":"env","var":"PG_DSN"}}]`)
	_, err := PostgresFromSync(raw, syncTestLogger())
	require.ErrorContains(t, err, "foreign_id is required")
}

func TestPostgresFromSync_MissingDSN(t *testing.T) {
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-x"}]`)
	_, err := PostgresFromSync(raw, syncTestLogger())
	require.ErrorContains(t, err, "dsn is required")
}

func TestPostgresFromSync_UnknownSourceType(t *testing.T) {
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-x","dsn":{"type":"bogus"}}]`)
	_, err := PostgresFromSync(raw, syncTestLogger())
	require.ErrorContains(t, err, "building dsn source")
}

func TestPostgresFromSync_InvalidJSON(t *testing.T) {
	_, err := PostgresFromSync(json.RawMessage(`{not an array`), syncTestLogger())
	require.ErrorContains(t, err, "parsing postgres")
}

func TestTransformsFromSync_RulesPresent(t *testing.T) {
	rules := json.RawMessage(`[{"host":"example.com","methods":["GET"],"paths":["/api/*"]}]`)

	transforms, err := TransformsFromSync(rules, nil, nil)
	require.NoError(t, err)
	require.Len(t, transforms, 1)
	require.Equal(t, "allowlist", transforms[0].Name)
}

func TestTransformsFromSync_Nil(t *testing.T) {
	transforms, err := TransformsFromSync(nil, nil, nil)
	require.NoError(t, err)
	require.Empty(t, transforms)
}

func TestTransformsFromSync_NullJSON(t *testing.T) {
	transforms, err := TransformsFromSync(json.RawMessage("null"), json.RawMessage("null"), json.RawMessage("null"))
	require.NoError(t, err)
	require.Empty(t, transforms)
}

func TestTransformsFromSync_InvalidRules(t *testing.T) {
	_, err := TransformsFromSync(json.RawMessage(`{bad json`), nil, nil)
	require.ErrorContains(t, err, "parsing rules")
}

func TestTransformsFromSync_InvalidSecrets(t *testing.T) {
	_, err := TransformsFromSync(nil, json.RawMessage(`{bad json`), nil)
	require.ErrorContains(t, err, "parsing secrets")
}

func TestTransformsFromSync_RoundTrip(t *testing.T) {
	rules := json.RawMessage(`[{"host":"*.example.com","methods":["GET","POST"],"paths":["/api/*"]},{"host":"api.test.io","methods":["*"],"paths":["*"]}]`)

	transforms, err := TransformsFromSync(rules, nil, nil)
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

	transforms, err := TransformsFromSync(rules, nil, nil)
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

	transforms, err := TransformsFromSync(nil, secrets, nil)
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

	transforms, err := TransformsFromSync(rules, secrets, nil)
	require.NoError(t, err)
	require.Len(t, transforms, 2)
	require.Equal(t, "allowlist", transforms[0].Name)
	require.Equal(t, "secrets", transforms[1].Name)
}

func TestTransformsFromSync_EmptySecrets(t *testing.T) {
	transforms, err := TransformsFromSync(nil, json.RawMessage(`[]`), nil)
	require.NoError(t, err)
	require.Len(t, transforms, 1)
	require.Equal(t, "secrets", transforms[0].Name)
}

func TestTransformsFromSync_OAuthTokenTransform(t *testing.T) {
	// The control plane bundles every granted OAuth token secret into a single
	// oauth_token transform delivered in the transforms array.
	transformsRaw := json.RawMessage(`[
		{
			"name": "oauth_token",
			"config": {
				"tokens": [
					{
						"grant": "refresh_token",
						"token_endpoint": "https://slack.com/api/oauth.v2.access",
						"client_id": {"type": "env", "var": "SLACK_CLIENT_ID"},
						"refresh_token": {"type": "control_plane", "value": "xoxe-1-..."},
						"scopes": ["chat:write"],
						"header": "Authorization",
						"value_prefix": "Bearer",
						"rules": [{"host": "slack.com", "methods": ["POST"], "paths": ["/api/*"]}]
					}
				]
			}
		}
	]`)

	transforms, err := TransformsFromSync(nil, nil, transformsRaw)
	require.NoError(t, err)
	require.Len(t, transforms, 1)
	require.Equal(t, "oauth_token", transforms[0].Name)

	var decoded struct {
		Tokens []struct {
			Grant         string `yaml:"grant"`
			TokenEndpoint string `yaml:"token_endpoint"`
			ClientID      struct {
				Type string `yaml:"type"`
				Var  string `yaml:"var"`
			} `yaml:"client_id"`
			Scopes []string `yaml:"scopes"`
			Rules  []struct {
				Host string `yaml:"host"`
			} `yaml:"rules"`
		} `yaml:"tokens"`
	}
	require.NoError(t, transforms[0].Config.Decode(&decoded))
	require.Len(t, decoded.Tokens, 1)
	require.Equal(t, "refresh_token", decoded.Tokens[0].Grant)
	require.Equal(t, "https://slack.com/api/oauth.v2.access", decoded.Tokens[0].TokenEndpoint)
	require.Equal(t, "env", decoded.Tokens[0].ClientID.Type)
	require.Equal(t, "SLACK_CLIENT_ID", decoded.Tokens[0].ClientID.Var)
	require.Equal(t, []string{"chat:write"}, decoded.Tokens[0].Scopes)
	require.Equal(t, "slack.com", decoded.Tokens[0].Rules[0].Host)
}

func TestTransformsFromSync_TransformsAfterSecrets(t *testing.T) {
	// allowlist, then secrets, then the control-plane transforms in delivered
	// order — so a body-mutating secret swap runs before hmac_sign signs.
	rules := json.RawMessage(`[{"host":"example.com"}]`)
	secrets := json.RawMessage(`[{"source":{"type":"env","var":"X"},"inject":{"header":"Authorization"},"rules":[{"host":"example.com"}]}]`)
	transformsRaw := json.RawMessage(`[
		{"name":"hmac_sign","config":{"credentials":{"secret":{"type":"env","var":"K"}}}},
		{"name":"oauth_token","config":{"tokens":[]}}
	]`)

	transforms, err := TransformsFromSync(rules, secrets, transformsRaw)
	require.NoError(t, err)
	require.Len(t, transforms, 4)
	require.Equal(t, "allowlist", transforms[0].Name)
	require.Equal(t, "secrets", transforms[1].Name)
	require.Equal(t, "hmac_sign", transforms[2].Name)
	require.Equal(t, "oauth_token", transforms[3].Name)
}

func TestTransformsFromSync_TransformsNilAndNull(t *testing.T) {
	transforms, err := TransformsFromSync(nil, nil, nil)
	require.NoError(t, err)
	require.Empty(t, transforms)

	transforms, err = TransformsFromSync(nil, nil, json.RawMessage("null"))
	require.NoError(t, err)
	require.Empty(t, transforms)
}

func TestTransformsFromSync_TransformsSkipsNullElements(t *testing.T) {
	transformsRaw := json.RawMessage(`[null,{"name":"oauth_token","config":{"tokens":[]}},null]`)
	transforms, err := TransformsFromSync(nil, nil, transformsRaw)
	require.NoError(t, err)
	require.Len(t, transforms, 1)
	require.Equal(t, "oauth_token", transforms[0].Name)
}

func TestTransformsFromSync_TransformsMissingName(t *testing.T) {
	transformsRaw := json.RawMessage(`[{"config":{"tokens":[]}}]`)
	_, err := TransformsFromSync(nil, nil, transformsRaw)
	require.ErrorContains(t, err, "name is required")
}

func TestTransformsFromSync_TransformsInvalidJSON(t *testing.T) {
	_, err := TransformsFromSync(nil, nil, json.RawMessage(`{not an array`))
	require.ErrorContains(t, err, "parsing transforms")
}

func TestMCPFromSync_Nil(t *testing.T) {
	node, present, err := MCPFromSync(nil)
	require.NoError(t, err)
	require.False(t, present)
	require.Equal(t, 0, int(node.Kind))
}

func TestMCPFromSync_NullJSON(t *testing.T) {
	node, present, err := MCPFromSync(json.RawMessage("null"))
	require.NoError(t, err)
	require.False(t, present)
	require.Equal(t, 0, int(node.Kind))
}

func TestMCPFromSync_EmptyObject(t *testing.T) {
	node, present, err := MCPFromSync(json.RawMessage(`{}`))
	require.NoError(t, err)
	require.True(t, present)
	require.NotEqual(t, 0, int(node.Kind))
}

func TestMCPFromSync_RoundTrip(t *testing.T) {
	raw := json.RawMessage(`{"error":{"code":-32099,"message":"nope"},"servers":[{"name":"github","rules":[{"host":"api.github.com"}],"tools":[{"name":"list_repos"}]}]}`)
	node, present, err := MCPFromSync(raw)
	require.NoError(t, err)
	require.True(t, present)

	var decoded struct {
		Error struct {
			Code    *int    `yaml:"code"`
			Message *string `yaml:"message"`
		} `yaml:"error"`
		Servers []struct {
			Name  string `yaml:"name"`
			Rules []struct {
				Host string `yaml:"host"`
			} `yaml:"rules"`
			Tools []struct {
				Name string `yaml:"name"`
			} `yaml:"tools"`
		} `yaml:"servers"`
	}
	require.NoError(t, node.Decode(&decoded))
	require.NotNil(t, decoded.Error.Code)
	require.Equal(t, -32099, *decoded.Error.Code)
	require.NotNil(t, decoded.Error.Message)
	require.Equal(t, "nope", *decoded.Error.Message)
	require.Len(t, decoded.Servers, 1)
	require.Equal(t, "github", decoded.Servers[0].Name)
	require.Equal(t, "api.github.com", decoded.Servers[0].Rules[0].Host)
	require.Equal(t, "list_repos", decoded.Servers[0].Tools[0].Name)
}

func TestMCPFromSync_InvalidJSON(t *testing.T) {
	_, _, err := MCPFromSync(json.RawMessage(`{bad json`))
	require.ErrorContains(t, err, "parsing mcp")
}
