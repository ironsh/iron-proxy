package codexlogin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	connectop "github.com/1Password/connect-sdk-go/onepassword"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

type fakeSource struct {
	name  string
	value string
}

func (s *fakeSource) Name() string { return s.name }
func (s *fakeSource) Get(context.Context) (string, error) {
	return s.value, nil
}

type fakeWriter struct {
	current      string
	swaps        int
	seenOld      string
	seenNewValue string
}

func (w *fakeWriter) CompareAndSwap(_ context.Context, oldRefreshToken, newValue string) (string, bool, error) {
	w.swaps++
	w.seenOld = oldRefreshToken
	w.seenNewValue = newValue
	currentRefresh, err := refreshTokenFromRaw(w.current)
	if err != nil {
		return "", false, err
	}
	if currentRefresh != oldRefreshToken {
		return w.current, false, nil
	}
	w.current = newValue
	return newValue, true, nil
}

func TestCodexLoginInjectsExistingAuth(t *testing.T) {
	raw := authJSON(t, validJWT(t, time.Now().Add(time.Hour)), "refresh-old", "acct_123")
	tr := newTestTransform(t, raw, &fakeWriter{current: raw}, nil)

	req := newRequest(t, "https://chatgpt.com/backend-api/codex/responses")
	res, err := tr.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "Bearer "+mustAccess(t, raw), req.Header.Get("Authorization"))
	require.Equal(t, "acct_123", req.Header.Get("Chatgpt-Account-Id"))
}

func TestCodexLoginRefreshesAndWritesBack(t *testing.T) {
	expired := authJSON(t, validJWT(t, time.Now().Add(-time.Hour)), "refresh-old", "acct_123")
	var gotForm url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		gotForm, err = url.ParseQuery(string(body))
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + validJWT(t, time.Now().Add(time.Hour)) + `","refresh_token":"refresh-new","id_token":"id-new","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer server.Close()

	writer := &fakeWriter{current: expired}
	tr := newTestTransform(t, expired, writer, &testOptions{tokenEndpoint: server.URL})

	req := newRequest(t, "https://chatgpt.com/backend-api/codex/responses")
	res, err := tr.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "refresh_token", gotForm.Get("grant_type"))
	require.Equal(t, "refresh-old", gotForm.Get("refresh_token"))
	require.Equal(t, defaultClientID, gotForm.Get("client_id"))
	require.Equal(t, "refresh-old", writer.seenOld)
	require.Equal(t, "refresh-new", mustRefresh(t, writer.current))
	require.Equal(t, "id-new", nestedString(mustDoc(t, writer.current), "tokens", "id_token"))
}

func TestCodexLoginReloadsOnCASMismatch(t *testing.T) {
	expired := authJSON(t, validJWT(t, time.Now().Add(-time.Hour)), "refresh-old", "acct_123")
	newer := authJSON(t, validJWT(t, time.Now().Add(time.Hour)), "refresh-newer", "acct_123")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + validJWT(t, time.Now().Add(time.Hour)) + `","refresh_token":"unused-new","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer server.Close()
	writer := &fakeWriter{current: newer}
	tr := newTestTransform(t, expired, writer, &testOptions{tokenEndpoint: server.URL})

	req := newRequest(t, "https://chatgpt.com/backend-api/codex/responses")
	res, err := tr.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "Bearer "+mustAccess(t, newer), req.Header.Get("Authorization"))
	require.Equal(t, 1, writer.swaps)
}

func TestCodexLoginUsesCachedWritebackWhenSourceTTLIsStale(t *testing.T) {
	expired := authJSON(t, validJWT(t, time.Now().Add(-time.Hour)), "refresh-old", "acct_123")
	newer := authJSON(t, validJWT(t, time.Now().Add(time.Hour)), "refresh-new", "acct_123")
	writer := &fakeWriter{current: newer}
	tr := newTestTransform(t, expired, writer, nil)
	tr.auth.cachedRaw = newer

	req := newRequest(t, "https://chatgpt.com/backend-api/codex/responses")
	res, err := tr.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "Bearer "+mustAccess(t, newer), req.Header.Get("Authorization"))
	require.Equal(t, 0, writer.swaps)
}

func TestCodexLoginStubsTokenEndpoint(t *testing.T) {
	raw := authJSON(t, validJWT(t, time.Now().Add(time.Hour)), "refresh-old", "acct_123")
	tr := newTestTransform(t, raw, &fakeWriter{current: raw}, nil)

	req := newRequest(t, "https://auth.openai.com/oauth/token")
	res, err := tr.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionStub, res.Action)
	body, err := io.ReadAll(res.Response.Body)
	require.NoError(t, err)
	require.Contains(t, string(body), stubAccessToken)
	require.Contains(t, string(body), stubRefreshToken)
}

func TestOPConnectWriterCompareAndSwapUpdatesOnlyConfiguredField(t *testing.T) {
	current := authJSON(t, validJWT(t, time.Now().Add(-time.Hour)), "refresh-old", "acct_123")
	next := authJSON(t, validJWT(t, time.Now().Add(time.Hour)), "refresh-new", "acct_123")
	item := &connectop.Item{
		ID:    "item-uuid",
		Vault: connectop.ItemVault{ID: "vault-uuid"},
		Fields: []*connectop.ItemField{
			{ID: "target", Label: "auth_json", Value: current},
			{ID: "other", Label: "other", Value: "preserve-me"},
		},
	}
	client := &fakeOPConnectClient{
		vault: &connectop.Vault{ID: "vault-uuid", Name: "Engineering"},
		item:  item,
	}
	writer := &opConnectWriter{
		ref:    opRef{vault: "Engineering", item: "Codex", field: "auth_json"},
		client: client,
	}

	got, swapped, err := writer.CompareAndSwap(context.Background(), "refresh-old", next)
	require.NoError(t, err)
	require.True(t, swapped)
	require.Equal(t, next, got)
	require.Equal(t, next, item.Fields[0].Value)
	require.Equal(t, "preserve-me", item.Fields[1].Value)
	require.Equal(t, 1, client.updates)
}

func TestOPConnectWriterCompareAndSwapMismatchReturnsCurrent(t *testing.T) {
	current := authJSON(t, validJWT(t, time.Now().Add(time.Hour)), "refresh-other", "acct_123")
	next := authJSON(t, validJWT(t, time.Now().Add(time.Hour)), "refresh-new", "acct_123")
	item := &connectop.Item{
		ID:    "item-uuid",
		Vault: connectop.ItemVault{ID: "vault-uuid"},
		Fields: []*connectop.ItemField{
			{ID: "target", Label: "auth_json", Value: current},
		},
	}
	client := &fakeOPConnectClient{
		vault: &connectop.Vault{ID: "vault-uuid", Name: "Engineering"},
		item:  item,
	}
	writer := &opConnectWriter{
		ref:    opRef{vault: "Engineering", item: "Codex", field: "auth_json"},
		client: client,
	}

	got, swapped, err := writer.CompareAndSwap(context.Background(), "refresh-old", next)
	require.NoError(t, err)
	require.False(t, swapped)
	require.Equal(t, current, got)
	require.Equal(t, 0, client.updates)
}

type fakeOPConnectClient struct {
	vault   *connectop.Vault
	item    *connectop.Item
	updates int
}

func (c *fakeOPConnectClient) GetVault(string) (*connectop.Vault, error) {
	return c.vault, nil
}

func (c *fakeOPConnectClient) GetItem(string, string) (*connectop.Item, error) {
	return c.item, nil
}

func (c *fakeOPConnectClient) UpdateItem(item *connectop.Item, _ string) (*connectop.Item, error) {
	c.updates++
	c.item = item
	return item, nil
}

type testOptions struct {
	tokenEndpoint string
}

func newTestTransform(t *testing.T, raw string, writer authJSONWriter, opts *testOptions) *CodexLogin {
	t.Helper()
	tokenEndpoint := defaultTokenEndpoint
	if opts != nil && opts.tokenEndpoint != "" {
		tokenEndpoint = opts.tokenEndpoint
	}
	cfg := config{
		AuthJSON: authJSONConfig{
			Source:    yamlNode(t, map[string]string{"type": "env", "var": "IGNORED"}),
			Writeback: yamlNode(t, map[string]string{"type": "1password_connect", "secret_ref": "op://v/i/f"}),
		},
		Rules:         []hostmatch.RuleConfig{{Host: "chatgpt.com", Paths: []string{"/backend-api/codex/*"}}},
		TokenEndpoint: tokenEndpoint,
	}
	tr, err := newFromConfig(cfg, slog.Default(),
		func(yaml.Node, *slog.Logger) (secrets.Source, error) {
			return &fakeSource{name: "fake", value: raw}, nil
		},
		func(yaml.Node, *slog.Logger) (authJSONWriter, error) {
			return writer, nil
		},
	)
	require.NoError(t, err)
	tr.now = time.Now
	return tr
}

func yamlNode(t *testing.T, v any) yaml.Node {
	t.Helper()
	data, err := yaml.Marshal(v)
	require.NoError(t, err)
	var node yaml.Node
	require.NoError(t, yaml.Unmarshal(data, &node))
	if len(node.Content) > 0 {
		return *node.Content[0]
	}
	return node
}

func newRequest(t *testing.T, rawURL string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, rawURL, strings.NewReader("{}"))
	require.NoError(t, err)
	return req
}

func authJSON(t *testing.T, accessToken, refreshToken, accountID string) string {
	t.Helper()
	doc := map[string]any{
		"auth_mode":    "chatgpt",
		"last_refresh": "2026-05-01T00:00:00Z",
		"tokens": map[string]any{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
			"account_id":    accountID,
		},
	}
	out, err := json.Marshal(doc)
	require.NoError(t, err)
	return string(out)
}

func validJWT(t *testing.T, exp time.Time) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":` + jsonNumber(exp.Unix()) + `}`))
	return header + "." + payload + ".sig"
}

func jsonNumber(v int64) string {
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(jsonMarshal(v), "\n"), "\r"))
}

func jsonMarshal(v any) string {
	out, _ := json.Marshal(v)
	return string(out)
}

func mustDoc(t *testing.T, raw string) map[string]any {
	t.Helper()
	var doc map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw), &doc))
	return doc
}

func mustAccess(t *testing.T, raw string) string {
	t.Helper()
	return nestedString(mustDoc(t, raw), "tokens", "access_token")
}

func mustRefresh(t *testing.T, raw string) string {
	t.Helper()
	return nestedString(mustDoc(t, raw), "tokens", "refresh_token")
}
