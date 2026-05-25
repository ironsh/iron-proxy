package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func mustNode(t *testing.T, src string) yaml.Node {
	t.Helper()
	var n yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(src), &n))
	require.Equal(t, 1, len(n.Content), "expected a single document node")
	return *n.Content[0]
}

func TestFileBuilderRejectsRelativePath(t *testing.T) {
	_, err := fileBuilder{}.Build(mustNode(t, `{type: file, path: relative.json}`), nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "absolute")
}

func TestFileBuilderRequiresPath(t *testing.T) {
	_, err := fileBuilder{}.Build(mustNode(t, `{type: file}`), nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "path")
}

func TestFileHandleGetReturnsNotFound(t *testing.T) {
	dir := t.TempDir()
	h, err := fileBuilder{}.Build(mustNode(t, `{type: file, path: `+filepath.Join(dir, "missing.json")+`}`), nil)
	require.NoError(t, err)
	_, err = h.Get(t.Context())
	require.ErrorIs(t, err, ErrNotFound)
}

func TestFileHandlePutGetRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.json")
	h, err := fileBuilder{}.Build(mustNode(t, `{type: file, path: `+path+`}`), nil)
	require.NoError(t, err)

	blob := CredentialBlob{
		AccessToken:  "access-1",
		RefreshToken: "refresh-1",
		ExpiresAt:    time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC),
		LastRefresh:  time.Date(2026, 5, 24, 11, 0, 0, 0, time.UTC),
	}
	mustPut(t, h, blob)

	got, err := h.Get(t.Context())
	require.NoError(t, err)
	require.Equal(t, blob.AccessToken, got.AccessToken)
	require.Equal(t, blob.RefreshToken, got.RefreshToken)
	require.True(t, blob.ExpiresAt.Equal(got.ExpiresAt))

	// File should be 0600 — credentials must not land world-readable.
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestFileHandlePutPreservesExistingPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.json")
	h, err := fileBuilder{}.Build(mustNode(t, `{type: file, path: `+path+`}`), nil)
	require.NoError(t, err)

	mustPut(t, h, CredentialBlob{RefreshToken: "rt"})
	// Operator tightens permissions further. The broker must preserve
	// them across subsequent writes rather than reverting to 0600.
	require.NoError(t, os.Chmod(path, 0o400))
	mustPut(t, h, CredentialBlob{RefreshToken: "rt2"})

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o400), info.Mode().Perm())
}

func TestFileHandleGetRejectsMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.json")
	require.NoError(t, os.WriteFile(path, []byte("not json"), 0o600))
	h, err := fileBuilder{}.Build(mustNode(t, `{type: file, path: `+path+`}`), nil)
	require.NoError(t, err)
	_, err = h.Get(t.Context())
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrNotFound)
}
