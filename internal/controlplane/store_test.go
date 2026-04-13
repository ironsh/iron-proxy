package controlplane

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSaveAndLoadCredential(t *testing.T) {
	dir := t.TempDir()

	cred := &Credential{
		ProxyID: "irnp_01JX123",
		Secret:  []byte{0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6},
	}

	err := SaveCredential(dir, cred)
	require.NoError(t, err)

	// Verify file permissions.
	info, err := os.Stat(filepath.Join(dir, credentialFile))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())

	loaded, err := LoadCredential(dir)
	require.NoError(t, err)
	require.Equal(t, cred.ProxyID, loaded.ProxyID)
	require.Equal(t, cred.Secret, loaded.Secret)
}

func TestLoadCredentialMissing(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadCredential(dir)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestLoadCredentialCorrupted(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, credentialFile), []byte("not json"), 0600)
	require.NoError(t, err)

	_, err = LoadCredential(dir)
	require.Error(t, err)
	require.Contains(t, err.Error(), "parsing credential file")
}

func TestLoadCredentialBadHex(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, credentialFile), []byte(`{"proxy_id":"irnp_test","secret":"not-hex!"}`), 0600)
	require.NoError(t, err)

	_, err = LoadCredential(dir)
	require.Error(t, err)
	require.Contains(t, err.Error(), "decoding credential secret")
}

func TestLoadCredentialIncomplete(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, credentialFile), []byte(`{"proxy_id":"","secret":"aabb"}`), 0600)
	require.NoError(t, err)

	_, err = LoadCredential(dir)
	require.Error(t, err)
	require.Contains(t, err.Error(), "incomplete")
}

func TestDeleteCredential(t *testing.T) {
	dir := t.TempDir()

	cred := &Credential{ProxyID: "irnp_test", Secret: []byte{0xaa}}
	require.NoError(t, SaveCredential(dir, cred))

	require.NoError(t, DeleteCredential(dir))

	_, err := LoadCredential(dir)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestDeleteCredentialNonexistent(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, DeleteCredential(dir))
}

func TestSaveCredentialCreatesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "state")

	cred := &Credential{ProxyID: "irnp_test", Secret: []byte{0xaa}}
	require.NoError(t, SaveCredential(dir, cred))

	loaded, err := LoadCredential(dir)
	require.NoError(t, err)
	require.Equal(t, cred.ProxyID, loaded.ProxyID)
}
