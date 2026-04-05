package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunGenerateCA(t *testing.T) {
	dir := t.TempDir()
	runGenerateCA([]string{"-outdir", dir, "-alg", "ed25519", "-name", "Test CA", "-expiry-hours", "24"})

	_, err := os.Stat(filepath.Join(dir, "ca.crt"))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(dir, "ca.key"))
	require.NoError(t, err)
}
