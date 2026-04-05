package cagen

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerate_RSA(t *testing.T) {
	result, err := Generate(Options{
		Name:        "Test CA",
		ExpiryHours: 24,
		Algorithm:   RSA4096,
	})
	require.NoError(t, err)

	cert := parseCert(t, result.CertPEM)
	assert.True(t, cert.IsCA)
	assert.Equal(t, "Test CA", cert.Subject.CommonName)
	assert.NotZero(t, cert.KeyUsage&x509.KeyUsageCertSign)
	assert.NotZero(t, cert.KeyUsage&x509.KeyUsageCRLSign)
	assert.Equal(t, x509.RSA, cert.PublicKeyAlgorithm)
	assert.WithinDuration(t, time.Now().Add(24*time.Hour), cert.NotAfter, 2*time.Minute)

	assertValidKey(t, result.KeyPEM)
}

func TestGenerate_Ed25519(t *testing.T) {
	result, err := Generate(Options{
		Name:        "iron-proxy CA",
		ExpiryHours: 8760,
		Algorithm:   Ed25519,
	})
	require.NoError(t, err)

	cert := parseCert(t, result.CertPEM)
	assert.True(t, cert.IsCA)
	assert.Equal(t, "iron-proxy CA", cert.Subject.CommonName)
	assert.Equal(t, x509.Ed25519, cert.PublicKeyAlgorithm)

	assertValidKey(t, result.KeyPEM)
}

func TestParseAlgorithm(t *testing.T) {
	alg, err := ParseAlgorithm("rsa4096")
	require.NoError(t, err)
	assert.Equal(t, RSA4096, alg)

	alg, err = ParseAlgorithm("ed25519")
	require.NoError(t, err)
	assert.Equal(t, Ed25519, alg)

	_, err = ParseAlgorithm("invalid")
	assert.Error(t, err)
}

func TestWriteFiles(t *testing.T) {
	result, err := Generate(Options{
		Name:        "Test CA",
		ExpiryHours: 1,
		Algorithm:   Ed25519,
	})
	require.NoError(t, err)

	dir := t.TempDir()
	certPath, keyPath, err := WriteFiles(dir, result)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, "ca.crt"), certPath)
	assert.Equal(t, filepath.Join(dir, "ca.key"), keyPath)

	certData, err := os.ReadFile(certPath)
	require.NoError(t, err)
	assert.Equal(t, result.CertPEM, certData)

	keyData, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	assert.Equal(t, result.KeyPEM, keyData)

	info, err := os.Stat(keyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestWriteFiles_RefusesOverwrite(t *testing.T) {
	result, err := Generate(Options{
		Name:        "Test CA",
		ExpiryHours: 1,
		Algorithm:   Ed25519,
	})
	require.NoError(t, err)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("existing"), 0o644))

	_, _, err = WriteFiles(dir, result)
	assert.Error(t, err)
}

func TestWriteFiles_CreatesOutdir(t *testing.T) {
	result, err := Generate(Options{
		Name:        "Test CA",
		ExpiryHours: 1,
		Algorithm:   Ed25519,
	})
	require.NoError(t, err)

	dir := filepath.Join(t.TempDir(), "nested", "dir")
	_, _, err = WriteFiles(dir, result)
	require.NoError(t, err)
}

func parseCert(t *testing.T, data []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

func assertValidKey(t *testing.T, data []byte) {
	t.Helper()
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	assert.Equal(t, "PRIVATE KEY", block.Type)
	_, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
}
