// Package cagen generates ephemeral CA certificates and private keys.
package cagen

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// Algorithm is the key algorithm to use for the CA.
type Algorithm string

const (
	RSA4096 Algorithm = "rsa4096"
	Ed25519 Algorithm = "ed25519"
)

// ParseAlgorithm parses a string into an Algorithm.
func ParseAlgorithm(s string) (Algorithm, error) {
	switch Algorithm(s) {
	case RSA4096:
		return RSA4096, nil
	case Ed25519:
		return Ed25519, nil
	default:
		return "", fmt.Errorf("unsupported algorithm %q (use rsa4096 or ed25519)", s)
	}
}

// Options configures CA generation.
type Options struct {
	Name        string
	ExpiryHours int
	Algorithm   Algorithm
}

// Result holds the generated CA certificate and key in PEM form.
type Result struct {
	CertPEM []byte
	KeyPEM  []byte
}

// Generate creates a new CA certificate and private key.
func Generate(opts Options) (*Result, error) {
	signer, err := generateKey(opts.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: opts.Name},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(time.Duration(opts.ExpiryHours) * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("creating certificate: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, fmt.Errorf("marshaling private key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return &Result{CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

// WriteFiles writes the CA certificate and key to outdir/ca.crt and
// outdir/ca.key. It creates outdir if needed and refuses to overwrite
// existing files.
func WriteFiles(outdir string, result *Result) (certPath, keyPath string, err error) {
	if err := os.MkdirAll(outdir, 0o755); err != nil {
		return "", "", fmt.Errorf("creating output directory: %w", err)
	}

	certPath = filepath.Join(outdir, "ca.crt")
	if err := writeExclusive(certPath, result.CertPEM, 0o644); err != nil {
		return "", "", err
	}

	keyPath = filepath.Join(outdir, "ca.key")
	if err := writeExclusive(keyPath, result.KeyPEM, 0o600); err != nil {
		return "", "", err
	}

	return certPath, keyPath, nil
}

func generateKey(alg Algorithm) (crypto.Signer, error) {
	switch alg {
	case RSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	case Ed25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	default:
		return nil, fmt.Errorf("unsupported algorithm %q", alg)
	}
}

func writeExclusive(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}
