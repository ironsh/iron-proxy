package controlplane

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const credentialFile = "credential.json"

// credentialJSON is the on-disk representation with hex-encoded secret.
type credentialJSON struct {
	ProxyID string `json:"proxy_id"`
	Secret  string `json:"secret"`
}

// SaveCredential writes the credential to a JSON file in dir with 0600 permissions.
func SaveCredential(dir string, cred *Credential) error {
	data, err := json.Marshal(credentialJSON{
		ProxyID: cred.ProxyID,
		Secret:  hex.EncodeToString(cred.Secret),
	})
	if err != nil {
		return fmt.Errorf("marshaling credential: %w", err)
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating state directory: %w", err)
	}

	path := filepath.Join(dir, credentialFile)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("writing credential file: %w", err)
	}

	return nil
}

// LoadCredential reads and parses a credential from the state directory.
// Returns os.ErrNotExist if the file does not exist.
func LoadCredential(dir string) (*Credential, error) {
	path := filepath.Join(dir, credentialFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cj credentialJSON
	if err := json.Unmarshal(data, &cj); err != nil {
		return nil, fmt.Errorf("parsing credential file: %w", err)
	}

	secret, err := hex.DecodeString(cj.Secret)
	if err != nil {
		return nil, fmt.Errorf("decoding credential secret: %w", err)
	}

	if cj.ProxyID == "" || len(secret) == 0 {
		return nil, fmt.Errorf("credential file is incomplete")
	}

	return &Credential{
		ProxyID: cj.ProxyID,
		Secret:  secret,
	}, nil
}

// DeleteCredential removes the credential file from the state directory.
func DeleteCredential(dir string) error {
	path := filepath.Join(dir, credentialFile)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing credential file: %w", err)
	}
	return nil
}
