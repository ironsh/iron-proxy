package config

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

// TransformsFromSync builds a []Transform from the control plane's sync
// payload. Each payload field is a JSON array that gets wrapped to match the
// corresponding transform's config shape: rules → {"rules": [...]} for the
// allowlist transform, secrets → {"secrets": [...]} for the secrets transform.
// Pipeline order is allowlist first, then secrets. Fields that are nil or JSON
// null are skipped.
func TransformsFromSync(rules, secrets json.RawMessage) ([]Transform, error) {
	var transforms []Transform

	if isNonNullJSON(rules) {
		node, err := yamlNodeFromJSON(map[string]json.RawMessage{"rules": rules})
		if err != nil {
			return nil, fmt.Errorf("parsing rules: %w", err)
		}
		transforms = append(transforms, Transform{
			Name:   "allowlist",
			Config: node,
		})
	}

	if isNonNullJSON(secrets) {
		node, err := yamlNodeFromJSON(map[string]json.RawMessage{"secrets": secrets})
		if err != nil {
			return nil, fmt.Errorf("parsing secrets: %w", err)
		}
		transforms = append(transforms, Transform{
			Name:   "secrets",
			Config: node,
		})
	}

	return transforms, nil
}

// MCPFromSync converts a JSON document for the top-level mcp: block into a
// yaml.Node so internal/mcp.LoadFromNode can decode it the same way as the
// YAML config path.
//
// present is true when raw is non-nil and not JSON null. Callers use it to
// distinguish "the control plane sent an mcp block" (apply, even if empty)
// from "the control plane omitted mcp" (preserve current state).
func MCPFromSync(raw json.RawMessage) (node yaml.Node, present bool, err error) {
	if !isNonNullJSON(raw) {
		return yaml.Node{}, false, nil
	}
	node, err = yamlNodeFromRawJSON(raw)
	if err != nil {
		return yaml.Node{}, false, fmt.Errorf("parsing mcp: %w", err)
	}
	return node, true, nil
}

// PostgresSyncEntry is one control-plane-synced postgres upstream. The DSN and
// optional role come from the control plane; the listener and client knobs are
// supplied separately via environment variables keyed off ForeignID (see the
// managed-mode env convention in cmd/iron-proxy).
type PostgresSyncEntry struct {
	ForeignID string
	DSN       secrets.Source
	Role      string
}

// PostgresFromSync parses the top-level postgres: array from the control
// plane's sync payload into PostgresSyncEntry values, building each entry's DSN
// source through the same secrets.BuildSource path the YAML config uses. A nil
// or JSON-null payload returns (nil, nil); individual null array elements are
// skipped. Source construction is lazy, so an entry whose DSN points at an
// unset env var still parses without error here.
func PostgresFromSync(raw json.RawMessage, logger *slog.Logger) ([]PostgresSyncEntry, error) {
	if !isNonNullJSON(raw) {
		return nil, nil
	}

	var rawEntries []json.RawMessage
	if err := json.Unmarshal(raw, &rawEntries); err != nil {
		return nil, fmt.Errorf("parsing postgres: %w", err)
	}

	entries := make([]PostgresSyncEntry, 0, len(rawEntries))
	for i, re := range rawEntries {
		if !isNonNullJSON(re) {
			continue
		}
		var e struct {
			ForeignID string          `json:"foreign_id"`
			DSN       json.RawMessage `json:"dsn"`
			Role      string          `json:"role"`
		}
		if err := json.Unmarshal(re, &e); err != nil {
			return nil, fmt.Errorf("parsing postgres[%d]: %w", i, err)
		}
		if e.ForeignID == "" {
			return nil, fmt.Errorf("postgres[%d]: foreign_id is required", i)
		}
		if !isNonNullJSON(e.DSN) {
			return nil, fmt.Errorf("postgres[%q]: dsn is required", e.ForeignID)
		}
		node, err := yamlNodeFromRawJSON(e.DSN)
		if err != nil {
			return nil, fmt.Errorf("postgres[%q]: parsing dsn: %w", e.ForeignID, err)
		}
		src, err := secrets.BuildSource(node, logger)
		if err != nil {
			return nil, fmt.Errorf("postgres[%q]: building dsn source: %w", e.ForeignID, err)
		}
		entries = append(entries, PostgresSyncEntry{
			ForeignID: e.ForeignID,
			DSN:       src,
			Role:      e.Role,
		})
	}
	return entries, nil
}

// yamlNodeFromRawJSON parses raw JSON bytes as a yaml.Node. JSON is valid YAML,
// and gopkg.in/yaml.v3 handles it natively.
func yamlNodeFromRawJSON(raw []byte) (yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return yaml.Node{}, fmt.Errorf("unmarshaling JSON as YAML: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return yaml.Node{}, fmt.Errorf("unexpected YAML structure")
	}
	return *doc.Content[0], nil
}

// yamlNodeFromJSON marshals v to JSON, then parses as a yaml.Node. This works
// because JSON is valid YAML, and gopkg.in/yaml.v3 handles it natively.
func yamlNodeFromJSON(v any) (yaml.Node, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return yaml.Node{}, fmt.Errorf("marshaling to JSON: %w", err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return yaml.Node{}, fmt.Errorf("unmarshaling JSON as YAML: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return yaml.Node{}, fmt.Errorf("unexpected YAML structure")
	}
	return *doc.Content[0], nil
}

func isNonNullJSON(data json.RawMessage) bool {
	return len(data) > 0 && string(data) != "null"
}
