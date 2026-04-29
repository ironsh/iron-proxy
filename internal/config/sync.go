package config

import (
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
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
