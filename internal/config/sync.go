package config

import (
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

// TransformsFromSync builds a []Transform from the control plane's rules JSON
// payload. The rules payload is a JSON array of rule objects that gets wrapped
// into {"rules": [...]} to match the allowlist transform's expected config
// shape. If rules is nil or JSON null, an empty slice is returned.
func TransformsFromSync(rules json.RawMessage) ([]Transform, error) {
	var transforms []Transform

	if isNonNullJSON(rules) {
		wrapped := map[string]json.RawMessage{"rules": rules}
		node, err := yamlNodeFromJSON(wrapped)
		if err != nil {
			return nil, fmt.Errorf("parsing rules: %w", err)
		}
		transforms = append(transforms, Transform{
			Name:   "allowlist",
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
