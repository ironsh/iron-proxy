package config

import (
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

// TransformsFromSync builds a []Transform from the control plane's rules JSON
// payload. If rules is nil or JSON null, an empty slice is returned.
func TransformsFromSync(rules json.RawMessage) ([]Transform, error) {
	var transforms []Transform

	if isNonNullJSON(rules) {
		node, err := yamlNodeFromJSON(rules)
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

// yamlNodeFromJSON converts a JSON byte slice into a yaml.Node. This works
// because JSON is valid YAML, and gopkg.in/yaml.v3 handles it natively.
func yamlNodeFromJSON(data json.RawMessage) (yaml.Node, error) {
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
