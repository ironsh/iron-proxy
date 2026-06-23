package config

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/postgres"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

// TransformsFromSync builds a []Transform from the control plane's sync
// payload. The rules and secrets fields are JSON arrays that get wrapped to
// match the corresponding transform's config shape: rules → {"rules": [...]}
// for the allowlist transform, secrets → {"secrets": [...]} for the secrets
// transform. The transforms field is the control plane's already-shaped
// transform array — each element a {name, config} object bundling the
// gcp_auth, gcp_id_token, hmac_sign, and oauth_token transforms granted to the
// proxy's principal.
//
// Pipeline order is allowlist, then secrets, then the control-plane transforms
// in delivered order. Secrets runs before the transforms so a body-mutating
// secret swap lands before hmac_sign signs the body, matching the canonical
// ordering in iron-proxy.example.yaml. Fields that are nil or JSON null are
// skipped.
func TransformsFromSync(rules, secrets, transformsRaw json.RawMessage) ([]Transform, error) {
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

	extra, err := transformsFromArray(transformsRaw)
	if err != nil {
		return nil, err
	}
	transforms = append(transforms, extra...)

	return transforms, nil
}

// transformsFromArray parses the control plane's top-level transforms array
// into Transform values. Each element is a {name, config} object whose shape
// matches the YAML transforms list, so config is carried through verbatim as a
// yaml.Node for the named transform's factory to decode. A nil or JSON-null
// payload yields no transforms; null array elements are skipped.
func transformsFromArray(raw json.RawMessage) ([]Transform, error) {
	if !isNonNullJSON(raw) {
		return nil, nil
	}

	var rawEntries []json.RawMessage
	if err := json.Unmarshal(raw, &rawEntries); err != nil {
		return nil, fmt.Errorf("parsing transforms: %w", err)
	}

	out := make([]Transform, 0, len(rawEntries))
	for i, re := range rawEntries {
		if !isNonNullJSON(re) {
			continue
		}
		var e struct {
			Name   string          `json:"name"`
			Config json.RawMessage `json:"config"`
		}
		if err := json.Unmarshal(re, &e); err != nil {
			return nil, fmt.Errorf("parsing transforms[%d]: %w", i, err)
		}
		if e.Name == "" {
			return nil, fmt.Errorf("transforms[%d]: name is required", i)
		}
		var node yaml.Node
		if isNonNullJSON(e.Config) {
			n, err := yamlNodeFromRawJSON(e.Config)
			if err != nil {
				return nil, fmt.Errorf("transforms[%d] (%s): parsing config: %w", i, e.Name, err)
			}
			node = n
		}
		out = append(out, Transform{Name: e.Name, Config: node})
	}
	return out, nil
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

// PostgresSyncEntry is one control-plane-synced postgres upstream, mapped to a
// single route under the managed listener. The DSN, optional role, and routing
// database come from the control plane; the per-route client credentials are
// supplied separately via environment variables keyed off ForeignID (see the
// managed-mode env convention in cmd/iron-proxy).
type PostgresSyncEntry struct {
	ForeignID string
	// Database is the routing key clients use to reach this upstream. Required:
	// it must equal the database the DSN connects to, so the control plane must
	// supply it explicitly.
	Database string
	DSN      secrets.Source
	Role     string
	// Settings are the pinned session variables the proxy SETs at session start
	// for this upstream. Optional; nil when the control plane sends none.
	Settings []postgres.Setting
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
			Database  string          `json:"database"`
			DSN       json.RawMessage `json:"dsn"`
			Role      string          `json:"role"`
			Settings  []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"settings"`
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
		if e.Database == "" {
			return nil, fmt.Errorf("postgres[%q]: database is required", e.ForeignID)
		}
		node, err := yamlNodeFromRawJSON(e.DSN)
		if err != nil {
			return nil, fmt.Errorf("postgres[%q]: parsing dsn: %w", e.ForeignID, err)
		}
		src, err := secrets.BuildSource(node, logger)
		if err != nil {
			return nil, fmt.Errorf("postgres[%q]: building dsn source: %w", e.ForeignID, err)
		}
		var settings []postgres.Setting
		if len(e.Settings) > 0 {
			settings = make([]postgres.Setting, len(e.Settings))
			for j, s := range e.Settings {
				settings[j] = postgres.Setting{Name: s.Name, Value: s.Value}
			}
		}
		entries = append(entries, PostgresSyncEntry{
			ForeignID: e.ForeignID,
			Database:  e.Database,
			DSN:       src,
			Role:      e.Role,
			Settings:  settings,
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
