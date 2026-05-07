package mcp

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// clause is a compiled argument constraint. Exactly one of equals, in, or
// matches is set.
type clause struct {
	path    []string
	equals  any
	hasEq   bool
	in      []any
	matches *regexp.Regexp
}

func compileClauses(configs []ClauseConfig, prefix string) ([]clause, error) {
	if len(configs) == 0 {
		return nil, nil
	}
	out := make([]clause, 0, len(configs))
	for i, cc := range configs {
		if cc.Path == "" {
			return nil, fmt.Errorf("%s.when[%d]: path is required", prefix, i)
		}
		set := 0
		if cc.Equals != nil {
			set++
		}
		if cc.In != nil {
			set++
		}
		if cc.Matches != "" {
			set++
		}
		if set != 1 {
			return nil, fmt.Errorf("%s.when[%d]: exactly one of equals, in, matches is required", prefix, i)
		}
		c := clause{path: splitPath(cc.Path)}
		switch {
		case cc.Equals != nil:
			c.equals = normalizeJSONScalar(cc.Equals)
			c.hasEq = true
		case cc.In != nil:
			c.in = make([]any, len(cc.In))
			for j, v := range cc.In {
				c.in[j] = normalizeJSONScalar(v)
			}
		case cc.Matches != "":
			re, err := regexp.Compile(cc.Matches)
			if err != nil {
				return nil, fmt.Errorf("%s.when[%d]: invalid matches regex: %w", prefix, i, err)
			}
			c.matches = re
		}
		out = append(out, c)
	}
	return out, nil
}

func splitPath(p string) []string {
	if p == "" {
		return nil
	}
	return strings.Split(p, ".")
}

// evaluate returns true if the clause holds for the supplied params (typically
// the JSON-RPC params object).
func (c clause) evaluate(params any) bool {
	v, ok := resolvePath(params, c.path)
	if !ok {
		return false
	}
	switch {
	case c.hasEq:
		return jsonScalarEquals(v, c.equals)
	case c.in != nil:
		for _, want := range c.in {
			if jsonScalarEquals(v, want) {
				return true
			}
		}
		return false
	case c.matches != nil:
		s, ok := v.(string)
		if !ok {
			return false
		}
		return c.matches.MatchString(s)
	}
	return false
}

// resolvePath walks a dotted path through a JSON-decoded value. Numeric
// segments index into arrays; all other segments index into maps. Returns
// (value, true) on success, (nil, false) on missing or type mismatch.
func resolvePath(root any, segments []string) (any, bool) {
	cur := root
	for _, seg := range segments {
		switch v := cur.(type) {
		case map[string]any:
			next, ok := v[seg]
			if !ok {
				return nil, false
			}
			cur = next
		case []any:
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(v) {
				return nil, false
			}
			cur = v[idx]
		default:
			return nil, false
		}
	}
	return cur, true
}

// normalizeJSONScalar coerces YAML-decoded scalars into their JSON-decoded
// equivalents so equality checks are consistent: YAML decodes 5 as int, JSON
// decodes 5 as float64, and YAML decodes "5" as string. We coerce numeric
// types to float64 to match encoding/json's default decoding.
func normalizeJSONScalar(v any) any {
	switch x := v.(type) {
	case int:
		return float64(x)
	case int32:
		return float64(x)
	case int64:
		return float64(x)
	case uint:
		return float64(x)
	case uint32:
		return float64(x)
	case uint64:
		return float64(x)
	case float32:
		return float64(x)
	}
	return v
}

func jsonScalarEquals(a, b any) bool {
	a = normalizeJSONScalar(a)
	b = normalizeJSONScalar(b)
	return a == b
}
