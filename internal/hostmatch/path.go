package hostmatch

import (
	"path"
	"strings"
)

// MatchPath checks if reqPath matches a path pattern. Patterns ending in /*
// match any path under that prefix (e.g. /v1/* matches /v1/models and /v1).
// Other patterns use path.Match glob semantics.
func MatchPath(pattern, reqPath string) bool {
	if strings.HasSuffix(pattern, "/*") {
		prefix := pattern[:len(pattern)-1] // "/v1/"
		base := pattern[:len(pattern)-2]   // "/v1"
		return strings.HasPrefix(reqPath, prefix) || reqPath == base
	}
	matched, _ := path.Match(pattern, reqPath)
	return matched
}

// MatchAnyPath returns true if reqPath matches any of the given patterns.
func MatchAnyPath(patterns []string, reqPath string) bool {
	for _, p := range patterns {
		if MatchPath(p, reqPath) {
			return true
		}
	}
	return false
}
