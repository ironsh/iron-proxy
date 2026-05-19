package transform

import "net/http"

// SetHeaderPreservingCase replaces any existing values under name (matched
// case-insensitively via http.Header.Del) with a single value stored under
// the exact name provided. Use this when the upstream venue cares about the
// literal wire casing of the header — http.Header.Set would canonicalize
// the key and discard the user's casing.
func SetHeaderPreservingCase(h http.Header, name, value string) {
	h.Del(name)
	h[name] = []string{value}
}

// HeaderValuesByExactName returns the values stored under the exact map key
// name, bypassing the canonicalization that http.Header.Get and Values apply.
// Use this to inspect (in transforms or tests) headers that were written with
// preserved casing.
//
// Routing the name through a function also keeps staticcheck's SA1008 from
// flagging non-canonical string literals at call sites — the lint rule only
// fires on direct http.Header literal-key access.
func HeaderValuesByExactName(h http.Header, name string) []string {
	return h[name]
}
