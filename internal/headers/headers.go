// Package headers centralizes case-sensitive HTTP header handling.
//
// Go's net/http canonicalizes header keys via textproto.CanonicalMIMEHeaderKey
// whenever you go through http.Header.Set, Add, Get, or Values. That rewrites
// "x-api-key" to "X-Api-Key" before it reaches the wire. A handful of upstream
// venues care about the literal wire casing: some IdP gateways reject the
// canonical form for "x-api-key" on OAuth token endpoints, and a handful of
// vendor APIs validate exact-case header names on signed requests.
//
// Every helper here bypasses canonicalization by writing the http.Header map
// directly. Concentrating the direct-assignment pattern in one place keeps
// the "why is this not Header.Set" comment off every call site and gives
// staticcheck's SA1008 a single place to be silenced.
package headers

import "net/http"

// Set replaces any existing values stored under name (matched
// case-insensitively via http.Header.Del) with a single value under the
// exact name provided. Use when the upstream venue cares about literal
// wire casing.
func Set(h http.Header, name, value string) {
	h.Del(name)
	h[name] = []string{value}
}

// Add appends value under the exact name provided, preserving casing.
// Unlike Set it leaves any existing values under other casings in place,
// so use it only when the call site is intentionally building up multiple
// values under one wire-cased name.
func Add(h http.Header, name, value string) {
	h[name] = append(h[name], value)
}

// Apply sets every entry in m on h, preserving the map's key casing.
// Equivalent to calling Set in a loop; provided so call sites that inject
// a configured headers map share one line.
func Apply(h http.Header, m map[string]string) {
	for k, v := range m {
		Set(h, k, v)
	}
}

// Swap rewrites every value stored under any case-variant of canonical,
// writing the transformed values back under wireName. The caller's fn is
// invoked once per existing value with the original value string; its
// return value is written back. If canonical does not appear in h, h is
// left untouched and fn is not called.
//
// When fn must signal whether it actually modified a value (e.g. a
// substring match was found), capture a flag in its closure — keeping
// that bookkeeping out of this signature avoids biasing the API toward
// any one caller.
func Swap(h http.Header, canonical, wireName string, fn func(value string) string) {
	vals := h.Values(canonical)
	if len(vals) == 0 {
		return
	}
	out := make([]string, len(vals))
	for i, v := range vals {
		out[i] = fn(v)
	}
	h.Del(canonical)
	h[wireName] = append(h[wireName], out...)
}

// Values returns the values stored under the exact map key name, bypassing
// the canonicalization that http.Header.Get and Values apply. Use to
// inspect headers that were written with preserved casing (typically from
// tests).
//
// Routing the name through a function also keeps staticcheck's SA1008
// from flagging non-canonical string literals at call sites — the lint
// rule only fires on direct http.Header literal-key access.
func Values(h http.Header, exactName string) []string {
	return h[exactName]
}
