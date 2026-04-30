// Package version exposes the iron-proxy build version.
package version

// Version is the iron-proxy build version. It is overridden at link time via
// -ldflags "-X github.com/ironsh/iron-proxy/internal/version.Version=...".
var Version = "dev"
