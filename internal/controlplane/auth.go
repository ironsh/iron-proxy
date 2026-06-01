package controlplane

import (
	"net/http"
)

// bearerTransport is an http.RoundTripper that authenticates each request with
// a fixed bearer token issued by the control plane.
type bearerTransport struct {
	inner http.RoundTripper
	token string
}

func (t *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+t.token)
	return t.inner.RoundTrip(req)
}
