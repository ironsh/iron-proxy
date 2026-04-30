// Package controlplane implements the client for the iron.sh control plane API.
package controlplane

import "fmt"

// ErrorCode identifies a specific control plane error condition.
type ErrorCode string

const (
	ErrInvalidToken   ErrorCode = "invalid_token"
	ErrTokenExpired   ErrorCode = "token_expired"
	ErrTokenExhausted ErrorCode = "token_exhausted"
	ErrValidationFail ErrorCode = "validation_failed"
	ErrProxyRevoked   ErrorCode = "proxy_revoked"
	ErrHMACFailure    ErrorCode = "hmac_failure"
)

// APIError is a typed error returned by the control plane API.
type APIError struct {
	StatusCode int
	Code       ErrorCode
	Detail     string
}

func (e *APIError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("control plane: %s: %s (HTTP %d)", e.Code, e.Detail, e.StatusCode)
	}
	return fmt.Sprintf("control plane: %s (HTTP %d)", e.Code, e.StatusCode)
}

// IsRetryable returns true if the error is transient and the request should be retried.
func (e *APIError) IsRetryable() bool {
	return e.StatusCode == 429 || e.StatusCode >= 500
}
