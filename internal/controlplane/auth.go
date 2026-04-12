package controlplane

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// hmacTransport is an http.RoundTripper that signs requests with HMAC-SHA256.
type hmacTransport struct {
	inner http.RoundTripper
	cred  *Credential
}

func (t *hmacTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("reading request body for signing: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
	}

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	message := fmt.Sprintf("%s.%s.%s.%s", timestamp, req.Method, req.URL.Path, body)

	mac := hmac.New(sha256.New, t.cred.Secret)
	mac.Write([]byte(message))
	signature := hex.EncodeToString(mac.Sum(nil))

	req.Header.Set("X-Iron-Proxy-Id", t.cred.ProxyID)
	req.Header.Set("X-Iron-Timestamp", timestamp)
	req.Header.Set("X-Iron-Signature", signature)

	return t.inner.RoundTrip(req)
}

// ComputeSignature computes the HMAC-SHA256 signature for the given parameters.
// Exported for testing.
func ComputeSignature(secret []byte, timestamp, method, path string, body []byte) string {
	message := fmt.Sprintf("%s.%s.%s.%s", timestamp, method, path, body)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}
