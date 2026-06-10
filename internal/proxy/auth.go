package proxy

import (
	"crypto/subtle"
	"encoding/base64"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"

	"github.com/ironsh/iron-proxy/internal/config"
)

const proxyAuthRealm = `Basic realm="iron-proxy"`

type authenticator struct {
	required  bool
	passwords map[string]string
}

type authenticatorHolder struct {
	value atomic.Value // *authenticator
}

type proxyAuth struct {
	Login string
}

func newAuthenticatorHolder(cfg config.ProxyAuth) *authenticatorHolder {
	h := &authenticatorHolder{}
	h.Store(cfg)
	return h
}

func (h *authenticatorHolder) Store(cfg config.ProxyAuth) {
	h.value.Store(newAuthenticator(cfg))
}

func (h *authenticatorHolder) Load() *authenticator {
	v := h.value.Load()
	if v == nil {
		return newAuthenticator(config.ProxyAuth{})
	}
	return v.(*authenticator)
}

func newAuthenticator(cfg config.ProxyAuth) *authenticator {
	passwords := make(map[string]string, len(cfg.Users))
	for _, user := range cfg.Users {
		password := user.Password
		if user.PasswordEnv != "" {
			password = os.Getenv(user.PasswordEnv)
		}
		passwords[user.Login] = password
	}
	return &authenticator{
		required:  cfg.Required,
		passwords: passwords,
	}
}

func (a *authenticator) enabled() bool {
	return a.required || len(a.passwords) > 0
}

func (a *authenticator) authenticateHeader(header string) (proxyAuth, bool) {
	if header == "" {
		return proxyAuth{}, !a.required
	}
	login, password, ok := parseBasicProxyAuth(header)
	if !ok {
		return proxyAuth{}, false
	}
	if !a.authenticateLoginPassword(login, password) {
		return proxyAuth{}, false
	}
	return proxyAuth{Login: login}, true
}

func (a *authenticator) authenticateLoginPassword(login, password string) bool {
	want, ok := a.passwords[login]
	if !ok {
		_ = subtle.ConstantTimeCompare([]byte(password), []byte(""))
		return false
	}
	return subtle.ConstantTimeCompare([]byte(password), []byte(want)) == 1
}

func parseBasicProxyAuth(header string) (string, string, bool) {
	scheme, encoded, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", false
	}
	login, password, ok := strings.Cut(string(decoded), ":")
	if !ok || login == "" {
		return "", "", false
	}
	return login, password, true
}

func proxyAuthRequiredResponse(req *http.Request) *http.Response {
	return &http.Response{
		StatusCode:    http.StatusProxyAuthRequired,
		Status:        "407 Proxy Authentication Required",
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Proxy-Authenticate": {proxyAuthRealm}},
		Body:          http.NoBody,
		Request:       req,
		ContentLength: 0,
	}
}

func sourceIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	return remoteAddr
}
