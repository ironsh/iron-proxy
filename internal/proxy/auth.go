package proxy

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/ironsh/iron-proxy/internal/config"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"
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

func newAuthenticatorHolder(ctx context.Context, cfg config.ProxyAuth, logger *slog.Logger) (*authenticatorHolder, error) {
	h := &authenticatorHolder{}
	if err := h.Store(ctx, cfg, logger); err != nil {
		return nil, err
	}
	return h, nil
}

func (h *authenticatorHolder) Store(ctx context.Context, cfg config.ProxyAuth, logger *slog.Logger) error {
	a, err := newAuthenticator(ctx, cfg, logger)
	if err != nil {
		return err
	}
	h.value.Store(a)
	return nil
}

func (h *authenticatorHolder) Load() *authenticator {
	v := h.value.Load()
	if v == nil {
		return emptyAuthenticator()
	}
	return v.(*authenticator)
}

func emptyAuthenticator() *authenticator {
	return &authenticator{passwords: map[string]string{}}
}

func newAuthenticator(ctx context.Context, cfg config.ProxyAuth, logger *slog.Logger) (*authenticator, error) {
	passwords := make(map[string]string, len(cfg.Users))
	for i, user := range cfg.Users {
		source, err := secrets.BuildSource(user.Password, logger)
		if err != nil {
			return nil, fmt.Errorf("proxy.auth.users[%d].password: %w", i, err)
		}
		password, err := source.Get(ctx)
		if err != nil {
			return nil, fmt.Errorf("proxy.auth.users[%d].password from %q: %w", i, source.Name(), err)
		}
		passwords[user.Login] = password
	}
	return &authenticator{
		required:  cfg.Required,
		passwords: passwords,
	}, nil
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
