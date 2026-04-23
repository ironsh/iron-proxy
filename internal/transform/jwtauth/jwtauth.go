// Package jwtauth implements a transform that verifies JWT tokens from the
// Proxy-Authorization header on CONNECT requests.
package jwtauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform"
)

func init() {
	transform.Register("jwtauth", factory)
}

type jwtauthConfig struct {
	PublicKeyFile string `yaml:"public_key_file"`
	PublicKeyEnv  string `yaml:"public_key_env"`
	Audience      string `yaml:"audience"`
}

type JWTAuth struct {
	publicKey *ecdsa.PublicKey
	audience  string
	logger    *slog.Logger
}

func factory(cfg yaml.Node, logger *slog.Logger) (transform.Transformer, error) {
	var c jwtauthConfig
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing jwtauth config: %w", err)
	}

	var pemData []byte
	if c.PublicKeyFile != "" {
		var err error
		pemData, err = os.ReadFile(c.PublicKeyFile)
		if err != nil {
			return nil, fmt.Errorf("reading public key file: %w", err)
		}
	} else if c.PublicKeyEnv != "" {
		pemData = []byte(os.Getenv(c.PublicKeyEnv))
		if len(pemData) == 0 {
			return nil, fmt.Errorf("env var %s is empty", c.PublicKeyEnv)
		}
	} else {
		return nil, fmt.Errorf("jwtauth: either public_key_file or public_key_env required")
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("jwtauth: failed to decode PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("jwtauth: parsing public key: %w", err)
	}
	ecKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("jwtauth: key is not ECDSA")
	}

	return &JWTAuth{
		publicKey: ecKey,
		audience:  c.Audience,
		logger:    logger,
	}, nil
}

func (j *JWTAuth) Name() string { return "jwtauth" }

func (j *JWTAuth) TransformRequest(ctx context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	// Only enforce auth on CONNECT (tunnel establishment)
	if req.Method != http.MethodConnect {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}

	tokenStr := extractJWT(req)
	if tokenStr == "" {
		tctx.Annotate("auth", "rejected:missing")
		return &transform.TransformResult{Action: transform.ActionReject}, nil
	}

	claims, err := j.verify(tokenStr)
	if err != nil {
		j.logger.Debug("jwt verification failed", slog.String("error", err.Error()))
		tctx.Annotate("auth", "rejected:invalid")
		return &transform.TransformResult{Action: transform.ActionReject}, nil
	}

	userID, _ := claims["sub"].(string)
	tctx.Annotate("auth", "verified")
	tctx.Annotate("user_id", userID)

	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (j *JWTAuth) TransformResponse(ctx context.Context, tctx *transform.TransformContext, req *http.Request, resp *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (j *JWTAuth) verify(tokenStr string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return j.publicKey, nil
	}, jwt.WithValidMethods([]string{"ES256"}))
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid claims")
	}

	if j.audience != "" {
		aud, _ := claims["aud"].(string)
		if aud != j.audience {
			return nil, fmt.Errorf("audience mismatch: got %q, want %q", aud, j.audience)
		}
	}

	return claims, nil
}

func extractJWT(req *http.Request) string {
	auth := req.Header.Get("Proxy-Authorization")
	if auth == "" || !strings.HasPrefix(auth, "Basic ") {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(auth[6:])
	if err != nil {
		return ""
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

