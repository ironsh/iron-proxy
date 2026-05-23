// Package awsauth implements an AWS Signature Version 4 request-signing
// transform. It signs matching outbound requests with credentials drawn from
// the standard secret sources (env, aws_sm, aws_ssm, 1password, etc.) and
// injects the resulting Authorization, X-Amz-Date, and X-Amz-Security-Token
// headers using the AWS SDK's v4 signer.
//
// Like hmac_sign, this requires MITM mode: sni-only mode has no method, path,
// or body to sign. A truncated body would produce an invalid signature, so
// bodies shorter than Content-Length and chunked bodies are rejected by
// default; set allow_chunked_body: true to opt out of the chunked check, or
// unsigned_payload: true to sign without buffering the body at all (S3
// streaming uploads, etc.).
package awsauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

func init() {
	transform.Register("aws_auth", factory)
}

// unsignedPayload is the literal placeholder AWS accepts in lieu of a real
// SHA-256 payload hash. S3, Bedrock streaming, etc. document this value.
const unsignedPayload = "UNSIGNED-PAYLOAD"

// emptyPayloadSHA256 is the hex SHA-256 of the empty string, used when the
// request has no body. Per the SDK docs SignHTTP always requires a payload
// hash, even for empty bodies.
const emptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

type config struct {
	Region           string                 `yaml:"region"`
	Service          string                 `yaml:"service"`
	AccessKeyID      yaml.Node              `yaml:"access_key_id"`
	SecretAccessKey  yaml.Node              `yaml:"secret_access_key"`
	SessionToken     yaml.Node              `yaml:"session_token,omitempty"`
	UnsignedPayload  bool                   `yaml:"unsigned_payload,omitempty"`
	AllowChunkedBody bool                   `yaml:"allow_chunked_body,omitempty"`
	Rules            []hostmatch.RuleConfig `yaml:"rules"`
}

// sourceBuilder is the signature of secrets.BuildSource, factored out so tests
// can substitute a stub builder.
type sourceBuilder func(yaml.Node, *slog.Logger) (secrets.Source, error)

// signFunc is the part of the AWS SDK v4 signer the transform uses. Factored
// into a function value so tests can inject deterministic behavior without
// reaching for the real signer.
type signFunc func(ctx context.Context, creds aws.Credentials, req *http.Request, payloadHash, service, region string, signingTime time.Time) error

// AWSAuth is the transform.
type AWSAuth struct {
	logger           *slog.Logger
	rules            []hostmatch.Rule
	region           string
	service          string
	accessKeyID      secrets.Source
	secretAccessKey  secrets.Source
	sessionToken     secrets.Source // nil when omitted
	unsignedPayload  bool
	allowChunkedBody bool

	now  func() time.Time
	sign signFunc
}

func factory(cfg yaml.Node, logger *slog.Logger) (transform.Transformer, error) {
	var c config
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing aws_auth config: %w", err)
	}
	return newFromConfig(c, logger, secrets.BuildSource)
}

func newFromConfig(c config, logger *slog.Logger, build sourceBuilder) (*AWSAuth, error) {
	if c.Region == "" {
		return nil, fmt.Errorf("aws_auth: region is required")
	}
	if c.Service == "" {
		return nil, fmt.Errorf("aws_auth: service is required")
	}
	if c.AccessKeyID.IsZero() {
		return nil, fmt.Errorf("aws_auth: access_key_id is required")
	}
	if c.SecretAccessKey.IsZero() {
		return nil, fmt.Errorf("aws_auth: secret_access_key is required")
	}

	accessKey, err := build(c.AccessKeyID, logger)
	if err != nil {
		return nil, fmt.Errorf("aws_auth: building access_key_id source: %w", err)
	}
	secretKey, err := build(c.SecretAccessKey, logger)
	if err != nil {
		return nil, fmt.Errorf("aws_auth: building secret_access_key source: %w", err)
	}
	var sessionToken secrets.Source
	if !c.SessionToken.IsZero() {
		sessionToken, err = build(c.SessionToken, logger)
		if err != nil {
			return nil, fmt.Errorf("aws_auth: building session_token source: %w", err)
		}
	}

	rules, err := hostmatch.CompileRules(c.Rules, "aws_auth")
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("aws_auth: at least one entry in \"rules\" is required")
	}

	signer := v4.NewSigner()
	return &AWSAuth{
		logger:           logger,
		rules:            rules,
		region:           c.Region,
		service:          c.Service,
		accessKeyID:      accessKey,
		secretAccessKey:  secretKey,
		sessionToken:     sessionToken,
		unsignedPayload:  c.UnsignedPayload,
		allowChunkedBody: c.AllowChunkedBody,
		now:              time.Now,
		sign: func(ctx context.Context, creds aws.Credentials, req *http.Request, payloadHash, service, region string, signingTime time.Time) error {
			return signer.SignHTTP(ctx, creds, req, payloadHash, service, region, signingTime)
		},
	}, nil
}

func (a *AWSAuth) Name() string { return "aws_auth" }

func (a *AWSAuth) TransformRequest(ctx context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	if !hostmatch.MatchAnyRule(a.rules, req) {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}

	accessKey, err := a.accessKeyID.Get(ctx)
	if err != nil {
		return a.rejectCredentialUnavailable(tctx, req, "access_key_id", err), nil
	}
	secretKey, err := a.secretAccessKey.Get(ctx)
	if err != nil {
		return a.rejectCredentialUnavailable(tctx, req, "secret_access_key", err), nil
	}
	var token string
	if a.sessionToken != nil {
		token, err = a.sessionToken.Get(ctx)
		if err != nil {
			return a.rejectCredentialUnavailable(tctx, req, "session_token", err), nil
		}
	}

	payloadHash, reject := a.payloadHash(tctx, req)
	if reject != nil {
		return reject, nil
	}

	creds := aws.Credentials{
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
		SessionToken:    token,
	}
	if err := a.sign(ctx, creds, req, payloadHash, a.service, a.region, a.now()); err != nil {
		tctx.Annotate("rejected", "signing_failed")
		tctx.Annotate("error", err.Error())
		return &transform.TransformResult{
			Action:   transform.ActionReject,
			Response: errorResponse(req, http.StatusInternalServerError, "signing_failed"),
		}, nil
	}

	injected := []string{"header:Authorization", "header:X-Amz-Date"}
	if token != "" {
		injected = append(injected, "header:X-Amz-Security-Token")
	}
	tctx.Annotate("injected", injected)
	tctx.Annotate("service", a.service)
	tctx.Annotate("region", a.region)
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (a *AWSAuth) TransformResponse(context.Context, *transform.TransformContext, *http.Request, *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

// payloadHash returns the SHA-256 hex hash of the request body, or the
// UNSIGNED-PAYLOAD sentinel when unsigned_payload is set. It reuses
// hmac_sign's body-verification policy: a truncated body or (by default) a
// chunked body produces a clean proxy-side rejection rather than a request
// the upstream will reject with an opaque "signature mismatch" error.
func (a *AWSAuth) payloadHash(tctx *transform.TransformContext, req *http.Request) (string, *transform.TransformResult) {
	if a.unsignedPayload {
		return unsignedPayload, nil
	}

	if req.Body == nil || req.Body == http.NoBody {
		if req.ContentLength > 0 {
			tctx.Annotate("rejected", "body_missing")
			tctx.Annotate("content_length", req.ContentLength)
			return "", &transform.TransformResult{
				Action:   transform.ActionReject,
				Response: errorResponse(req, http.StatusBadRequest, "body_missing"),
			}
		}
		return emptyPayloadSHA256, nil
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		tctx.Annotate("rejected", "body_read_failed")
		tctx.Annotate("error", err.Error())
		return "", &transform.TransformResult{
			Action:   transform.ActionReject,
			Response: errorResponse(req, http.StatusBadRequest, "body_read_failed"),
		}
	}

	switch {
	case req.ContentLength >= 0 && int64(len(body)) < req.ContentLength:
		tctx.Annotate("rejected", "body_truncated")
		tctx.Annotate("content_length", req.ContentLength)
		tctx.Annotate("buffered_length", len(body))
		return "", &transform.TransformResult{
			Action:   transform.ActionReject,
			Response: errorResponse(req, http.StatusRequestEntityTooLarge, "body_truncated"),
		}
	case req.ContentLength < 0 && !a.allowChunkedBody:
		tctx.Annotate("rejected", "chunked_body_not_allowed")
		return "", &transform.TransformResult{
			Action:   transform.ActionReject,
			Response: errorResponse(req, http.StatusBadRequest, "chunked_body_not_allowed"),
		}
	case req.ContentLength < 0 && a.allowChunkedBody:
		a.logger.Warn("aws_auth signing chunked request body without length verification",
			"host", hostmatch.StripPort(req.Host),
			"path", req.URL.Path,
			"buffered_length", len(body),
		)
	}

	req.Body = transform.NewBufferedBodyFromBytes(body)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

func (a *AWSAuth) rejectCredentialUnavailable(tctx *transform.TransformContext, req *http.Request, which string, err error) *transform.TransformResult {
	tctx.Annotate("rejected", "credential_unavailable")
	tctx.Annotate("credential", which)
	tctx.Annotate("error", err.Error())
	return &transform.TransformResult{
		Action:   transform.ActionReject,
		Response: errorResponse(req, http.StatusBadGateway, "credential_unavailable"),
	}
}

func errorResponse(req *http.Request, status int, reason string) *http.Response {
	body := []byte(`{"error":"aws_auth","reason":"` + reason + `"}`)
	return &http.Response{
		StatusCode:    status,
		Status:        strconv.Itoa(status) + " " + http.StatusText(status),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"application/json"}},
		Body:          transform.NewBufferedBodyFromBytes(body),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}
