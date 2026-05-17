package transform

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func captureAuditLog(result *PipelineResult) (map[string]any, string) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	fn := NewAuditLogger(logger)
	fn(result)

	var parsed map[string]any
	_ = json.Unmarshal(buf.Bytes(), &parsed)
	return parsed, buf.String()
}

func TestAudit_AllowedRequest(t *testing.T) {
	result := &PipelineResult{
		Host:       "api.openai.com",
		Method:     "POST",
		Path:       "/v1/chat/completions",
		RemoteAddr: "10.16.0.5:43210",
		SNI:        "api.openai.com",
		StartedAt:  time.Now(),
		Duration:   142500 * time.Microsecond,
		Action:     ActionContinue,
		StatusCode: 200,
		RequestTransforms: []TransformTrace{
			{Name: "allowlist", Action: ActionContinue, Duration: 20 * time.Microsecond},
			{Name: "secrets", Action: ActionContinue, Duration: 80 * time.Microsecond,
				Annotations: map[string]any{"swapped": "OPENAI_API_KEY"}},
		},
	}

	parsed, raw := captureAuditLog(result)

	require.Equal(t, "INFO", parsed["level"])
	require.Equal(t, "request", parsed["msg"])

	audit := parsed["audit"].(map[string]any)
	require.Equal(t, "api.openai.com", audit["host"])
	require.Equal(t, "POST", audit["method"])
	require.Equal(t, "/v1/chat/completions", audit["path"])
	require.Equal(t, "allow", audit["action"])
	require.Equal(t, float64(200), audit["status_code"])
	require.Greater(t, audit["duration_ms"].(float64), float64(0))

	// Should have transform traces
	require.Contains(t, raw, "allowlist")
	require.Contains(t, raw, "secrets")
}

func TestAudit_RejectedRequest(t *testing.T) {
	result := &PipelineResult{
		Host:       "evil.com",
		Method:     "GET",
		Path:       "/exfiltrate",
		RemoteAddr: "10.16.0.5:43211",
		SNI:        "evil.com",
		StartedAt:  time.Now(),
		Duration:   50 * time.Microsecond,
		Action:     ActionReject,
		StatusCode: 403,
		RequestTransforms: []TransformTrace{
			{Name: "allowlist", Action: ActionReject, Duration: 50 * time.Microsecond},
		},
	}

	parsed, _ := captureAuditLog(result)

	require.Equal(t, "WARN", parsed["level"])
	require.Equal(t, "request", parsed["msg"])
	require.Equal(t, "allowlist", parsed["rejected_by"])

	audit := parsed["audit"].(map[string]any)
	require.Equal(t, "reject", audit["action"])
	require.Equal(t, float64(403), audit["status_code"])
}

func TestAudit_StubbedRequest(t *testing.T) {
	result := &PipelineResult{
		Host:       "oauth2.googleapis.com",
		Method:     "POST",
		Path:       "/token",
		RemoteAddr: "10.16.0.5:43216",
		SNI:        "oauth2.googleapis.com",
		StartedAt:  time.Now(),
		Duration:   80 * time.Microsecond,
		Action:     ActionStub,
		StatusCode: 200,
		RequestTransforms: []TransformTrace{
			{Name: "gcp_auth", Action: ActionStub, Duration: 80 * time.Microsecond,
				Annotations: map[string]any{"stubbed": "oauth2_token_endpoint"}},
		},
	}

	parsed, _ := captureAuditLog(result)

	require.Equal(t, "INFO", parsed["level"])
	require.Equal(t, "request", parsed["msg"])
	require.Equal(t, "gcp_auth", parsed["stubbed_by"])

	audit := parsed["audit"].(map[string]any)
	require.Equal(t, "stub", audit["action"])
	require.Equal(t, float64(200), audit["status_code"])
}

func TestAudit_TunnelInfo(t *testing.T) {
	result := &PipelineResult{
		Host:       "example.com",
		Method:     "GET",
		Path:       "/",
		RemoteAddr: "10.16.0.5:43213",
		SNI:        "example.com",
		StartedAt:  time.Now(),
		Duration:   time.Millisecond,
		Action:     ActionContinue,
		StatusCode: 200,
		Tunnel: &TunnelInfo{
			Target: "example.com:443",
			RequestTransforms: []TransformTrace{
				{
					Name:        "auth",
					Action:      ActionContinue,
					Duration:    250 * time.Microsecond,
					Annotations: map[string]any{"user_id": "alice"},
				},
			},
		},
	}

	parsed, _ := captureAuditLog(result)

	tunnel := parsed["tunnel"].(map[string]any)
	require.Equal(t, "example.com:443", tunnel["target"])
	traces := tunnel["request_transforms"].([]any)
	require.Len(t, traces, 1)
	trace := traces[0].(map[string]any)
	require.Equal(t, "auth", trace["name"])
	require.Equal(t, "allow", trace["action"])
	annotations := trace["annotations"].(map[string]any)
	require.Equal(t, "alice", annotations["user_id"])
}

func TestAudit_ErroredRequest(t *testing.T) {
	result := &PipelineResult{
		Host:       "api.openai.com",
		Method:     "POST",
		Path:       "/v1/chat/completions",
		RemoteAddr: "10.16.0.5:43212",
		SNI:        "api.openai.com",
		StartedAt:  time.Now(),
		Duration:   12300 * time.Microsecond,
		Action:     ActionContinue,
		StatusCode: 502,
		Err:        errors.New("env var OPENAI_API_KEY read failed"),
		RequestTransforms: []TransformTrace{
			{Name: "allowlist", Action: ActionContinue, Duration: 20 * time.Microsecond},
			{Name: "secrets", Duration: 12200 * time.Microsecond,
				Err: errors.New("env var OPENAI_API_KEY read failed")},
		},
	}

	parsed, raw := captureAuditLog(result)

	require.Equal(t, "ERROR", parsed["level"])
	require.Equal(t, "request", parsed["msg"])
	require.Contains(t, raw, "env var OPENAI_API_KEY read failed")

	audit := parsed["audit"].(map[string]any)
	require.Equal(t, "error", audit["action"])
	require.Equal(t, float64(502), audit["status_code"])
}

func TestAudit_ClientCanceled(t *testing.T) {
	result := &PipelineResult{
		Host:           "api.openai.com",
		Method:         "POST",
		Path:           "/v1/chat/completions",
		RemoteAddr:     "10.16.0.5:43215",
		SNI:            "api.openai.com",
		StartedAt:      time.Now(),
		Duration:       3200 * time.Microsecond,
		Action:         ActionContinue,
		StatusCode:     200,
		ClientCanceled: true,
	}

	parsed, raw := captureAuditLog(result)

	require.Equal(t, "INFO", parsed["level"])
	require.Equal(t, "request", parsed["msg"])
	require.NotContains(t, raw, "\"error\"")

	audit := parsed["audit"].(map[string]any)
	require.Equal(t, "client_cancel", audit["action"])
	require.Equal(t, float64(200), audit["status_code"])
}

func TestAudit_TransformTraceOrder(t *testing.T) {
	result := &PipelineResult{
		Host:       "example.com",
		Method:     "GET",
		Path:       "/",
		StartedAt:  time.Now(),
		Duration:   1 * time.Millisecond,
		Action:     ActionContinue,
		StatusCode: 200,
		RequestTransforms: []TransformTrace{
			{Name: "first", Action: ActionContinue, Duration: 100 * time.Microsecond},
			{Name: "second", Action: ActionContinue, Duration: 200 * time.Microsecond},
			{Name: "third", Action: ActionContinue, Duration: 300 * time.Microsecond},
		},
	}

	_, raw := captureAuditLog(result)

	// Verify all three transforms appear in the log
	require.Contains(t, raw, "first")
	require.Contains(t, raw, "second")
	require.Contains(t, raw, "third")
}

func TestAudit_TimingNonZero(t *testing.T) {
	result := &PipelineResult{
		Host:       "example.com",
		Method:     "GET",
		Path:       "/",
		StartedAt:  time.Now(),
		Duration:   5 * time.Millisecond,
		Action:     ActionContinue,
		StatusCode: 200,
		RequestTransforms: []TransformTrace{
			{Name: "t1", Action: ActionContinue, Duration: 1 * time.Millisecond},
		},
	}

	parsed, _ := captureAuditLog(result)

	audit := parsed["audit"].(map[string]any)
	require.Greater(t, audit["duration_ms"].(float64), float64(0))
}

func TestAudit_EmptyTransforms(t *testing.T) {
	result := &PipelineResult{
		Host:       "example.com",
		Method:     "GET",
		Path:       "/",
		StartedAt:  time.Now(),
		Duration:   1 * time.Millisecond,
		Action:     ActionContinue,
		StatusCode: 200,
	}

	parsed, _ := captureAuditLog(result)

	require.Equal(t, "INFO", parsed["level"])
	audit := parsed["audit"].(map[string]any)
	require.Equal(t, "allow", audit["action"])
}

// fakeBodyCapture is a test-only implementation of BodyCapture for exercising
// the audit emitters without pulling in the bodycapture package (which would
// cause an import cycle via its dependency on transform).
type fakeBodyCapture struct {
	body      string
	truncated bool
}

func (f *fakeBodyCapture) RequestBody() string        { return f.body }
func (f *fakeBodyCapture) RequestBodyTruncated() bool { return f.truncated }

func TestAudit_BodyCapture_PopulatesTopLevelFields(t *testing.T) {
	result := &PipelineResult{
		Host:        "api.anthropic.com",
		Method:      "POST",
		Path:        "/v1/messages",
		StartedAt:   time.Now(),
		Duration:    1 * time.Millisecond,
		Action:      ActionContinue,
		StatusCode:  200,
		BodyCapture: &fakeBodyCapture{body: `{"prompt":"hi"}`, truncated: false},
	}

	parsed, raw := captureAuditLog(result)

	// request_body / request_body_truncated land at the TOP level of the log
	// record (mirroring the MCP block's position), not inside the `audit`
	// group. ENG-571 / litmus parseIronProxyAudit reads them at root.
	require.Equal(t, `{"prompt":"hi"}`, parsed["request_body"], "raw=%s", raw)
	require.Equal(t, false, parsed["request_body_truncated"])
}

func TestAudit_BodyCapture_TruncationFlagPropagates(t *testing.T) {
	result := &PipelineResult{
		Host:        "api.openai.com",
		Method:      "POST",
		Path:        "/v1/chat/completions",
		StartedAt:   time.Now(),
		Duration:    1 * time.Millisecond,
		Action:      ActionContinue,
		StatusCode:  200,
		BodyCapture: &fakeBodyCapture{body: "xxxxxxxxxxxxxxxx", truncated: true},
	}

	parsed, _ := captureAuditLog(result)

	require.Equal(t, true, parsed["request_body_truncated"])
}

func TestAudit_BodyCapture_NilOmitsFields(t *testing.T) {
	// No body_capture rule matched — BodyCapture is nil. Audit line must
	// NOT include request_body / request_body_truncated fields.
	result := &PipelineResult{
		Host:       "example.com",
		Method:     "GET",
		Path:       "/",
		StartedAt:  time.Now(),
		Duration:   1 * time.Millisecond,
		Action:     ActionContinue,
		StatusCode: 200,
	}

	parsed, raw := captureAuditLog(result)

	_, hasBody := parsed["request_body"]
	require.False(t, hasBody, "request_body should be absent when BodyCapture is nil. raw=%s", raw)
	_, hasFlag := parsed["request_body_truncated"]
	require.False(t, hasFlag, "request_body_truncated should be absent when BodyCapture is nil. raw=%s", raw)
}

func TestAudit_BodyCapture_EmptyBodyOmitsFields(t *testing.T) {
	// BodyCapture is set but RequestBody() is empty (defensive — shouldn't
	// happen in practice because the transform skips empty bodies, but the
	// audit emitter checks `!= ""` too). Audit line must not include the
	// fields.
	result := &PipelineResult{
		Host:        "example.com",
		Method:      "GET",
		Path:        "/",
		StartedAt:   time.Now(),
		Duration:    1 * time.Millisecond,
		Action:      ActionContinue,
		StatusCode:  200,
		BodyCapture: &fakeBodyCapture{body: "", truncated: false},
	}

	parsed, _ := captureAuditLog(result)

	_, hasBody := parsed["request_body"]
	require.False(t, hasBody, "request_body should be absent when RequestBody() is empty")
}
