package transform

import (
	"context"
	"encoding/json"
	"time"

	"go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

const instrumentationName = "iron-proxy/audit"

// NewOTELAuditFunc returns an AuditFunc that emits structured OTEL log records
// for every proxied request. The log records use the schema:
//
//	{
//	  "host": "httpbin.org",
//	  "method": "GET",
//	  "path": "/headers",
//	  "action": "allow",
//	  "status_code": 200,
//	  "duration_ms": 142,
//	  "request_transforms": [...],
//	  "response_transforms": [...]
//	}
func NewOTELAuditFunc(provider *sdklog.LoggerProvider) AuditFunc {
	logger := provider.Logger(instrumentationName)

	return func(result *PipelineResult) {
		action := actionString(result.Action)
		if result.Err != nil {
			action = "error"
		}

		var rec log.Record
		rec.SetTimestamp(result.StartedAt)
		rec.SetObservedTimestamp(time.Now())
		rec.SetBody(log.StringValue("request"))
		rec.SetSeverity(otelSeverity(result))
		rec.SetSeverityText(otelSeverityText(result))

		attrs := []log.KeyValue{
			log.String("host", result.Host),
			log.String("method", result.Method),
			log.String("path", result.Path),
			log.String("remote_addr", result.RemoteAddr),
			log.String("sni", result.SNI),
			log.String("mode", result.Mode.String()),
			log.String("action", action),
			log.Int("status_code", result.StatusCode),
			log.Float64("duration_ms", float64(result.Duration.Microseconds())/1000.0),
		}

		if result.Action == ActionReject {
			for _, tr := range result.RequestTransforms {
				if tr.Action == ActionReject {
					attrs = append(attrs, log.String("rejected_by", tr.Name))
					break
				}
			}
		}

		if result.Err != nil {
			attrs = append(attrs, log.String("error", result.Err.Error()))
		}

		if len(result.RequestTransforms) > 0 {
			attrs = append(attrs, log.KeyValue{
				Key:   "request_transforms",
				Value: transformTracesValue(result.RequestTransforms),
			})
		}
		if len(result.ResponseTransforms) > 0 {
			attrs = append(attrs, log.KeyValue{
				Key:   "response_transforms",
				Value: transformTracesValue(result.ResponseTransforms),
			})
		}

		rec.AddAttributes(attrs...)
		logger.Emit(context.Background(), rec)
	}
}

// ChainAuditFuncs returns an AuditFunc that calls all provided funcs in order.
func ChainAuditFuncs(funcs ...AuditFunc) AuditFunc {
	return func(result *PipelineResult) {
		for _, f := range funcs {
			f(result)
		}
	}
}

func otelSeverity(result *PipelineResult) log.Severity {
	switch {
	case result.Err != nil:
		return log.SeverityError1
	case result.Action == ActionReject:
		return log.SeverityWarn1
	default:
		return log.SeverityInfo1
	}
}

func otelSeverityText(result *PipelineResult) string {
	switch {
	case result.Err != nil:
		return "ERROR"
	case result.Action == ActionReject:
		return "WARN"
	default:
		return "INFO"
	}
}

// transformTracesValue converts a slice of TransformTrace into an OTEL log
// Slice of Maps, preserving the nested structure for downstream analysis.
func transformTracesValue(traces []TransformTrace) log.Value {
	vals := make([]log.Value, len(traces))
	for i, tr := range traces {
		kvs := []log.KeyValue{
			log.String("name", tr.Name),
			log.String("action", traceActionString(tr)),
			log.Float64("duration_ms", float64(tr.Duration.Microseconds())/1000.0),
		}

		if tr.Err != nil {
			kvs = append(kvs, log.String("error", tr.Err.Error()))
		}

		if len(tr.Annotations) > 0 {
			kvs = append(kvs, log.KeyValue{
				Key:   "annotations",
				Value: annotationsValue(tr.Annotations),
			})
		}

		vals[i] = log.MapValue(kvs...)
	}
	return log.SliceValue(vals...)
}

// annotationsValue converts an arbitrary map[string]any into an OTEL log Value.
// Since annotations can contain nested structures (e.g. swapped secret lists),
// we JSON-encode the entire map as a string for maximum compatibility with
// OTEL backends.
func annotationsValue(annotations map[string]any) log.Value {
	data, err := json.Marshal(annotations)
	if err != nil {
		return log.StringValue("{}")
	}
	return log.StringValue(string(data))
}
