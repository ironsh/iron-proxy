package broker

import (
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// metrics owns the broker's Prometheus instruments. All instruments are
// labeled with credential_id so operators can alert per-credential.
type metrics struct {
	reg *prometheus.Registry

	refreshAttempts  *prometheus.CounterVec
	refreshDuration  *prometheus.HistogramVec
	httpRequests     *prometheus.CounterVec
	httpDuration     *prometheus.HistogramVec
	dead             *prometheus.GaugeVec
	tokenAge         *prometheus.GaugeVec
	timeToExpiry     *prometheus.GaugeVec

	// observableMu guards observable Gauge state mutated by the
	// per-credential goroutines.
	observableMu sync.Mutex
}

func newMetrics() *metrics {
	reg := prometheus.NewRegistry()
	m := &metrics{
		reg: reg,
		refreshAttempts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "broker_refresh_attempts_total",
			Help: "Number of refresh attempts by credential, result, and error code.",
		}, []string{"credential_id", "result", "error_code"}),
		refreshDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "broker_refresh_duration_seconds",
			Help:    "Duration of refresh attempts by credential and result.",
			Buckets: prometheus.DefBuckets,
		}, []string{"credential_id", "result"}),
		httpRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "broker_http_requests_total",
			Help: "Number of HTTP requests to the broker API by endpoint and status.",
		}, []string{"endpoint", "status"}),
		httpDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "broker_http_request_duration_seconds",
			Help:    "Duration of HTTP requests to the broker API by endpoint and status.",
			Buckets: prometheus.DefBuckets,
		}, []string{"endpoint", "status"}),
		dead: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "broker_credential_dead",
			Help: "1 when the credential is structurally dead (needs human re-auth); 0 otherwise. Labelled with the reason when set.",
		}, []string{"credential_id", "reason"}),
		tokenAge: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "broker_token_age_seconds",
			Help: "Seconds since the credential's access token was last refreshed.",
		}, []string{"credential_id"}),
		timeToExpiry: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "broker_token_time_to_expiry_seconds",
			Help: "Seconds until the credential's access token expires; negative if past expiry.",
		}, []string{"credential_id"}),
	}
	reg.MustRegister(
		m.refreshAttempts,
		m.refreshDuration,
		m.httpRequests,
		m.httpDuration,
		m.dead,
		m.tokenAge,
		m.timeToExpiry,
	)
	return m
}

// Handler returns the HTTP handler that exposes the broker's metrics in
// Prometheus text format. Mount under /metrics on the metrics server.
func (m *metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{Registry: m.reg})
}

func (m *metrics) recordRefresh(credentialID, result, errorCode string, elapsed time.Duration) {
	m.refreshAttempts.WithLabelValues(credentialID, result, errorCode).Inc()
	m.refreshDuration.WithLabelValues(credentialID, result).Observe(elapsed.Seconds())
}

func (m *metrics) recordHTTPRequest(endpoint, status string, elapsed time.Duration) {
	m.httpRequests.WithLabelValues(endpoint, status).Inc()
	m.httpDuration.WithLabelValues(endpoint, status).Observe(elapsed.Seconds())
}

// setTokenWindow updates the observable token-age and time-to-expiry
// gauges for one credential. Called from the credential loop after every
// successful refresh; never called from request handlers (the snapshot
// would race with the refresh write).
func (m *metrics) setTokenWindow(credentialID string, lastRefresh, expiresAt, now time.Time) {
	m.observableMu.Lock()
	defer m.observableMu.Unlock()
	m.tokenAge.WithLabelValues(credentialID).Set(now.Sub(lastRefresh).Seconds())
	m.timeToExpiry.WithLabelValues(credentialID).Set(expiresAt.Sub(now).Seconds())
}

// setDead marks a credential as structurally dead (1) or alive (0). The
// reason label distinguishes invalid_grant from store-conflict and friends
// so dashboards can group by cause.
func (m *metrics) setDead(credentialID, reason string, dead bool) {
	v := 0.0
	if dead {
		v = 1.0
	}
	m.dead.WithLabelValues(credentialID, reason).Set(v)
}

// resultLabel maps a refresh outcome onto the metric label value. Kept
// out of the call sites so the strings live in one place.
const (
	resultSuccess      = "success"
	resultTransient    = "transient_error"
	resultUnrecoverable = "unrecoverable_error"
)
