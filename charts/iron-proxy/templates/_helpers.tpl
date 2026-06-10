{{/*
Expand the name of the chart.
*/}}
{{- define "iron-proxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this
(by the DNS naming spec).
*/}}
{{- define "iron-proxy.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "iron-proxy.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "iron-proxy.labels" -}}
helm.sh/chart: {{ include "iron-proxy.chart" . }}
{{ include "iron-proxy.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "iron-proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "iron-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use.
*/}}
{{- define "iron-proxy.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "iron-proxy.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
The name of the chart-managed Secret holding inline secretEnv values.
*/}}
{{- define "iron-proxy.secretEnvName" -}}
{{- printf "%s-env" (include "iron-proxy.fullname" .) }}
{{- end }}

{{/*
The name of the chart-managed Secret holding the inline CA cert/key.
*/}}
{{- define "iron-proxy.caSecretName" -}}
{{- printf "%s-ca" (include "iron-proxy.fullname" .) }}
{{- end }}

{{/*
The name of the chart-managed Secret holding the inline control-plane token.
*/}}
{{- define "iron-proxy.tokenSecretName" -}}
{{- printf "%s-token" (include "iron-proxy.fullname" .) }}
{{- end }}

{{/*
Resolve the metrics port number from listeners.metrics, used by the named
"metrics" container port that probes and the ServiceMonitor target.
*/}}
{{- define "iron-proxy.metricsPort" -}}
{{- .Values.listeners.metrics.port | default 9090 }}
{{- end }}

{{/*
Listener environment variables, emitted in BOTH standalone and managed mode so
.Values.listeners is the single source of truth for ports: the proxy binds exactly
what the Service exposes. Listen addresses are set via IRON_*_LISTEN (env overrides
apply on top of any config file), and the DNS server is turned off with
IRON_DNS_ENABLED=false when listeners.dns is disabled.

Only listeners with a real env override are emitted here. postgres and management
have no general env override: postgres is driven by the control plane in managed
mode (IRON_PROXY_PG_LISTEN) and by the config block in standalone mode; management
is standalone-only and set from the config block.
*/}}
{{- define "iron-proxy.listenerEnv" -}}
{{- $l := .Values.listeners -}}
{{- if $l.dns.enabled }}
- name: IRON_DNS_LISTEN
  value: {{ printf ":%v" (int $l.dns.port) | quote }}
{{- else }}
- name: IRON_DNS_ENABLED
  value: "false"
{{- end }}
{{- if $l.http.enabled }}
- name: IRON_PROXY_HTTP_LISTEN
  value: {{ printf ":%v" (int $l.http.port) | quote }}
{{- end }}
{{- if $l.https.enabled }}
- name: IRON_PROXY_HTTPS_LISTEN
  value: {{ printf ":%v" (int $l.https.port) | quote }}
{{- end }}
{{- if $l.tunnel.enabled }}
- name: IRON_PROXY_TUNNEL_LISTEN
  value: {{ printf ":%v" (int $l.tunnel.port) | quote }}
{{- end }}
{{- if $l.metrics.enabled }}
- name: IRON_METRICS_LISTEN
  value: {{ printf ":%v" (int $l.metrics.port) | quote }}
{{- end }}
{{- if and (eq .Values.mode "managed") $l.postgres.enabled }}
- name: IRON_PROXY_PG_LISTEN
  value: {{ printf ":%v" (int $l.postgres.port) | quote }}
{{- end }}
{{- end }}

{{/*
Managed-mode-only environment variables. In managed mode there is no config file,
so proxy_ip, TLS, and logging are supplied via IRON_* env vars; CA paths are derived
from the CA mount. The control-plane token is emitted separately by the Deployment
(it uses a secretKeyRef). Listen addresses come from iron-proxy.listenerEnv.
*/}}
{{- define "iron-proxy.managedEnv" -}}
{{- with .Values.managed.controlPlaneURL }}
- name: IRON_CONTROL_PLANE_URL
  value: {{ . | quote }}
{{- end }}
{{- with .Values.managed.proxyIP }}
- name: IRON_DNS_PROXY_IP
  value: {{ . | quote }}
{{- end }}
{{- with .Values.managed.tlsMode }}
- name: IRON_TLS_MODE
  value: {{ . | quote }}
{{- end }}
{{- with .Values.managed.logLevel }}
- name: IRON_LOG_LEVEL
  value: {{ . | quote }}
{{- end }}
{{- with .Values.managed.upstreamResolver }}
- name: IRON_DNS_UPSTREAM_RESOLVER
  value: {{ . | quote }}
{{- end }}
{{- if ne .Values.ca.mode "none" }}
- name: IRON_TLS_CA_CERT
  value: "/etc/iron-proxy/tls/ca.crt"
- name: IRON_TLS_CA_KEY
  value: "/etc/iron-proxy/tls/ca.key"
{{- end }}
{{- end }}
