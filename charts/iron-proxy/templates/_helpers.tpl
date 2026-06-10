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
Managed-mode environment variables. In managed mode there is no config file, so
listen addresses, proxy_ip, TLS, and logging are supplied via IRON_* env vars.
Listen addresses come from .Values.listeners so they match the Service; CA paths
are derived from the CA mount. The control-plane token is emitted separately by
the Deployment (it uses a secretKeyRef). Excludes management (no env override).
*/}}
{{- define "iron-proxy.managedEnv" -}}
{{- $l := .Values.listeners -}}
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
{{- if $l.dns.enabled }}
- name: IRON_DNS_LISTEN
  value: {{ printf ":%v" (int $l.dns.port) | quote }}
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
{{- if $l.postgres.enabled }}
- name: IRON_PROXY_PG_LISTEN
  value: {{ printf ":%v" (int $l.postgres.port) | quote }}
{{- end }}
{{- end }}
