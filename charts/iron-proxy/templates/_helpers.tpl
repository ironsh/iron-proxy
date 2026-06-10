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
Resolve the metrics port number from service.ports.metrics, used by the named
"metrics" container port that probes and the ServiceMonitor target.
*/}}
{{- define "iron-proxy.metricsPort" -}}
{{- .Values.service.ports.metrics.targetPort | default 9090 }}
{{- end }}
