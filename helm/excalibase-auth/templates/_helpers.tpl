{{/*
Expand the name of the chart.
*/}}
{{- define "excalibase-auth.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "excalibase-auth.fullname" -}}
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
Create chart label.
*/}}
{{- define "excalibase-auth.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "excalibase-auth.labels" -}}
helm.sh/chart: {{ include "excalibase-auth.chart" . }}
{{ include "excalibase-auth.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "excalibase-auth.selectorLabels" -}}
app.kubernetes.io/name: {{ include "excalibase-auth.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount name
*/}}
{{- define "excalibase-auth.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "excalibase-auth.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Name of the secret that holds provisioning credentials.
Uses existingSecret if provided, otherwise the chart-managed secret.
*/}}
{{- define "excalibase-auth.secretName" -}}
{{- if .Values.provisioning.existingSecret }}
{{- .Values.provisioning.existingSecret }}
{{- else }}
{{- include "excalibase-auth.fullname" . }}
{{- end }}
{{- end }}
