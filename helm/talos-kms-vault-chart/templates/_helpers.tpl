{{/*
Expand the name of the chart.
*/}}
{{- define "talos-kms-vault.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "talos-kms-vault.fullname" -}}
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
{{- define "talos-kms-vault.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "talos-kms-vault.labels" -}}
helm.sh/chart: {{ include "talos-kms-vault.chart" . }}
{{ include "talos-kms-vault.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "talos-kms-vault.selectorLabels" -}}
app.kubernetes.io/name: {{ include "talos-kms-vault.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "talos-kms-vault.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "talos-kms-vault.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the image name
*/}}
{{- define "talos-kms-vault.image" -}}
{{- $registry := .Values.global.imageRegistry | default .Values.image.registry }}
{{- $repository := .Values.image.repository }}
{{- $tag := .Values.image.tag | default .Chart.AppVersion }}
{{- printf "%s/%s:%s" $registry $repository $tag }}
{{- end }}

{{/*
Generate environment variables for Vault authentication
*/}}
{{- define "talos-kms-vault.vaultEnv" -}}
- name: VAULT_ADDR
  value: {{ .Values.vault.addr | quote }}
- name: VAULT_AUTH_METHOD
  value: {{ .Values.vault.auth.method | quote }}
{{- if eq .Values.vault.auth.method "token" }}
{{- if .Values.vault.auth.token.secretName }}
- name: VAULT_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ .Values.vault.auth.token.secretName }}
      key: {{ .Values.vault.auth.token.secretKey | default "token" }}
{{- else if .Values.vault.auth.token.value }}
- name: VAULT_TOKEN
  value: {{ .Values.vault.auth.token.value | quote }}
{{- end }}
{{- else if eq .Values.vault.auth.method "kubernetes" }}
- name: VAULT_K8S_ROLE
  value: {{ .Values.vault.auth.kubernetes.role | quote }}
{{- if .Values.vault.auth.kubernetes.mountPath }}
- name: VAULT_K8S_MOUNT_PATH
  value: {{ .Values.vault.auth.kubernetes.mountPath | quote }}
{{- end }}
{{- else if eq .Values.vault.auth.method "approle" }}
{{- if .Values.vault.auth.approle.roleIdSecret.name }}
- name: VAULT_ROLE_ID
  valueFrom:
    secretKeyRef:
      name: {{ .Values.vault.auth.approle.roleIdSecret.name }}
      key: {{ .Values.vault.auth.approle.roleIdSecret.key }}
{{- else if .Values.vault.auth.approle.roleId }}
- name: VAULT_ROLE_ID
  value: {{ .Values.vault.auth.approle.roleId | quote }}
{{- end }}
{{- if .Values.vault.auth.approle.secretIdSecret.name }}
- name: VAULT_SECRET_ID
  valueFrom:
    secretKeyRef:
      name: {{ .Values.vault.auth.approle.secretIdSecret.name }}
      key: {{ .Values.vault.auth.approle.secretIdSecret.key }}
{{- else if .Values.vault.auth.approle.secretId }}
- name: VAULT_SECRET_ID
  value: {{ .Values.vault.auth.approle.secretId | quote }}
{{- end }}
{{- if .Values.vault.auth.approle.mountPath }}
- name: VAULT_APPROLE_MOUNT_PATH
  value: {{ .Values.vault.auth.approle.mountPath | quote }}
{{- end }}
{{- end }}
{{- if not .Values.vault.autoRenew }}
- name: VAULT_AUTO_RENEW
  value: "false"
{{- end }}
{{- end }}

{{/*
Generate command line arguments
*/}}
{{- define "talos-kms-vault.args" -}}
- --kms-api-endpoint={{ .Values.config.apiEndpoint }}
- --mount-path={{ .Values.config.mountPath }}
{{- if not .Values.config.validation.enabled }}
- --disable-validation=true
{{- end }}
{{- if .Values.config.validation.allowUUIDVersions }}
- --allow-uuid-versions={{ .Values.config.validation.allowUUIDVersions }}
{{- end }}
{{- if .Values.config.validation.disableEntropyCheck }}
- --disable-entropy-check=true
{{- end }}
{{- if .Values.config.tls.enabled }}
- --enable-tls=true
- --tls-cert={{ .Values.config.tls.certPath }}
- --tls-key={{ .Values.config.tls.keyPath }}
{{- end }}
{{- if .Values.config.leaderElection.enabled }}
- --enable-leader-election=true
- --leader-election-namespace={{ .Values.config.leaderElection.namespace | default .Release.Namespace }}
- --leader-election-name={{ .Values.config.leaderElection.name }}
- --leader-election-lease-duration={{ .Values.config.leaderElection.leaseDuration }}
- --leader-election-renew-deadline={{ .Values.config.leaderElection.renewDeadline }}
- --leader-election-retry-period={{ .Values.config.leaderElection.retryPeriod }}
{{- end }}
{{- end }}