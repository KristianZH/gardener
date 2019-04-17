{{- define "global-network-policies.private-networks-except" -}}
# Seed Nodes
- {{ required "seed.nodes is required" .Values.seed.nodes }}
# Seed Pods
- {{ required "seed.pods is required" .Values.seed.pods }}
# Seed Services
- {{ required "seed.services is required" .Values.seed.services }}
# Shoot Nodes
- {{ required "shoot.nodes is required" .Values.shoot.nodes }}
# Shoot Pods
- {{ required "shoot.pods is required" .Values.shoot.pods }}
# Shoot Services
- {{ required "shoot.services is required" .Values.shoot.services }}
{{- if .Values.metadataService }}
- {{ .Values.metadataService }}
{{- end }}
{{- end -}}