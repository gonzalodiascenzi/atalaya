# ══════════════════════════════════════════════════════════════════════
#  ATALAYA // Variables de entrada (AWS)
# ══════════════════════════════════════════════════════════════════════

variable "region" {
  description = "Región. us-east-1 porque CloudFront sólo acepta certificados de ahí."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Prefijo de los recursos."
  type        = string
  default     = "atalaya"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,20}$", var.project_name))
    error_message = "project_name: minúsculas, números y guiones; entre 3 y 21 caracteres."
  }
}

variable "environment" {
  description = "Entorno lógico del despliegue."
  type        = string
  default     = "prod"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment debe ser dev, staging o prod."
  }
}

# ── Identidad de GitHub (OIDC) ────────────────────────────────────────

variable "github_owner" {
  description = "Dueño del repositorio en GitHub."
  type        = string
  default     = "gonzalodiascenzi"
}

variable "github_repo" {
  description = "Nombre del repositorio."
  type        = string
  default     = "atalaya"
}

variable "github_owner_id" {
  description = <<-EOT
    ID numérico del dueño. El repo usa sujeto OIDC INMUTABLE: GitHub firma
    `repo:dueño@ID/repo@ID:...`, así que el rol se ata a los IDs y no sólo a
    los nombres. Si alguien re-registrara el nombre, no podría asumirlo.
    Se obtiene con: gh api repos/DUEÑO/REPO --jq .owner.id
  EOT
  type        = number
  default     = 88945030
}

variable "github_repo_id" {
  description = "ID numérico del repo (gh api repos/DUEÑO/REPO --jq .id)."
  type        = number
  default     = 1365053110
}

variable "github_deploy_branch" {
  description = "Única rama que puede desplegar."
  type        = string
  default     = "main"
}

# ── Lambda ────────────────────────────────────────────────────────────

variable "api_image_tag" {
  description = <<-EOT
    Tag de la imagen en ECR. Los tags son INMUTABLES: cada commit publica
    `sha-xxxxxxx`, y un tag ya publicado no se puede sobrescribir — nadie puede
    reemplazar en silencio lo que está corriendo.
  EOT
  type        = string
  default     = "arranque"
}

variable "lambda_memory_mb" {
  description = <<-EOT
    Memoria de la API. En Lambda la CPU escala con la memoria: con 1024 MB el
    arranque en frío de FastAPI baja a la mitad que con 512, y el nivel
    gratuito (400.000 GB-s/mes) sigue cubriendo de sobra el tráfico de demo.
  EOT
  type        = number
  default     = 1024
}

variable "log_retention_days" {
  description = <<-EOT
    Días de retención de logs. El valor por defecto de CloudWatch es "para
    siempre", que es una factura que crece sola sin que nadie la mire.
  EOT
  type        = number
  default     = 14
}
