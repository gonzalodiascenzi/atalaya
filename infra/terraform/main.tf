# ══════════════════════════════════════════════════════════════════════════
#  ATALAYA // Infraestructura en AWS
#  ------------------------------------------------------------------------
#
#     navegador ──HTTPS──▶ CloudFront ──┬── /*      ──▶ S3 (consola estática)
#                                        └── /api/* ──▶ Lambda (FastAPI)
#                                                          │
#                                                          └──▶ Neon (Postgres)
#
#  Por qué así, y no otra cosa:
#
#  · Mismo dominio para la consola y la API → las cookies de sesión con
#    SameSite=strict funcionan y no hace falta CORS. Dos dominios habrían
#    obligado a relajar SameSite, o sea a debilitar la defensa contra CSRF.
#  · Lambda en vez de App Runner: App Runner no acepta clientes nuevos desde
#    el 30/04/2026. En vez de ECS: Lambda se apaga sola sin tráfico.
#  · Costo esperado ≈ $0: Lambda y CloudFront tienen nivel gratuito que no
#    vence; S3 y ECR cuestan centavos; Neon es gratis.
#
#  Los SECRETOS no pasan por acá. Viven en SSM Parameter Store (gratis en el
#  nivel estándar), se cargan con la CLI, y Terraform sólo conoce sus NOMBRES
#  para dar permiso de lectura. Si los creara Terraform, sus valores quedarían
#  en texto plano en el archivo de estado.
# ══════════════════════════════════════════════════════════════════════════

locals {
  name = "${var.project_name}-${var.environment}"

  common_tags = {
    Project     = "ATALAYA"
    Environment = var.environment
    ManagedBy   = "terraform"
    Repository  = "${var.github_owner}/${var.github_repo}"
  }

  # Nombres de los secretos en SSM. Terraform no crea ni lee sus valores.
  ssm_prefix         = "/${var.project_name}/${var.environment}"
  ssm_database_url   = "${local.ssm_prefix}/database-url"
  ssm_api_secret_key = "${local.ssm_prefix}/api-secret-key"
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# El proveedor OIDC de GitHub YA existe en la cuenta (lo creó otro proyecto).
# Se referencia, no se crea: AWS no admite dos proveedores con la misma URL y
# el apply fallaría con EntityAlreadyExists.
data "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
}
