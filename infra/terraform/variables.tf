# ══════════════════════════════════════════════════════════════════════
#  ATALAYA // Variables de entrada (GCP)
# ══════════════════════════════════════════════════════════════════════

variable "project_id" {
  description = "ID del proyecto de GCP. No es el nombre para mostrar: es el ID."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id inválido: 6-30 caracteres, minúsculas, números y guiones."
  }
}

variable "region" {
  description = <<-EOT
    Región de despliegue. us-central1 es la que más servicios tiene en el
    nivel gratuito de Cloud Run; si la cambiás, verificá el free tier.
  EOT
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "Zona para recursos zonales (el nodo CTI)."
  type        = string
  default     = "us-central1-a"
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
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment debe ser dev, staging o prod."
  }
}

# ── Red ───────────────────────────────────────────────────────────────

variable "subnet_cidr" {
  description = "Rango de la subred principal (nodo CTI y egreso de Cloud Run)."
  type        = string
  default     = "10.42.0.0/24"

  validation {
    condition     = can(cidrhost(var.subnet_cidr, 0))
    error_message = "subnet_cidr debe ser un bloque CIDR IPv4 válido."
  }
}

variable "enable_flow_logs" {
  description = "VPC Flow Logs en la subred. En un proyecto de CTI, obligatorio."
  type        = bool
  default     = true
}

variable "flow_log_sampling" {
  description = "Fracción de flujos registrados (0.0-1.0). 0.5 equilibra costo y visibilidad."
  type        = number
  default     = 0.5

  validation {
    condition     = var.flow_log_sampling > 0 && var.flow_log_sampling <= 1
    error_message = "flow_log_sampling debe estar en (0.0, 1.0]."
  }
}

# ── Acceso ────────────────────────────────────────────────────────────

variable "admin_cidrs" {
  description = <<-EOT
    Rangos autorizados a alcanzar los puertos de administración del nodo CTI
    (OpenCTI 8080, MISP 8443, SpiderFoot 5001).

    NO tiene valor por defecto a propósito: obligar a declararlo evita el
    clásico "lo abro a todos por ahora" que queda para siempre.
    Obtené el tuyo con:  curl -s https://ifconfig.me
    Ejemplo: ["203.0.113.10/32"]
  EOT
  type        = list(string)

  validation {
    condition     = length(var.admin_cidrs) > 0
    error_message = "admin_cidrs no puede estar vacío."
  }

  validation {
    # Los puertos de administración de una plataforma de inteligencia jamás
    # van abiertos a Internet. Para SSH ya está IAP; para las consolas web,
    # un rango fijo o VPN.
    condition     = !contains(var.admin_cidrs, "0.0.0.0/0")
    error_message = "admin_cidrs no admite 0.0.0.0/0. Usá IAP, VPN o un rango fijo."
  }

  validation {
    condition     = alltrue([for c in var.admin_cidrs : can(cidrhost(c, 0))])
    error_message = "Todos los elementos de admin_cidrs deben ser CIDRs válidos."
  }
}

variable "allow_public_console" {
  description = <<-EOT
    Si es true, la consola (frontend en Cloud Run) queda accesible sin
    autenticación de IAM. Es lo que querés para una demo pública.
    Poné false y el acceso pasa a requerir identidad de Google.
  EOT
  type        = bool
  default     = true
}

# ── Imágenes de contenedor ────────────────────────────────────────────

variable "api_image" {
  description = <<-EOT
    Imagen completa de la API. Vacío = imagen placeholder de Google, para que
    el primer `apply` funcione antes de que exista tu build.
    Después: REGION-docker.pkg.dev/PROJECT/atalaya/api:TAG
  EOT
  type        = string
  default     = ""
}

variable "frontend_image" {
  description = <<-EOT
    Imagen completa del frontend. Vacío = placeholder.

    OJO: NEXT_PUBLIC_API_URL se resuelve en tiempo de BUILD, no de runtime
    (Next lo incrusta en el bundle del navegador). La URL de la API tiene que
    pasarse como --build-arg al construir la imagen, no como variable de
    entorno de Cloud Run. Ver el output `comandos_build`.
  EOT
  type        = string
  default     = ""
}

# ── Cloud Run ─────────────────────────────────────────────────────────

variable "cors_origins_extra" {
  description = <<-EOT
    Orígenes adicionales permitidos por CORS, además de la URL que Cloud Run
    le asigna al frontend.

    Existe porque el formato de las URLs de Cloud Run NO es estable entre
    proyectos: hay servicios que reciben `servicio-NUMERO.region.run.app` y
    otros el formato viejo con hash. Terraform arma la primera forma, pero si
    tu proyecto usa la otra —o si ponés un dominio propio— agregala acá.

    Comprobalo después del primer apply:
      terraform output consola_url
  EOT
  type        = list(string)
  default     = []
}

variable "max_instances" {
  description = <<-EOT
    Tope de instancias por servicio. Es el freno de mano contra la factura:
    sin tope, un pico de tráfico (o un bucle) escala sin límite.
  EOT
  type        = number
  default     = 3

  validation {
    condition     = var.max_instances >= 1 && var.max_instances <= 100
    error_message = "max_instances debe estar entre 1 y 100."
  }
}

variable "cpu_limit" {
  description = "CPU por instancia de Cloud Run."
  type        = string
  default     = "1"
}

variable "memory_limit" {
  description = "Memoria por instancia de Cloud Run."
  type        = string
  default     = "512Mi"
}

# ── Base de datos ─────────────────────────────────────────────────────

variable "enable_cloud_sql" {
  description = <<-EOT
    Levanta Cloud SQL para PostgreSQL con IP privada.

    Por defecto FALSE: Cloud SQL no tiene nivel gratuito. La ruta de costo
    cero es un Postgres serverless externo (Neon, Supabase) cuya cadena de
    conexión se carga en el secreto `database-url`. La API no nota la
    diferencia: consume un DATABASE_URL y nada más.
  EOT
  type        = bool
  default     = false
}

variable "cloud_sql_tier" {
  description = "Tamaño de la instancia de Cloud SQL."
  type        = string
  default     = "db-f1-micro"
}

variable "cloud_sql_deletion_protection" {
  description = "Impide destruir la base por accidente. Poné false sólo en dev."
  type        = bool
  default     = true
}

# ── Nodo CTI ──────────────────────────────────────────────────────────

variable "enable_cti_node" {
  description = <<-EOT
    Levanta la VM que hospeda OpenCTI + MISP vía Docker Compose.

    Por defecto FALSE, y con razón: el stack pide ~8 GB de RAM sostenidos.
    No entra en ningún nivel gratuito. Encendelo cuando sepas que lo vas a
    usar, y apagalo cuando termines.
  EOT
  type        = bool
  default     = false
}

variable "cti_machine_type" {
  description = "Tipo de máquina del nodo CTI. OpenCTI + ElasticSearch piden >= 8 GB."
  type        = string
  default     = "e2-standard-2"
}

variable "cti_disk_gb" {
  description = "Disco del nodo CTI."
  type        = number
  default     = 100
}

# ── Etiquetado ────────────────────────────────────────────────────────

variable "extra_labels" {
  description = "Etiquetas adicionales. Sólo minúsculas, números, guiones y guiones bajos."
  type        = map(string)
  default     = {}
}
