# ══════════════════════════════════════════════════════════════════════════
#  ATALAYA // Identidad, registro de imágenes y secretos
#  ------------------------------------------------------------------------
#  Todo proyecto de GCP viene con una cuenta de servicio de cómputo por
#  defecto que tiene el rol Editor sobre el proyecto entero. Usarla para
#  correr cargas de trabajo es el hallazgo #1 de cualquier auditoría de GCP.
#  Acá cada servicio tiene su propia identidad con lo mínimo que necesita.
# ══════════════════════════════════════════════════════════════════════════

# ── Registro de imágenes ─────────────────────────────────────────────────

resource "google_artifact_registry_repository" "images" {
  location      = var.region
  repository_id = var.project_name
  description   = "Imágenes de contenedor de ATALAYA"
  format        = "DOCKER"

  # El almacenamiento del registro sí se cobra pasado el nivel gratuito.
  # Esta política borra lo que no está etiquetado y envejeció: las capas
  # huérfanas de builds viejos se acumulan rápido.
  cleanup_policies {
    id     = "borrar-sin-etiqueta"
    action = "DELETE"
    condition {
      tag_state  = "UNTAGGED"
      older_than = "604800s" # 7 días
    }
  }

  cleanup_policies {
    id     = "conservar-ultimas"
    action = "KEEP"
    most_recent_versions {
      keep_count = 10
    }
  }

  depends_on = [google_project_service.apis]
}

# ── Cuentas de servicio ──────────────────────────────────────────────────

resource "google_service_account" "api" {
  account_id   = "${var.project_name}-api"
  display_name = "ATALAYA · API de gamificación"
  description  = "Identidad del servicio Cloud Run de la API"
}

resource "google_service_account" "frontend" {
  account_id   = "${var.project_name}-frontend"
  display_name = "ATALAYA · Consola"
  description  = "Identidad del servicio Cloud Run del frontend"
}

resource "google_service_account" "cti_node" {
  account_id   = "${var.project_name}-cti-node"
  display_name = "ATALAYA · Nodo CTI"
  description  = "Identidad de la VM que hospeda OpenCTI y MISP"
}

# ── Permisos mínimos ─────────────────────────────────────────────────────
# Escribir logs y métricas es lo único que necesita una carga de trabajo
# sana. Todo lo demás se concede recurso por recurso, no a nivel proyecto.

locals {
  telemetry_roles = [
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
  ]

  workload_sas = {
    api      = google_service_account.api.email
    frontend = google_service_account.frontend.email
    cti      = google_service_account.cti_node.email
  }

  telemetry_bindings = {
    for pair in setproduct(keys(local.workload_sas), local.telemetry_roles) :
    "${pair[0]}-${replace(pair[1], "roles/", "")}" => {
      sa   = local.workload_sas[pair[0]]
      role = pair[1]
    }
  }
}

resource "google_project_iam_member" "telemetry" {
  for_each = local.telemetry_bindings

  project = var.project_id
  role    = each.value.role
  member  = "serviceAccount:${each.value.sa}"
}

# El nodo CTI baja imágenes del registro. Sólo lectura, y sólo de ese repo.
resource "google_artifact_registry_repository_iam_member" "cti_puller" {
  location   = google_artifact_registry_repository.images.location
  repository = google_artifact_registry_repository.images.name
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${google_service_account.cti_node.email}"
}

# ══════════════════════════════════════════════════════════════════════════
#  SECRETOS
#  ------------------------------------------------------------------------
#  Terraform crea el CONTENEDOR del secreto, nunca su VALOR.
#
#  Si cargaras el valor acá, quedaría en texto plano dentro del archivo de
#  estado — y el estado se guarda en un bucket que suele tener más lectores
#  que el secreto original. Es el error más común y el más caro.
#
#  Las versiones se cargan fuera de banda, una sola vez:
#
#    echo -n "$(openssl rand -hex 32)" | \
#      gcloud secrets versions add atalaya-api-secret-key --data-file=-
#
#    printf '%s' 'postgresql+asyncpg://user:pass@host/db' | \
#      gcloud secrets versions add atalaya-database-url --data-file=-
#
#  (`echo -n` y `printf '%s'` a propósito: un salto de línea al final del
#  secreto rompe la autenticación de formas muy difíciles de diagnosticar.)
# ══════════════════════════════════════════════════════════════════════════

locals {
  secretos = {
    "api-secret-key" = "Clave de firma de sesiones y JWT de la API"
    "database-url"   = "Cadena de conexión a PostgreSQL (Cloud SQL o Neon)"
    "opencti-token"  = "Token del conector de ingesta hacia OpenCTI"
  }
}

resource "google_secret_manager_secret" "app" {
  for_each = local.secretos

  secret_id = "${var.project_name}-${each.key}"

  labels = {
    component = "api"
  }

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis]
}

# Sólo la API puede leerlos, y sólo estos tres. Nada de
# roles/secretmanager.secretAccessor a nivel proyecto.
resource "google_secret_manager_secret_iam_member" "api_accessor" {
  for_each = google_secret_manager_secret.app

  secret_id = each.value.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.api.email}"
}

# El nodo CTI necesita el token de OpenCTI para que corran los conectores.
resource "google_secret_manager_secret_iam_member" "cti_accessor" {
  secret_id = google_secret_manager_secret.app["opencti-token"].id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.cti_node.email}"
}
