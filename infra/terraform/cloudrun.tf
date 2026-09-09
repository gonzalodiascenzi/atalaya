# ══════════════════════════════════════════════════════════════════════════
#  ATALAYA // Cloud Run: la API y la consola
#  ------------------------------------------------------------------------
#  Por qué Cloud Run y no una VM: escala a cero. Un proyecto de entrenamiento
#  recibe visitas a ráfagas; pagar una máquina prendida 24/7 para servir
#  tráfico intermitente es tirar plata. Además corre los Dockerfiles del repo
#  tal cual están, sin adaptación.
# ══════════════════════════════════════════════════════════════════════════

# ── API de gamificación ──────────────────────────────────────────────────

resource "google_cloud_run_v2_service" "api" {
  name        = "${local.name}-api"
  location    = var.region
  description = "Feed de Misiones (STIX 2.1) y motor de progresión"

  # En dev conviene poder destruir sin pelear. En prod, ponelo en true.
  deletion_protection = var.environment == "prod"

  # El navegador del analista llama a esta API directamente, así que el
  # ingreso tiene que ser público.
  #
  # ⚠️ DEUDA CONOCIDA: hasta que aterrice la autenticación (Etapa 2), el
  # endpoint /api/v1/level-up acepta cualquier callsign en el cuerpo. Público
  # + sin auth = cualquiera se asciende a CAZADOR con un curl. Mientras tanto,
  # tratá este despliegue como una demo, no como un entorno con puntaje real.
  ingress = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.api.email

    scaling {
      min_instance_count = 0 # escala a cero: sin tráfico, sin costo
      max_instance_count = var.max_instances
    }

    containers {
      image = local.api_image

      ports {
        container_port = 8000
      }

      resources {
        limits = {
          cpu    = var.cpu_limit
          memory = var.memory_limit
        }
        # La CPU se libera entre peticiones. Es lo que hace que el escalado a
        # cero salga barato de verdad.
        cpu_idle = true
      }

      env {
        name  = "ATALAYA_ENV"
        value = var.environment
      }

      env {
        name  = "API_LOG_LEVEL"
        value = var.environment == "prod" ? "warning" : "info"
      }

      # ⚠️ La URL del frontend se ARMA a mano en vez de referenciar
      # `google_cloud_run_v2_service.frontend.uri`, porque esa referencia
      # crearía un ciclo: el frontend ya depende de la URI de la API.
      #
      # El riesgo es que el formato de URL de Cloud Run no es idéntico en
      # todos los proyectos. Si al abrir la consola el navegador bloquea las
      # llamadas por CORS, la causa es ésta: pasá la URL real —la que devuelve
      # `terraform output consola_url`— en la variable `cors_origins_extra`.
      env {
        name = "API_CORS_ORIGINS"
        value = join(",", concat(
          ["https://${local.name}-frontend-${data.google_project.current.number}.${var.region}.run.app"],
          var.cors_origins_extra
        ))
      }

      # Los secretos se inyectan por referencia, nunca por valor. El contenedor
      # los recibe como variables de entorno pero jamás aparecen en el plan,
      # en el estado ni en la definición del servicio.
      env {
        name = "API_SECRET_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.app["api-secret-key"].secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "DATABASE_URL"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.app["database-url"].secret_id
            version = "latest"
          }
        }
      }

      # Sonda de arranque: Cloud Run no manda tráfico hasta que /health
      # responde. Sin esto, las primeras peticiones de un arranque en frío
      # se comen un 503.
      # Arranque: /health/ready SÍ consulta PostgreSQL. No queremos recibir
      # tráfico antes de poder registrar la progresión de nadie.
      startup_probe {
        http_get {
          path = "/health/ready"
        }
        initial_delay_seconds = 5
        timeout_seconds       = 3
        period_seconds        = 5
        failure_threshold     = 12
      }

      # Vida: /health NO toca la base. Si la sonda de vida dependiera de
      # PostgreSQL, un parpadeo de la base reiniciaría instancias sanas y
      # convertiría una degradación en una caída.
      liveness_probe {
        http_get {
          path = "/health"
        }
        period_seconds    = 30
        timeout_seconds   = 3
        failure_threshold = 3
      }
    }

    # Egreso directo a la VPC. Necesario para alcanzar Cloud SQL por IP
    # privada o el nodo CTI. `PRIVATE_RANGES_ONLY` deja que el tráfico a
    # Internet siga saliendo por la ruta de Cloud Run, que es más barata que
    # hacerlo pasar por el NAT.
    vpc_access {
      network_interfaces {
        network    = google_compute_network.main.id
        subnetwork = google_compute_subnetwork.main.id
      }
      egress = "PRIVATE_RANGES_ONLY"
    }

    timeout = "60s"
  }

  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }

  depends_on = [
    google_project_service.apis,
    google_secret_manager_secret_iam_member.api_accessor,
  ]
}

# ── Consola (frontend) ───────────────────────────────────────────────────

resource "google_cloud_run_v2_service" "frontend" {
  name        = "${local.name}-frontend"
  location    = var.region
  description = "Consola de operaciones ATALAYA"

  deletion_protection = var.environment == "prod"
  ingress             = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.frontend.email

    scaling {
      min_instance_count = 0
      max_instance_count = var.max_instances
    }

    containers {
      image = local.frontend_image

      ports {
        container_port = 3000
      }

      resources {
        limits = {
          cpu    = var.cpu_limit
          memory = var.memory_limit
        }
        cpu_idle = true
      }

      env {
        name  = "NODE_ENV"
        value = "production"
      }

      # ⚠️ Esta variable acá NO alcanza. Next incrusta las NEXT_PUBLIC_* en el
      # bundle del navegador durante el BUILD, así que la URL de la API tiene
      # que ir como --build-arg al construir la imagen. Se deja declarada
      # porque el servidor de Next también la lee, pero la que manda para el
      # cliente es la del build. Ver el output `comandos_build`.
      env {
        name  = "NEXT_PUBLIC_API_URL"
        value = google_cloud_run_v2_service.api.uri
      }

      startup_probe {
        http_get {
          path = "/"
        }
        initial_delay_seconds = 5
        timeout_seconds       = 3
        period_seconds        = 5
        failure_threshold     = 6
      }
    }

    timeout = "30s"
  }

  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }

  depends_on = [google_project_service.apis]
}

# ── Quién puede invocar ──────────────────────────────────────────────────
# `allUsers` significa "sin autenticación de IAM", que es lo que necesita una
# demo pública. Con allow_public_console = false, el acceso pasa a requerir
# una identidad de Google válida.

resource "google_cloud_run_v2_service_iam_member" "frontend_public" {
  count = var.allow_public_console ? 1 : 0

  project  = google_cloud_run_v2_service.frontend.project
  location = google_cloud_run_v2_service.frontend.location
  name     = google_cloud_run_v2_service.frontend.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

resource "google_cloud_run_v2_service_iam_member" "api_public" {
  count = var.allow_public_console ? 1 : 0

  project  = google_cloud_run_v2_service.api.project
  location = google_cloud_run_v2_service.api.location
  name     = google_cloud_run_v2_service.api.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# Número del proyecto: hace falta para armar la URL previsible de Cloud Run
# y poder configurar CORS antes de que el servicio exista.
data "google_project" "current" {
  project_id = var.project_id
}
