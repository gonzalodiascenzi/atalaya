# ══════════════════════════════════════════════════════════════════════════
#  ATALAYA // Fundaciones en GCP: APIs, red, NAT y firewall
#  ------------------------------------------------------------------------
#  Diferencia clave con el modelo de AWS que esto reemplaza: en GCP el
#  firewall es de VPC (no hay "security group" adjunto a la instancia). El
#  control se expresa por `target_tags` o, mejor, por `target_service_accounts`
#  — que es la forma con identidad y no con etiquetas que cualquiera puede
#  ponerse.
# ══════════════════════════════════════════════════════════════════════════

locals {
  name = "${var.project_name}-${var.environment}"

  common_labels = merge(
    {
      project     = "atalaya"
      environment = var.environment
      managed_by  = "terraform"
      component   = "cti-platform"
    },
    var.extra_labels
  )

  # Rangos desde los que GCP emite sondas de salud y balanceo. Están
  # documentados y son fijos; sin esta regla los health checks fallan y el
  # backend queda marcado como caído sin motivo aparente.
  gcp_health_check_ranges = ["130.211.0.0/22", "35.191.0.0/16"]

  # Rango desde el que IAP hace TCP forwarding. Permitir SSH sólo desde acá
  # es el equivalente GCP a no tener bastión con IP pública.
  iap_range = "35.235.240.0/20"

  # Placeholder oficial de Google: permite que el primer `apply` levante los
  # servicios de Cloud Run antes de que existan tus imágenes.
  placeholder_image = "us-docker.pkg.dev/cloudrun/container/hello"

  api_image      = var.api_image != "" ? var.api_image : local.placeholder_image
  frontend_image = var.frontend_image != "" ? var.frontend_image : local.placeholder_image
}

# ══════════════════════════════════════════════════════════════════════════
#  APIs DEL PROYECTO
#  En GCP nada funciona hasta que la API está habilitada. Declararlas acá
#  evita el "resource not found" que en realidad es un "API apagada".
# ══════════════════════════════════════════════════════════════════════════

resource "google_project_service" "apis" {
  for_each = toset([
    "compute.googleapis.com",
    "run.googleapis.com",
    "artifactregistry.googleapis.com",
    "secretmanager.googleapis.com",
    "iam.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "iap.googleapis.com",
    "sqladmin.googleapis.com",
    "servicenetworking.googleapis.com",
    "cloudresourcemanager.googleapis.com",
  ])

  project = var.project_id
  service = each.value

  # No las apagamos al destruir: otro recurso del proyecto puede depender de
  # ellas y apagar una API es una acción de alcance mucho mayor que este stack.
  disable_on_destroy = false
}

# ══════════════════════════════════════════════════════════════════════════
#  RED
# ══════════════════════════════════════════════════════════════════════════

resource "google_compute_network" "main" {
  name                    = "${local.name}-vpc"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
  description             = "Red de la torre ATALAYA"

  depends_on = [google_project_service.apis]
}

resource "google_compute_subnetwork" "main" {
  name          = "${local.name}-subnet"
  ip_cidr_range = var.subnet_cidr
  region        = var.region
  network       = google_compute_network.main.id

  # Permite que instancias sin IP pública lleguen a las APIs de Google
  # (Artifact Registry, Secret Manager, Logging) sin salir a Internet.
  private_ip_google_access = true

  dynamic "log_config" {
    for_each = var.enable_flow_logs ? [1] : []
    content {
      aggregation_interval = "INTERVAL_5_SEC"
      flow_sampling        = var.flow_log_sampling
      metadata             = "INCLUDE_ALL_METADATA"
    }
  }
}

# ── Cloud NAT: salida a Internet sin IPs públicas ────────────────────────
# El nodo CTI necesita salir (bajar imágenes, actualizar feeds de OTX y
# abuse.ch) pero no necesita que Internet entre. NAT resuelve exactamente eso.

resource "google_compute_router" "main" {
  name    = "${local.name}-router"
  region  = var.region
  network = google_compute_network.main.id
}

resource "google_compute_router_nat" "main" {
  name                               = "${local.name}-nat"
  router                             = google_compute_router.main.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# ══════════════════════════════════════════════════════════════════════════
#  FIREWALL
#  GCP ya trae un deny implícito de ingreso en prioridad 65535, pero es
#  invisible en los logs. Una regla explícita en 65534 con logging te deja
#  ver qué está siendo rechazado, que es la mitad de una investigación.
# ══════════════════════════════════════════════════════════════════════════

resource "google_compute_firewall" "deny_all_ingress" {
  name        = "${local.name}-deny-all-ingress"
  network     = google_compute_network.main.name
  description = "Deny explícito y registrado. Todo lo permitido va en prioridad menor."
  direction   = "INGRESS"
  priority    = 65534

  deny {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# ── SSH sólo por IAP ─────────────────────────────────────────────────────
# Nunca se abre el 22 a Internet. `gcloud compute ssh --tunnel-through-iap`
# entra por acá, con la identidad de Google del operador y auditoría completa.

resource "google_compute_firewall" "allow_iap_ssh" {
  name        = "${local.name}-allow-iap-ssh"
  network     = google_compute_network.main.name
  description = "SSH exclusivamente vía IAP TCP forwarding"
  direction   = "INGRESS"
  priority    = 1000

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = [local.iap_range]
  target_tags   = ["cti-node"]

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# ── Consolas de administración del stack CTI ─────────────────────────────

resource "google_compute_firewall" "allow_cti_admin" {
  name        = "${local.name}-allow-cti-admin"
  network     = google_compute_network.main.name
  description = "OpenCTI (8080), MISP (8443) y SpiderFoot (5001) desde rangos autorizados"
  direction   = "INGRESS"
  priority    = 1000

  allow {
    protocol = "tcp"
    ports    = ["8080", "8443", "5001"]
  }

  # La validación de la variable garantiza que acá nunca entre 0.0.0.0/0.
  source_ranges = var.admin_cidrs
  target_tags   = ["cti-node"]

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# ── Sondas de salud de Google ────────────────────────────────────────────

resource "google_compute_firewall" "allow_health_checks" {
  name        = "${local.name}-allow-health-checks"
  network     = google_compute_network.main.name
  description = "Sondas de salud y balanceo desde los rangos publicados por GCP"
  direction   = "INGRESS"
  priority    = 900

  allow {
    protocol = "tcp"
    ports    = ["8000", "3000", "8080"]
  }

  source_ranges = local.gcp_health_check_ranges
  target_tags   = ["cti-node"]
}

# ── Tráfico interno de la subred ─────────────────────────────────────────

resource "google_compute_firewall" "allow_internal" {
  name        = "${local.name}-allow-internal"
  network     = google_compute_network.main.name
  description = "Comunicación entre cargas de trabajo dentro de la subred"
  direction   = "INGRESS"
  priority    = 1000

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }

  allow {
    protocol = "udp"
    ports    = ["0-65535"]
  }

  allow {
    protocol = "icmp"
  }

  source_ranges = [var.subnet_cidr]
}
