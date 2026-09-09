# ══════════════════════════════════════════════════════════════════════════
#  ATALAYA // Capa de datos: Cloud SQL (opcional)
#  ------------------------------------------------------------------------
#  Apagado por defecto y con motivo: Cloud SQL no tiene nivel gratuito. La
#  ruta de costo cero es un PostgreSQL serverless externo (Neon, Supabase)
#  cuya cadena de conexión vive en el secreto `database-url`. La API consume
#  un DATABASE_URL y le da igual de dónde salga.
#
#  Encendé esto cuando el proyecto justifique el gasto, no antes.
# ══════════════════════════════════════════════════════════════════════════

# ── Peering para IP privada ──────────────────────────────────────────────
# Cloud SQL con IP privada vive en una red gestionada por Google que se
# empareja con la tuya. Ese emparejamiento necesita un rango reservado.

resource "google_compute_global_address" "private_ip_range" {
  count = var.enable_cloud_sql ? 1 : 0

  name          = "${local.name}-sql-private-range"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.main.id
}

resource "google_service_networking_connection" "private_vpc" {
  count = var.enable_cloud_sql ? 1 : 0

  network                 = google_compute_network.main.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_range[0].name]

  depends_on = [google_project_service.apis]
}

# ── Contraseña de la base ────────────────────────────────────────────────
# Se genera acá porque Cloud SQL la exige al crear el usuario. Queda en el
# estado, así que el estado ES un secreto: bucket privado, versionado y con
# acceso restringido. Es la razón principal por la que el backend GCS de
# versions.tf no es opcional en cuanto esto se enciende.

resource "random_password" "db" {
  count = var.enable_cloud_sql ? 1 : 0

  length  = 32
  special = false # alfanumérico: entra en un DSN sin necesidad de escapado
}

resource "google_sql_database_instance" "main" {
  count = var.enable_cloud_sql ? 1 : 0

  name             = "${local.name}-pg"
  database_version = "POSTGRES_16"
  region           = var.region

  deletion_protection = var.cloud_sql_deletion_protection

  settings {
    tier              = var.cloud_sql_tier
    availability_type = var.environment == "prod" ? "REGIONAL" : "ZONAL"
    disk_type         = "PD_SSD"
    disk_size         = 10
    disk_autoresize   = true

    ip_configuration {
      # Sin IP pública. Se llega por la VPC y nada más.
      ipv4_enabled    = false
      private_network = google_compute_network.main.id
      ssl_mode        = "ENCRYPTED_ONLY"
    }

    backup_configuration {
      enabled                        = true
      start_time                     = "05:00"
      point_in_time_recovery_enabled = var.environment == "prod"
      transaction_log_retention_days = 7
    }

    # Registrar todas las conexiones: en una plataforma que maneja
    # inteligencia, saber quién se conectó a la base no es opcional.
    database_flags {
      name  = "log_connections"
      value = "on"
    }

    database_flags {
      name  = "log_disconnections"
      value = "on"
    }

    insights_config {
      query_insights_enabled = true
    }
  }

  depends_on = [google_service_networking_connection.private_vpc]
}

resource "google_sql_database" "atalaya" {
  count = var.enable_cloud_sql ? 1 : 0

  name     = "atalaya"
  instance = google_sql_database_instance.main[0].name
}

resource "google_sql_user" "atalaya" {
  count = var.enable_cloud_sql ? 1 : 0

  name     = "atalaya"
  instance = google_sql_database_instance.main[0].name
  password = random_password.db[0].result
}

# La API se conecta como cliente de Cloud SQL.
resource "google_project_iam_member" "api_sql_client" {
  count = var.enable_cloud_sql ? 1 : 0

  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.api.email}"
}
