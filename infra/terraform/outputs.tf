# ATALAYA // Salidas: lo que necesitás para operar después del apply.

output "consola_url" {
  description = "URL pública de la consola ATALAYA."
  value       = google_cloud_run_v2_service.frontend.uri
}

output "api_url" {
  description = "URL de la API. La documentación viva está en /docs."
  value       = google_cloud_run_v2_service.api.uri
}

output "registro_docker" {
  description = "Ruta del Artifact Registry donde van las imágenes."
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.images.repository_id}"
}

output "cuentas_de_servicio" {
  description = "Identidades de cada carga de trabajo."
  value = {
    api      = google_service_account.api.email
    frontend = google_service_account.frontend.email
    cti_node = google_service_account.cti_node.email
  }
}

output "secretos" {
  description = "Secretos creados. Los VALORES se cargan aparte (ver identity.tf)."
  value       = [for s in google_secret_manager_secret.app : s.secret_id]
}

output "red" {
  description = "Identificadores de red."
  value = {
    vpc    = google_compute_network.main.name
    subred = google_compute_subnetwork.main.name
    cidr   = google_compute_subnetwork.main.ip_cidr_range
  }
}

output "nodo_cti" {
  description = "Datos del nodo CTI (null si está apagado)."
  value = var.enable_cti_node ? {
    nombre   = google_compute_instance.cti[0].name
    ip_priva = google_compute_instance.cti[0].network_interface[0].network_ip
    ssh      = "gcloud compute ssh ${google_compute_instance.cti[0].name} --zone ${var.zone} --tunnel-through-iap"
  } : null
}

output "cloud_sql" {
  description = "Datos de Cloud SQL (null si está apagado)."
  value = var.enable_cloud_sql ? {
    instancia = google_sql_database_instance.main[0].name
    ip_priva  = google_sql_database_instance.main[0].private_ip_address
  } : null
}

output "cloud_sql_password" {
  description = "Contraseña generada del usuario de la base. Sensible."
  value       = var.enable_cloud_sql ? random_password.db[0].result : null
  sensitive   = true
}

output "comandos_build" {
  description = <<-EOT
    Cómo construir y publicar las imágenes.

    Prestá atención al --build-arg del frontend: Next incrusta las variables
    NEXT_PUBLIC_* en el bundle del navegador durante el BUILD. Pasarla como
    variable de entorno de Cloud Run no sirve para el código del cliente.
  EOT
  value = {
    "1_autenticar" = "gcloud auth configure-docker ${var.region}-docker.pkg.dev"
    "2_api" = join(" ", [
      "docker build -t ${var.region}-docker.pkg.dev/${var.project_id}/${var.project_name}/api:v1",
      "src/api && docker push ${var.region}-docker.pkg.dev/${var.project_id}/${var.project_name}/api:v1"
    ])
    "3_frontend" = join(" ", [
      "docker build --build-arg NEXT_PUBLIC_API_URL=${google_cloud_run_v2_service.api.uri}",
      "-t ${var.region}-docker.pkg.dev/${var.project_id}/${var.project_name}/frontend:v1",
      "src/frontend && docker push ${var.region}-docker.pkg.dev/${var.project_id}/${var.project_name}/frontend:v1"
    ])
    "4_reapply" = "terraform apply -var api_image=... -var frontend_image=..."
  }
}

output "carga_de_secretos" {
  description = "Comandos para cargar los valores de los secretos (fuera de Terraform)."
  value = {
    api_secret_key = "openssl rand -hex 32 | tr -d '\\n' | gcloud secrets versions add ${var.project_name}-api-secret-key --data-file=-"
    database_url   = "printf '%s' 'postgresql+asyncpg://USER:PASS@HOST/atalaya' | gcloud secrets versions add ${var.project_name}-database-url --data-file=-"
    opencti_token  = "uuidgen | tr -d '\\n' | gcloud secrets versions add ${var.project_name}-opencti-token --data-file=-"
  }
}
