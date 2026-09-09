# ATALAYA // Requisitos de versión y proveedores (GCP).
terraform {
  required_version = ">= 1.6.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.14"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Estado remoto en GCS. Comentado porque el bucket tiene que existir antes
  # del primer `init`. Crealo una sola vez, a mano:
  #
  #   gcloud storage buckets create gs://atalaya-tfstate \
  #     --location=us-central1 --uniform-bucket-level-access
  #   gcloud storage buckets update gs://atalaya-tfstate --versioning
  #
  # backend "gcs" {
  #   bucket = "atalaya-tfstate"
  #   prefix = "core"
  # }
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone

  # Etiquetas aplicadas a todo recurso que las soporte. En GCP se llaman
  # `labels` (minúsculas, sin espacios) y no `tags`: los `tags` de GCP son
  # otra cosa, se usan como destino de reglas de firewall.
  default_labels = local.common_labels
}
