# ══════════════════════════════════════════════════════════════════════════
#  ATALAYA // Nodo CTI (opcional)
#  ------------------------------------------------------------------------
#  La VM que hospeda OpenCTI + MISP + ElasticSearch vía Docker Compose.
#
#  Apagado por defecto. El stack pide ~8 GB de RAM sostenidos y no entra en
#  ningún nivel gratuito de ninguna nube. Encendelo cuando lo vayas a usar y
#  apagalo cuando termines: `enable_cti_node = false` y un apply.
# ══════════════════════════════════════════════════════════════════════════

data "google_compute_image" "ubuntu" {
  family  = "ubuntu-2204-lts"
  project = "ubuntu-os-cloud"
}

resource "google_compute_instance" "cti" {
  count = var.enable_cti_node ? 1 : 0

  name         = "${local.name}-cti"
  machine_type = var.cti_machine_type
  zone         = var.zone

  # La etiqueta es lo que engancha las reglas de firewall de main.tf.
  tags = ["cti-node"]

  boot_disk {
    initialize_params {
      image = data.google_compute_image.ubuntu.self_link
      size  = var.cti_disk_gb
      type  = "pd-balanced"
    }
    # El cifrado en reposo es transparente y está siempre activo en GCP.
    auto_delete = true
  }

  network_interface {
    subnetwork = google_compute_subnetwork.main.id
    # Sin bloque access_config = sin IP pública. La salida va por Cloud NAT
    # y la entrada administrativa por IAP.
  }

  # Shielded VM: arranque seguro, vTPM y monitoreo de integridad. Es el
  # equivalente en GCP al endurecimiento del arranque que en AWS se lograba
  # exigiendo IMDSv2 — protege contra rootkits de arranque y manipulación
  # del firmware.
  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  metadata = {
    # OS Login: el acceso SSH se controla por IAM, no por claves sueltas
    # pegadas en los metadatos del proyecto.
    enable-oslogin         = "TRUE"
    block-project-ssh-keys = "TRUE"
  }

  service_account {
    email = google_service_account.cti_node.email
    # `cloud-platform` delega el control real a los roles IAM de la cuenta,
    # que es lo recomendado desde que existen los roles granulares. Los
    # scopes son el mecanismo viejo.
    scopes = ["cloud-platform"]
  }

  metadata_startup_script = <<-EOT
    #!/bin/bash
    set -euo pipefail

    # ElasticSearch no arranca sin este sysctl.
    sysctl -w vm.max_map_count=1048575
    echo "vm.max_map_count=1048575" >> /etc/sysctl.conf

    apt-get update
    apt-get install -y ca-certificates curl git
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
      -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
      https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
      > /etc/apt/sources.list.d/docker.list
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable --now docker

    cat > /etc/motd <<'MOTD'
    ═══════════════════════════════════════════════════════════
      ATALAYA :: nodo CTI
      El que vigila desde arriba ve venir la amenaza primero.

      1. git clone <repo> /opt/atalaya
      2. cd /opt/atalaya && cp .env.example .env
      3. Cargá los secretos desde Secret Manager:
           gcloud secrets versions access latest \
             --secret=atalaya-opencti-token
      4. make up-cti
    ═══════════════════════════════════════════════════════════
    MOTD
  EOT

  # Permite cambiar el tipo de máquina sin recrear el disco.
  allow_stopping_for_update = true

  depends_on = [google_project_service.apis]
}
