# ATALAYA // Requisitos de versión y proveedor (AWS).
terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # >= 6.28 hace falta por `invoked_via_function_url` en aws_lambda_permission
      # (ver lambda_api.tf). Sin eso la URL pública de Lambda responde 403.
      version = "~> 6.64"
    }
  }

  # Estado remoto. Comentado: el bucket tiene que existir antes del primer
  # `init`, y el estado de ESTE proyecto no guarda secretos (los valores viven
  # en SSM, cargados fuera de Terraform), así que el estado local alcanza para
  # el arranque. En equipo, se mueve a S3 con bloqueo:
  #
  # backend "s3" {
  #   bucket       = "atalaya-tfstate-<cuenta>"
  #   key          = "prod/terraform.tfstate"
  #   region       = "us-east-1"
  #   encrypt      = true
  #   use_lockfile = true
  # }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = local.common_tags
  }
}
