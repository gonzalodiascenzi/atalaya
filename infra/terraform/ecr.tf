# ATALAYA // Registro de imágenes.

# Sin clave KMS propia (trivy AWS-0033): la misma imagen es pública en GHCR.
# Cifrarla con una clave propia no protege nada que no esté ya publicado.
#trivy:ignore:AWS-0033
resource "aws_ecr_repository" "api" {
  name = "${var.project_name}-api"

  # Tags INMUTABLES: un tag publicado no se puede reemplazar. Sin esto,
  # alguien con permiso de push podría cambiar lo que corre en producción
  # sin cambiar el tag que figura en Terraform.
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  # Destruir el repo con imágenes adentro exige vaciarlo antes a mano.
  force_delete = false
}

# El almacenamiento de ECR se cobra por GB. Sin política, cada commit suma
# una imagen de ~250 MB para siempre.
resource "aws_ecr_lifecycle_policy" "api" {
  repository = aws_ecr_repository.api.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Borrar imágenes sin tag a los 3 días"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 3
        }
        action = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "Conservar las últimas 10 imágenes"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 10
        }
        action = { type = "expire" }
      },
    ]
  })
}

# Lambda descarga la imagen con su propia identidad de servicio. Si la
# política no existe, Lambda la escribe sola al crear la función, y ese
# cambio quedaría fuera de Terraform. Se declara acá, acotada a ESTA función.
data "aws_iam_policy_document" "ecr_lambda" {
  statement {
    sid     = "LambdaLeeLaImagen"
    effect  = "Allow"
    actions = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      # Armado a mano y no con aws_lambda_function.api.arn: la función
      # depende de esta política, y la referencia cerraría un ciclo.
      values = ["arn:aws:lambda:${var.region}:${data.aws_caller_identity.current.account_id}:function:${local.name}-api"]
    }
  }
}

resource "aws_ecr_repository_policy" "api" {
  repository = aws_ecr_repository.api.name
  policy     = data.aws_iam_policy_document.ecr_lambda.json
}
