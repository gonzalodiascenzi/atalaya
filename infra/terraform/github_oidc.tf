# ══════════════════════════════════════════════════════════════════════════
#  ATALAYA // Rol de despliegue para GitHub Actions (OIDC, sin claves)
#  ------------------------------------------------------------------------
#  GitHub presenta un token firmado; AWS lo canjea por credenciales que
#  duran lo que dura la corrida. En GitHub no se guarda ninguna clave.
#
#  El rol sólo DESPLIEGA: sube imágenes, actualiza el código de la Lambda,
#  sincroniza la consola e invalida la caché. No puede tocar IAM ni la
#  infraestructura: los cambios de infraestructura siguen siendo una acción
#  humana con `terraform apply`.
# ══════════════════════════════════════════════════════════════════════════

locals {
  # Sujeto INMUTABLE, con los IDs numéricos. Coincidencia EXACTA
  # (StringEquals), sin comodines: aunque alguien re-registrara el nombre
  # del usuario o del repo, no podría asumir el rol.
  github_sub = "repo:${var.github_owner}@${var.github_owner_id}/${var.github_repo}@${var.github_repo_id}:ref:refs/heads/${var.github_deploy_branch}"
}

data "aws_iam_policy_document" "github_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = [local.github_sub]
    }
  }
}

resource "aws_iam_role" "github_deploy" {
  name                 = "${local.name}-github-deploy"
  description          = "Despliegue de ATALAYA desde GitHub Actions (rama ${var.github_deploy_branch})"
  assume_role_policy   = data.aws_iam_policy_document.github_assume.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "github_deploy" {
  statement {
    sid       = "LoginECR"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"] # la API de ECR no admite acotar esta acción
  }

  statement {
    sid    = "PublicarImagen"
    effect = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload",
      "ecr:PutImage",
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer", # Lambda lo verifica en update-function-code
      "ecr:DescribeImages",
    ]
    resources = [aws_ecr_repository.api.arn]
  }

  statement {
    sid    = "ActualizarAPI"
    effect = "Allow"
    actions = [
      "lambda:UpdateFunctionCode",
      "lambda:GetFunction",
      "lambda:GetFunctionConfiguration",
    ]
    resources = [aws_lambda_function.api.arn]
  }

  statement {
    sid       = "SincronizarConsola"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.consola.arn]
  }

  statement {
    sid       = "EscribirConsola"
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.consola.arn}/*"]
  }

  statement {
    sid       = "InvalidarCache"
    effect    = "Allow"
    actions   = ["cloudfront:CreateInvalidation", "cloudfront:GetInvalidation"]
    resources = [aws_cloudfront_distribution.atalaya.arn]
  }
}

resource "aws_iam_role_policy" "github_deploy" {
  name   = "${local.name}-github-deploy"
  role   = aws_iam_role.github_deploy.id
  policy = data.aws_iam_policy_document.github_deploy.json
}
