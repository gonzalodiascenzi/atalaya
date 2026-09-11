# ATALAYA // Consola estática en S3, servida SÓLO a través de CloudFront.

# Sin versionado (trivy AWS-0090): todo lo que hay en el bucket se regenera
# desde git en cada despliegue. Versionarlo sería pagar por guardar copias de
# lo que ya está en el historial del repo.
#
# Sin logs de acceso de S3 (trivy AWS-0089): al bucket sólo lo lee CloudFront.
# Esos logs registrarían las lecturas de CloudFront cuando no tiene la página
# en caché, no las de los jugadores. Los cambios de permisos del bucket ya
# quedan en CloudTrail.
#trivy:ignore:AWS-0090
#trivy:ignore:AWS-0089
resource "aws_s3_bucket" "consola" {
  # El nombre de un bucket es global en todo AWS: se le suma la cuenta para
  # no chocar con el de nadie.
  bucket        = "${local.name}-consola-${data.aws_caller_identity.current.account_id}"
  force_destroy = true # es contenido regenerable: se vuelve a construir
}

resource "aws_s3_bucket_ownership_controls" "consola" {
  bucket = aws_s3_bucket.consola.id
  rule {
    object_ownership = "BucketOwnerEnforced" # sin ACLs: todo por políticas
  }
}

# Cerrado al público por las cuatro vías. La única forma de leerlo es
# CloudFront con su identidad firmada (OAC); una URL directa al bucket da 403.
resource "aws_s3_bucket_public_access_block" "consola" {
  bucket                  = aws_s3_bucket.consola.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Clave de S3 y no una de KMS propia (trivy AWS-0132): el bucket guarda la
# consola estática, que es pública por definición. Una clave KMS cuesta
# USD 1/mes y obliga a darle permiso de descifrado a CloudFront, sin proteger
# nada que no esté ya publicado.
#trivy:ignore:AWS-0132
resource "aws_s3_bucket_server_side_encryption_configuration" "consola" {
  bucket = aws_s3_bucket.consola.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

data "aws_iam_policy_document" "consola" {
  statement {
    sid       = "SoloCloudFront"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.consola.arn}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    # Y sólo ESTA distribución: otra distribución de CloudFront, aunque sea
    # de otra cuenta, no puede leer el bucket.
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.atalaya.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "consola" {
  bucket     = aws_s3_bucket.consola.id
  policy     = data.aws_iam_policy_document.consola.json
  depends_on = [aws_s3_bucket_public_access_block.consola]
}
