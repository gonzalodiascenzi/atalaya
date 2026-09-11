# ATALAYA // Salidas.

output "consola_url" {
  description = "La dirección pública de ATALAYA."
  value       = "https://${aws_cloudfront_distribution.atalaya.domain_name}"
}

output "ecr_repositorio" {
  description = "Dónde se publican las imágenes de la API."
  value       = aws_ecr_repository.api.repository_url
}

output "rol_despliegue_github" {
  description = "ARN que usa GitHub Actions (no es un secreto: sin el token de GitHub no sirve)."
  value       = aws_iam_role.github_deploy.arn
}

output "bucket_consola" {
  description = "Bucket de la consola estática."
  value       = aws_s3_bucket.consola.bucket
}

output "distribucion_id" {
  description = "ID de CloudFront, para invalidar la caché al desplegar."
  value       = aws_cloudfront_distribution.atalaya.id
}

output "lambda_url_directa" {
  description = "URL directa de la Lambda. Tiene que responder 403: sólo CloudFront puede invocarla."
  value       = aws_lambda_function_url.api.function_url
}

output "cargar_secretos" {
  description = "Los secretos se cargan FUERA de Terraform, para que sus valores no queden en el estado."
  value = {
    database_url   = "aws ssm put-parameter --type SecureString --name ${local.ssm_database_url} --value \"$DATABASE_URL_PROD\""
    api_secret_key = "aws ssm put-parameter --type SecureString --name ${local.ssm_api_secret_key} --value \"$(openssl rand -hex 32)\""
  }
}
