# ══════════════════════════════════════════════════════════════════════════
#  ATALAYA // API en Lambda
#  La imagen es la misma que corre en Docker Compose: el Lambda Web Adapter
#  (ver src/api/Dockerfile) traduce los eventos de Lambda a HTTP.
# ══════════════════════════════════════════════════════════════════════════

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "api" {
  name               = "${local.name}-api"
  description        = "Identidad de la API de ATALAYA en Lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

# Permisos mínimos: escribir SUS logs y leer SUS dos secretos. Nada más.
data "aws_iam_policy_document" "api" {
  statement {
    sid       = "Logs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.api.arn}:*"]
  }

  statement {
    sid     = "LeerSusSecretos"
    effect  = "Allow"
    actions = ["ssm:GetParameter", "ssm:GetParameters"]
    resources = [
      "arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter${local.ssm_database_url}",
      "arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter${local.ssm_api_secret_key}",
    ]
  }

  # Descifrar SecureString con la clave administrada aws/ssm, y sólo cuando
  # la llamada llega a través de SSM. Una lectura directa a KMS no pasa.
  statement {
    sid       = "DescifrarViaSSM"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["ssm.${var.region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "api" {
  name   = "${local.name}-api"
  role   = aws_iam_role.api.id
  policy = data.aws_iam_policy_document.api.json
}

resource "aws_cloudwatch_log_group" "api" {
  name              = "/aws/lambda/${local.name}-api"
  retention_in_days = var.log_retention_days
}

resource "aws_lambda_function" "api" {
  function_name = "${local.name}-api"
  description   = "ATALAYA · Feed de Misiones, veredictos y progresión"
  role          = aws_iam_role.api.arn

  package_type  = "Image"
  image_uri     = "${aws_ecr_repository.api.repository_url}:${var.api_image_tag}"
  architectures = ["x86_64"]

  memory_size = var.lambda_memory_mb
  timeout     = 30

  # SIN concurrencia reservada, a propósito: la cuenta tiene un tope de 10
  # ejecuciones concurrentes y, con ese límite, AWS no deja reservar nada
  # (el apply fallaría). Ese tope ya funciona como techo natural de gasto.

  environment {
    variables = {
      ATALAYA_ENV   = var.environment
      API_LOG_LEVEL = "info"

      # Consola y API comparten dominio detrás de CloudFront: no hay pedidos
      # cruzados y CORS no tiene nada que habilitar. "none" y no "": Lambda
      # descarta las variables vacías y la API caería en el valor de
      # desarrollo (localhost). En producción eso aborta el arranque.
      API_CORS_ORIGINS = "none"

      # Los valores se leen de SSM en el arranque (config.py). Acá sólo va
      # el NOMBRE de cada parámetro, nunca el secreto.
      DATABASE_URL_SSM   = local.ssm_database_url
      API_SECRET_KEY_SSM = local.ssm_api_secret_key

      # De dónde sale la IP del cliente para el limitador de tasa. La escribe
      # la CloudFront Function de cdn.tf.
      API_CLIENT_IP_HEADER = "x-atalaya-ip"

      # Cada instancia de Lambda abre su propio pool. Con 10 instancias
      # posibles y pools grandes se agotan las conexiones de Neon.
      DB_POOL_SIZE    = "2"
      DB_MAX_OVERFLOW = "0"
    }
  }

  depends_on = [
    aws_iam_role_policy.api,
    aws_cloudwatch_log_group.api,
    aws_ecr_repository_policy.api,
  ]

  # El código lo despliega GitHub Actions (update-function-code con cada
  # commit). Si Terraform vigilara el tag, cada `plan` querría volver atrás
  # a la versión de la variable.
  lifecycle {
    ignore_changes = [image_uri]
  }
}

# ── La URL de la función, cerrada al público ─────────────────────────────
# AWS_IAM + OAC: sólo CloudFront, firmando cada pedido, puede invocarla. La
# URL directa responde 403 a cualquier otro.
#
# No es sólo prolijidad. Con la URL abierta, cualquiera podía hablarle a la
# API salteándose CloudFront y mandar la cabecera de IP que quisiera: el
# limitador de tasa quedaba de adorno (registro masivo de cuentas, fuerza
# bruta repartida). Y el costo: la única forma de invocarla pasa a ser por
# CloudFront.

resource "aws_lambda_function_url" "api" {
  function_name      = aws_lambda_function.api.function_name
  authorization_type = "AWS_IAM"
  invoke_mode        = "BUFFERED"
}

# Desde octubre de 2025, invocar por la URL exige DOS permisos:
# InvokeFunctionUrl e InvokeFunction. Los dos, sólo para ESTA distribución.
resource "aws_lambda_permission" "cloudfront_url" {
  statement_id  = "AllowCloudFrontServicePrincipal"
  action        = "lambda:InvokeFunctionUrl"
  function_name = aws_lambda_function.api.function_name
  principal     = "cloudfront.amazonaws.com"
  source_arn    = aws_cloudfront_distribution.atalaya.arn
}

resource "aws_lambda_permission" "cloudfront_invocar" {
  statement_id  = "AllowCloudFrontServicePrincipalInvokeFunction"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api.function_name
  principal     = "cloudfront.amazonaws.com"
  source_arn    = aws_cloudfront_distribution.atalaya.arn
}
