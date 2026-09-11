# ══════════════════════════════════════════════════════════════════════════
#  ATALAYA // CloudFront: una sola puerta para la consola y la API
# ══════════════════════════════════════════════════════════════════════════

data "aws_cloudfront_cache_policy" "optimizada" {
  name = "Managed-CachingOptimized"
}

data "aws_cloudfront_cache_policy" "sin_cache" {
  name = "Managed-CachingDisabled"
}

# Reenvía cookies, cabeceras y query string, MENOS Host: una URL de Lambda
# rechaza cualquier Host que no sea el suyo.
data "aws_cloudfront_origin_request_policy" "todo_menos_host" {
  name = "Managed-AllViewerExceptHostHeader"
}

resource "aws_cloudfront_origin_access_control" "consola" {
  name                              = "${local.name}-consola"
  description                       = "CloudFront firma cada lectura al bucket de la consola"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# Lo mismo para la API: CloudFront firma cada pedido a la Lambda (SigV4).
# CloudFront NO calcula el hash del cuerpo: en POST/PUT lo manda el cliente
# en `x-amz-content-sha256` (lo hace src/frontend/lib/api.ts).
resource "aws_cloudfront_origin_access_control" "api" {
  name                              = "${local.name}-api"
  description                       = "CloudFront firma cada pedido a la API; la URL directa da 403"
  origin_access_control_origin_type = "lambda"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# La IP real del cliente, en una cabecera que el cliente no puede falsificar.
resource "aws_cloudfront_function" "ip_del_cliente" {
  name    = "${local.name}-ip-del-cliente"
  runtime = "cloudfront-js-2.0"
  comment = "Escribe la IP real del cliente en x-atalaya-ip"
  publish = true
  code    = file("${path.module}/funciones/ip_del_cliente.js")
}

# ── Cabeceras de seguridad de la consola ─────────────────────────────────
# En el export estático Next no puede ponerlas (no hay servidor), así que las
# pone CloudFront con una función en cada respuesta. No es una "response
# headers policy" porque el plan Free sólo admite las administradas por AWS,
# y ninguna trae CSP.
locals {
  cabeceras_seguridad = {
    # 'unsafe-inline' en script-src NO es descuido: el App Router de Next
    # incrusta scripts en línea para hidratar la página, y en un export
    # estático no hay servidor que genere nonces. Sin esto la consola no
    # arranca. El riesgo se acota porque React escapa todo lo que renderiza y
    # el contenido de los feeds OSINT se muestra como texto, nunca como HTML.
    # connect-src 'self': la API está en el mismo dominio.
    "content-security-policy" = join("; ", [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com data:",
      "img-src 'self' data: blob:",
      "connect-src 'self'",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ])
    "strict-transport-security" = "max-age=63072000; includeSubDomains" # 2 años
    "x-content-type-options"    = "nosniff"
    "x-frame-options"           = "DENY"
    "referrer-policy"           = "no-referrer"
    "permissions-policy"        = "geolocation=(), microphone=(), camera=()"
  }
}

resource "aws_cloudfront_function" "cabeceras_seguridad" {
  name    = "${local.name}-cabeceras-seguridad"
  runtime = "cloudfront-js-2.0"
  comment = "CSP, HSTS y demas cabeceras de seguridad de la consola"
  publish = true
  code = templatefile("${path.module}/funciones/cabeceras_seguridad.js.tftpl", {
    cabeceras = jsonencode(local.cabeceras_seguridad)
  })
}

# Sin logs de acceso (trivy AWS-0010): el plan Free de CloudFront no los
# incluye; empiezan en Pro (USD 15/mes). Mientras tanto: los logs de la Lambda
# registran cada pedido a la API, y el WAF muestrea los pedidos que evalúa
# (tablero de seguridad de CloudFront). Con jugadores reales, se pasa a Pro.
#trivy:ignore:AWS-0010
resource "aws_cloudfront_distribution" "atalaya" {
  enabled             = true
  web_acl_id          = aws_wafv2_web_acl.atalaya.arn
  comment             = "ATALAYA · consola + API"
  default_root_object = "index.html"
  is_ipv6_enabled     = true
  http_version        = "http2and3"
  # Todos los bordes, incluido Sudamérica: la clase barata (PriceClass_100)
  # la excluye y desde Argentina se servía desde Miami. Con el plan Free de
  # tarifa plana, la elección de bordes la hace AWS y el precio es el mismo.
  price_class = "PriceClass_All"

  origin {
    origin_id                = "s3-consola"
    domain_name              = aws_s3_bucket.consola.bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.consola.id
  }

  origin {
    origin_id = "lambda-api"
    # "https://abc.lambda-url.us-east-1.on.aws/" → "abc.lambda-url.us-east-1.on.aws"
    domain_name              = trimsuffix(trimprefix(aws_lambda_function_url.api.function_url, "https://"), "/")
    origin_access_control_id = aws_cloudfront_origin_access_control.api.id

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  # ── /* → consola estática ──
  default_cache_behavior {
    target_origin_id       = "s3-consola"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true
    cache_policy_id        = data.aws_cloudfront_cache_policy.optimizada.id

    function_association {
      event_type   = "viewer-response"
      function_arn = aws_cloudfront_function.cabeceras_seguridad.arn
    }
  }

  # ── /api/* → Lambda, sin caché ──
  # Nada de la API se cachea: son respuestas por analista, con cookies de
  # sesión. Cachear una sería servirle a alguien el perfil de otro.
  ordered_cache_behavior {
    path_pattern             = "/api/*"
    target_origin_id         = "lambda-api"
    viewer_protocol_policy   = "redirect-to-https"
    allowed_methods          = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods           = ["GET", "HEAD"]
    compress                 = true
    cache_policy_id          = data.aws_cloudfront_cache_policy.sin_cache.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.todo_menos_host.id

    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.ip_del_cliente.arn
    }
  }

  ordered_cache_behavior {
    path_pattern             = "/health*"
    target_origin_id         = "lambda-api"
    viewer_protocol_policy   = "redirect-to-https"
    allowed_methods          = ["GET", "HEAD"]
    cached_methods           = ["GET", "HEAD"]
    cache_policy_id          = data.aws_cloudfront_cache_policy.sin_cache.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.todo_menos_host.id

    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.ip_del_cliente.arn
    }
  }

  # SIN custom_error_response, a propósito: esas reglas valen para TODA la
  # distribución. Un "403 → página de error" pensado para el sitio estático
  # también se tragaría los 403 legítimos de la API (ej: "permiso
  # insuficiente" al fijar una verdad) y el cliente recibiría HTML.

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}
