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

# Cabeceras de seguridad de la consola. En el despliegue estático Next no
# puede agregarlas (no hay servidor), así que las pone CloudFront.
resource "aws_cloudfront_response_headers_policy" "seguridad" {
  name    = "${local.name}-seguridad"
  comment = "Cabeceras de seguridad de la consola ATALAYA"

  security_headers_config {
    content_security_policy {
      override = true
      # 'unsafe-inline' en script-src NO es descuido: el App Router de Next
      # incrusta scripts en línea para hidratar la página, y en un export
      # estático no hay servidor que genere nonces. Sin esto la consola no
      # arranca. El riesgo se acota porque React escapa todo lo que
      # renderiza y el contenido de los feeds OSINT se muestra como texto,
      # nunca como HTML. connect-src 'self': la API está en el mismo dominio.
      content_security_policy = join("; ", [
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
    }

    content_type_options {
      override = true
    }

    frame_options {
      frame_option = "DENY"
      override     = true
    }

    referrer_policy {
      referrer_policy = "no-referrer"
      override        = true
    }

    strict_transport_security {
      access_control_max_age_sec = 63072000 # 2 años
      include_subdomains         = true
      preload                    = false
      override                   = true
    }
  }

  custom_headers_config {
    items {
      header   = "Permissions-Policy"
      value    = "geolocation=(), microphone=(), camera=()"
      override = true
    }
  }
}

resource "aws_cloudfront_distribution" "atalaya" {
  enabled             = true
  comment             = "ATALAYA · consola + API"
  default_root_object = "index.html"
  is_ipv6_enabled     = true
  http_version        = "http2and3"
  # Todos los bordes, incluido Sudamérica. La clase barata (PriceClass_100)
  # excluye Sudamérica: desde Argentina se servía desde Miami. El nivel
  # gratuito (1 TB y 10 M de pedidos al mes) no distingue regiones, así que
  # con el tráfico esperado la diferencia es $0.
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
    target_origin_id           = "s3-consola"
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = ["GET", "HEAD", "OPTIONS"]
    cached_methods             = ["GET", "HEAD"]
    compress                   = true
    cache_policy_id            = data.aws_cloudfront_cache_policy.optimizada.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.seguridad.id
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
