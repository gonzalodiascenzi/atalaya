# ══════════════════════════════════════════════════════════════════════════
#  ATALAYA // WAF delante de CloudFront
#  ------------------------------------------------------------------------
#  Cinco reglas: el máximo del plan Free de tarifa plana de CloudFront, que
#  cubre el web ACL, las reglas y los pedidos sin costo y sin excedentes.
#  Fuera del plan, este web ACL costaría ~USD 10/mes.
#
#  La suscripción al plan se hace en la consola de CloudFront (no existe
#  como recurso de Terraform); este web ACL es el que queda asociado.
# ══════════════════════════════════════════════════════════════════════════

locals {
  # Reglas administradas que miran el CUERPO del pedido y en ATALAYA van en
  # modo "contar" en vez de "bloquear". El cuerpo de un veredicto es el
  # fundamento del analista, y un analista de amenazas escribe, con razón,
  # cosas como `<script>`, `../../etc/passwd`, `${jndi:ldap://...}` o una URL
  # de C2 con IP. Bloquearlas castiga al que hace bien el trabajo. La defensa
  # real contra XSS está en la consola: React escapa todo lo que muestra.
  waf_cuerpo_solo_contar = {
    AWSManagedRulesCommonRuleSet = [
      "CrossSiteScripting_BODY",
      "GenericLFI_BODY",
      "GenericRFI_BODY",
      "EC2MetaDataSSRF_BODY",
    ]
    # Las misiones de KEV incluyen Log4Shell: citar el payload es análisis.
    AWSManagedRulesKnownBadInputsRuleSet = [
      "Log4JRCE_BODY",
      "JavaDeserializationRCE_BODY",
    ]
  }

  waf_reglas_administradas = [
    # Botnets y escáneres conocidos, según la inteligencia de Amazon.
    { nombre = "reputacion-ip", grupo = "AWSManagedRulesAmazonIpReputationList", prioridad = 30 },
    # OWASP básico: XSS, LFI, RFI, tamaños, user agents vacíos o de escáneres.
    { nombre = "reglas-base", grupo = "AWSManagedRulesCommonRuleSet", prioridad = 40 },
    # Entradas conocidas como maliciosas: Log4Shell, deserialización Java...
    { nombre = "entradas-maliciosas", grupo = "AWSManagedRulesKnownBadInputsRuleSet", prioridad = 50 },
  ]
}

resource "aws_wafv2_web_acl" "atalaya" {
  name        = "${local.name}-waf"
  description = "WAF de ATALAYA - plan Free de CloudFront, hasta 5 reglas" # sin parentesis: AWS los rechaza
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  # ── 1 · Tope por IP para todo el sitio ────────────────────────────────
  # A diferencia del limitador de la API (uno por instancia de Lambda), éste
  # es global: lo cuenta CloudFront en todos sus bordes. 2000 pedidos cada
  # 5 minutos alcanzan para un aula entera detrás de una sola IP pública
  # (30 personas cargando la consola a la vez) y cortan una inundación.
  rule {
    name     = "tope-por-ip"
    priority = 10

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit                 = 2000
        evaluation_window_sec = 300
        aggregate_key_type    = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "tope-por-ip"
      sampled_requests_enabled   = true
    }
  }

  # ── 2 · Tope estricto para registro, login y renovación ───────────────
  # Frena la fuerza bruta repartida entre muchas cuentas y el alta masiva de
  # cuentas. El ataque a UNA cuenta ya lo corta el bloqueo por intentos
  # fallidos de la API. 150 cada 5 minutos: un aula de 30 que se registra y
  # entra a la vez usa unos 70.
  rule {
    name     = "tope-auth-por-ip"
    priority = 20

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit                 = 150
        evaluation_window_sec = 300
        aggregate_key_type    = "IP"

        scope_down_statement {
          byte_match_statement {
            search_string         = "/api/v1/auth/"
            positional_constraint = "STARTS_WITH"

            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 0
              type     = "NONE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "tope-auth-por-ip"
      sampled_requests_enabled   = true
    }
  }

  # ── 3 a 5 · Reglas administradas por AWS ──────────────────────────────
  dynamic "rule" {
    for_each = local.waf_reglas_administradas

    content {
      name     = rule.value.nombre
      priority = rule.value.prioridad

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          vendor_name = "AWS"
          name        = rule.value.grupo

          dynamic "rule_action_override" {
            for_each = lookup(local.waf_cuerpo_solo_contar, rule.value.grupo, [])

            content {
              name = rule_action_override.value

              action_to_use {
                count {}
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = rule.value.nombre
        sampled_requests_enabled   = true
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name}-waf"
    sampled_requests_enabled   = true
  }
}
