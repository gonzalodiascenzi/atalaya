# ══════════════════════════════════════════════════════════════════════
#  ATALAYA // API — imagen endurecida
#  Multi-stage: las herramientas de build no llegan a la imagen final.
#
#  La MISMA imagen corre en tres lugares sin cambios:
#    · Docker Compose (local)  → uvicorn en el 8000
#    · AWS Lambda              → el Lambda Web Adapter traduce los eventos
#                                de Lambda a HTTP contra ese mismo uvicorn
#    · ECS / cualquier runtime de contenedores
#  Fuera de Lambda el adaptador es un archivo inerte en /opt/extensions.
# ══════════════════════════════════════════════════════════════════════

# Adaptador de Lambda como etapa con nombre: fijado por versión y copiado
# desde una etapa declarada (hadolint DL3022), no desde una imagen suelta.
FROM public.ecr.aws/awsguru/aws-lambda-adapter:1.0.1 AS lambda-adapter

FROM python:3.12-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build
COPY requirements.txt .
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip setuptools wheel \
    && /opt/venv/bin/pip install -r requirements.txt


# ──────────────────────────────────────────────────────────────────────
FROM python:3.12-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="atalaya-api" \
      org.opencontainers.image.description="Feed de Misiones CTI + motor de progresión" \
      org.opencontainers.image.source="https://github.com/gonzalodiascenzi/atalaya" \
      org.opencontainers.image.licenses="MIT"

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    # ── Lambda Web Adapter ──
    # Nuestra API escucha en el 8000; el adaptador asume 8080 por defecto y
    # sin esto se quedaría esperando en el puerto equivocado hasta el timeout.
    AWS_LWA_PORT=8000 \
    # /health es la sonda de VIDA: no toca la base. Si el adaptador usara
    # /health/ready, un parpadeo de Neon impediría arrancar la función.
    AWS_LWA_READINESS_CHECK_PATH=/health

# ca-certificates explícito: la verificación TLS contra Neon usa el almacén
# del sistema (ver config.split_tls). Antes llegaba de rebote como
# dependencia de curl; ahora es un requisito de seguridad, no un accidente.
# hadolint ignore=DL3008
RUN groupadd --gid 10001 atalaya \
    && useradd --uid 10001 --gid atalaya --no-create-home --shell /usr/sbin/nologin atalaya \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv
COPY --from=lambda-adapter /lambda-adapter /opt/extensions/lambda-adapter

WORKDIR /app
COPY --chown=atalaya:atalaya . /app

# UID numérico: runAsNonRoot de Kubernetes no puede verificar un nombre.
USER 10001:10001
EXPOSE 8000

# `curl -f` ya sale con error ante un HTTP 4xx/5xx: el `|| exit 1` sobraba.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["curl", "-fsS", "http://localhost:8000/health"]

# --no-proxy-headers: en Lambda los pedidos llegan desde 127.0.0.1 (el Web
# Adapter) y Uvicorn, por defecto, le cree el X-Forwarded-For a 127.0.0.1.
# Detrás de una Function URL esa cabecera la escribe el cliente. La IP real
# viene por otro lado (API_CLIENT_IP_HEADER).
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers"]
