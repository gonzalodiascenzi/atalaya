# ══════════════════════════════════════════════════════════════════════
#  ATALAYA // API — imagen endurecida
#  Multi-stage: las herramientas de build no llegan a la imagen final.
# ══════════════════════════════════════════════════════════════════════
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
      org.opencontainers.image.licenses="MIT"

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Usuario sin privilegios: si alguien escapa del proceso, que no sea root.
RUN groupadd --gid 10001 atalaya \
    && useradd --uid 10001 --gid atalaya --no-create-home --shell /usr/sbin/nologin atalaya \
    && apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=atalaya:atalaya . /app

USER atalaya
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://localhost:8000/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
