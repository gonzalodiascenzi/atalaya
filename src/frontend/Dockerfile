# ══════════════════════════════════════════════════════════════════════
#  ATALAYA // Frontend — imagen endurecida (Next.js standalone)
# ══════════════════════════════════════════════════════════════════════
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
# `npm ci` exige lockfile; si todavía no se commiteó, cae a install.
RUN if [ -f package-lock.json ]; then npm ci; else npm install --no-audit --no-fund; fi


FROM node:22-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# CRÍTICO: Next incrusta las variables NEXT_PUBLIC_* en el bundle del
# navegador durante el BUILD. Pasarlas como variable de entorno del
# contenedor en runtime NO afecta al código que corre en el cliente —
# el bundle ya salió compilado con el valor que había acá.
# Por eso viaja como build-arg y no como env de Cloud Run / Compose.
ARG NEXT_PUBLIC_API_URL=http://localhost:8000
ARG NEXT_PUBLIC_CALLSIGN=operador
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL \
    NEXT_PUBLIC_CALLSIGN=$NEXT_PUBLIC_CALLSIGN \
    NEXT_TELEMETRY_DISABLED=1

RUN npm run build


FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000

RUN addgroup -g 10002 -S atalaya && adduser -u 10002 -S atalaya -G atalaya

# El build standalone ya trae sólo las dependencias que realmente se usan.
COPY --from=builder --chown=atalaya:atalaya /app/.next/standalone ./
COPY --from=builder --chown=atalaya:atalaya /app/.next/static ./.next/static
COPY --from=builder --chown=atalaya:atalaya /app/public ./public

USER atalaya
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD wget -qO- http://localhost:3000/ >/dev/null 2>&1 || exit 1

CMD ["node", "server.js"]
