# ══════════════════════════════════════════════════════════════
#  ATALAYA // torre de control
#  `make` sin argumentos lista los objetivos disponibles.
# ══════════════════════════════════════════════════════════════
.DEFAULT_GOAL := help
SHELL := /bin/bash
COMPOSE := docker compose -f deployments/docker/docker-compose.yml --env-file .env

.PHONY: help
help: ## Muestra esta ayuda
	@echo ""
	@echo "  ATALAYA // objetivos disponibles"
	@echo "  ─────────────────────────────────────────────"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
	@echo ""

.PHONY: env
env: ## Crea .env a partir de la plantilla (no pisa el existente)
	@test -f .env && echo "[=] .env ya existe, no lo toco." || (cp .env.example .env && echo "[+] .env creado. Editalo ANTES de levantar nada.")

.PHONY: up
up: ## Levanta el stack mínimo (API + frontend)
	$(COMPOSE) up -d --build api
	@echo "[+] API   -> http://localhost:8000/docs"

.PHONY: up-cti
up-cti: ## Levanta el stack CTI completo (OpenCTI + MISP + deps). Necesita ~8 GB RAM
	$(COMPOSE) --profile cti up -d
	@echo "[+] OpenCTI -> http://localhost:8080"
	@echo "[+] MISP    -> https://localhost:8443"

.PHONY: down
down: ## Baja todo (conserva volúmenes)
	$(COMPOSE) --profile cti --profile hunt down

.PHONY: nuke
nuke: ## Baja todo y BORRA los volúmenes. Irreversible.
	$(COMPOSE) --profile cti --profile hunt down -v

.PHONY: logs
logs: ## Sigue los logs de todos los servicios
	$(COMPOSE) logs -f --tail=100

.PHONY: db-up
db-up: ## Levanta sólo PostgreSQL (la API no arranca sin base)
	$(COMPOSE) up -d postgres
	@echo "[+] PostgreSQL escuchando. Aplicá las migraciones con: make db-upgrade"

.PHONY: db-upgrade
db-upgrade: ## Aplica las migraciones pendientes
	cd src/api && alembic upgrade head

.PHONY: db-downgrade
db-downgrade: ## Revierte la última migración
	cd src/api && alembic downgrade -1

.PHONY: db-revision
db-revision: ## Genera una migración nueva. Uso: make db-revision M="descripcion"
	@test -n "$(M)" || (echo "Falta el mensaje: make db-revision M=\"agregar tabla X\""; exit 1)
	cd src/api && alembic revision --autogenerate -m "$(M)"

.PHONY: db-history
db-history: ## Historial de migraciones y revisión actual
	cd src/api && alembic history --verbose && alembic current

.PHONY: db-sql
db-sql: ## Imprime el SQL de las migraciones sin aplicarlo (revisión previa)
	cd src/api && alembic upgrade head --sql

.PHONY: api-dev
api-dev: ## API en modo desarrollo con reload (necesita make db-up primero)
	cd src/api && uvicorn main:app --reload --host 0.0.0.0 --port 8000

.PHONY: front-dev
front-dev: ## Frontend Next.js en modo desarrollo
	cd src/frontend && npm run dev

.PHONY: ingest-dry
ingest-dry: ## Consulta las fuentes OSINT y muestra, sin escribir nada
	python3 src/ingestion/run.py --dry-run

.PHONY: ingest
ingest: ## Consulta las fuentes y persiste las misiones
	python3 src/ingestion/run.py --ingest

.PHONY: ingest-resolve
ingest-resolve: ## Cierra la corroboración de las misiones vencidas
	python3 src/ingestion/run.py --resolve

.PHONY: ingest-loop
ingest-loop: ## Ciclo continuo de ingesta (perfil docker `ingesta`)
	$(COMPOSE) --profile ingesta up -d ingesta
	@echo "[+] Ciclo cada $${INGEST_INTERVAL_MINUTES:-15} min. Logs: make logs"

.PHONY: stix
stix: ## Genera el bundle STIX 2.1 de ejemplo (caso ransomware)
	python3 src/ingestion/misp_stix_connector.py --pretty

.PHONY: stix-validate
stix-validate: ## Genera y valida el bundle contra las reglas STIX 2.1
	python3 src/ingestion/misp_stix_connector.py --validate

.PHONY: lint
lint: ## flake8 sobre todo el Python del repo
	flake8 src/api src/ingestion tests

.PHONY: test
test: ## Corre la suite de tests
	pytest

.PHONY: secrets
secrets: ## Escaneo local de secretos (necesita gitleaks instalado)
	gitleaks detect --no-git --redact -v

.PHONY: tf-plan
tf-plan: ## Plan de Terraform (requiere infra/terraform/terraform.tfvars)
	cd infra/terraform && terraform init -input=false && terraform plan
