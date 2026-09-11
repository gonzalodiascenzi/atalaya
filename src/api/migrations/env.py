"""
ATALAYA // Entorno de Alembic (asíncrono).

La URL sale de la configuración de la aplicación, no del alembic.ini: así hay
una sola definición del DSN y ningún archivo versionado contiene credenciales.
"""

from __future__ import annotations

import asyncio
import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

# `src/api` al path: los módulos de la API se importan planos, igual que como
# los resuelve uvicorn dentro del contenedor.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from config import get_settings, split_tls  # noqa: E402
from models import Base  # noqa: E402

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _database() -> tuple[str, dict]:
    """(DSN asíncrono, argumentos TLS). Override por entorno para CI y tests.

    Las migraciones pasan por la misma traducción que la API: si no, la API
    conectaría a Neon y el job de migración reventaría con el mismo TypeError.
    """
    override = os.getenv("ALEMBIC_DATABASE_URL")
    if override:
        return split_tls(override)
    s = get_settings()
    return s.async_database_url, s.database_connect_args


def _database_url() -> str:
    return _database()[0]


def run_migrations_offline() -> None:
    """Genera el SQL sin conectarse. Útil para revisar antes de aplicar."""
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        # Detecta cambios de tipo y de nulabilidad, que por defecto Alembic
        # ignora y son justamente los que rompen en producción.
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    url, connect_args = _database()
    connectable = async_engine_from_config(
        {"sqlalchemy.url": url},
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        connect_args=connect_args,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
