"""
ATALAYA // Conexión a PostgreSQL.

El motor y el sessionmaker se crean una sola vez por proceso (perezosamente),
para que importar este módulo no abra conexiones — algo que rompe los tests y
los comandos de Alembic.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from config import get_settings

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    """Motor asíncrono, creado bajo demanda."""
    global _engine
    if _engine is None:
        settings = get_settings()
        _engine = create_async_engine(
            settings.async_database_url,
            echo=settings.db_echo,
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
            # Recicla conexiones antes de que el proveedor las corte por
            # inactividad: Neon y Cloud SQL cierran conexiones ociosas y el
            # síntoma es un error opaco en la primera consulta después.
            pool_recycle=1800,
            pool_pre_ping=True,
        )
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(),
            expire_on_commit=False,
            autoflush=False,
        )
    return _session_factory


async def get_session() -> AsyncIterator[AsyncSession]:
    """Dependencia de FastAPI: una sesión por petición, con rollback si falla."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def dispose_engine() -> None:
    """Cierra el pool. Se llama en el apagado del lifespan."""
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _session_factory = None


def reset_engine_cache() -> None:
    """Olvida el motor cacheado. Sólo para tests que cambian de base."""
    global _engine, _session_factory
    _engine = None
    _session_factory = None
