"""
Configuración de pytest.

Los tests corren contra **PostgreSQL real**, no SQLite. Si el motor de los
tests difiere del de producción, los tests mienten: el índice parcial único,
las funciones de ventana y `SELECT ... FOR UPDATE` que usa el repositorio no
existen o se comportan distinto en SQLite.

`pgserver` levanta un PostgreSQL efímero sobre un socket unix, sin Docker y
sin instalación de sistema. En CI se usa el servicio de Postgres de GitHub
Actions vía la variable TEST_DATABASE_URL.
"""

import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
API_DIR = REPO_ROOT / "src" / "api"
sys.path.insert(0, str(API_DIR))
sys.path.insert(0, str(REPO_ROOT / "src" / "ingestion"))


@pytest.fixture(scope="session")
def database_url() -> str:
    """DSN de la base de pruebas.

    Prioriza TEST_DATABASE_URL (CI); si no está, levanta un PostgreSQL
    efímero con pgserver y lo apaga al terminar la sesión.
    """
    external = os.getenv("TEST_DATABASE_URL")
    if external:
        yield external
        return

    import pgserver

    workdir = Path(tempfile.mkdtemp(prefix="atalaya-pg-"))
    server = pgserver.get_server(str(workdir), cleanup_mode=None)
    server.psql("CREATE DATABASE atalaya_test;")
    dsn = f"postgresql+asyncpg://postgres@/atalaya_test?host={workdir}"

    yield dsn

    try:
        server.cleanup()
    except Exception:  # pragma: no cover - el apagado no debe romper la suite
        pass
    shutil.rmtree(workdir, ignore_errors=True)


@pytest.fixture(scope="session", autouse=True)
def migrated_database(database_url):
    """Aplica las migraciones de Alembic antes de que corra ningún test.

    Se migra en vez de usar `Base.metadata.create_all()` a propósito: así lo
    que se testea es el esquema que realmente se va a desplegar, migraciones
    incluidas. Un `create_all` verde con una migración rota es el peor
    resultado posible.
    """
    os.environ["DATABASE_URL"] = database_url
    os.environ["ALEMBIC_DATABASE_URL"] = database_url
    os.environ.setdefault("API_SECRET_KEY", "clave-de-pruebas-no-usar-en-produccion")
    os.environ.setdefault("ATALAYA_ENV", "test")
    # La suite entera sale por la misma "IP" del TestClient, así que el
    # limitador por IP la corta a mitad de camino y hace fallar tests que no
    # tienen nada que ver. Se sube el techo para los tests; el límite en sí
    # tiene su propio test dedicado.
    os.environ.setdefault("API_RATE_LIMIT", "100000")

    from alembic import command
    from alembic.config import Config

    cfg = Config(str(API_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(API_DIR / "migrations"))
    command.upgrade(cfg, "head")

    yield

    # `downgrade base` verifica que la migración sea reversible. Una migración
    # que no sabe volver atrás es una migración que no se puede desplegar con
    # confianza.
    command.downgrade(cfg, "base")


@pytest.fixture(scope="session")
def client(migrated_database):
    """Cliente de pruebas de FastAPI, con el lifespan ejecutado."""
    from fastapi.testclient import TestClient

    from main import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def fresh_engine():
    """Motor de reglas limpio. Es puro: no toca la base."""
    from gamification import ProgressionEngine

    return ProgressionEngine()


# ══════════════════════════════════════════════════════════════════════
#  Identidad
# ══════════════════════════════════════════════════════════════════════

#: Frase larga y aburrida. Cumple el mínimo sin ser un secreto de verdad.
TEST_PASSWORD = "frase-larga-de-prueba-atalaya-2026"


@pytest.fixture(scope="session")
def token_for(client):
    """Devuelve cabeceras de autorización para un callsign, dándolo de alta.

    Se limpian las cookies del cliente después de cada alta: si quedaran,
    el TestClient mandaría la sesión del último registrado en TODAS las
    peticiones siguientes, y los tests estarían probando otra cosa sin que
    se note. La identidad viaja explícita, por cabecera.
    """
    cache: dict[str, dict[str, str]] = {}

    def _token(callsign: str) -> dict[str, str]:
        if callsign in cache:
            return cache[callsign]
        payload = {"callsign": callsign, "password": TEST_PASSWORD}
        res = client.post("/api/v1/auth/register", json=payload)
        if res.status_code == 409:
            res = client.post("/api/v1/auth/login", json=payload)
        assert res.status_code in (200, 201), res.text
        client.cookies.clear()
        cache[callsign] = {"Authorization": f"Bearer {res.json()['access_token']}"}
        return cache[callsign]

    return _token


@pytest.fixture(scope="session")
def instructor_token(client, token_for):
    """Cabeceras de un analista con rol INSTRUCTOR.

    El rol se eleva por SQL directo: no existe —ni debe existir— un endpoint
    que permita ascenderse a uno mismo.
    """
    import asyncio

    callsign = "instructor-de-pruebas"
    token_for(callsign)

    async def promover():
        from sqlalchemy import text as sa_text
        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy.pool import NullPool

        from config import get_settings

        engine = create_async_engine(
            get_settings().async_database_url, poolclass=NullPool
        )
        try:
            async with engine.begin() as conn:
                await conn.execute(
                    sa_text("UPDATE analysts SET role='INSTRUCTOR' WHERE callsign=:c"),
                    {"c": callsign},
                )
        finally:
            await engine.dispose()

    asyncio.run(promover())

    # El rol viaja dentro del token, así que hay que pedir uno nuevo.
    res = client.post(
        "/api/v1/auth/login",
        json={"callsign": callsign, "password": TEST_PASSWORD},
    )
    client.cookies.clear()
    assert res.json()["role"] == "INSTRUCTOR"
    return {"Authorization": f"Bearer {res.json()['access_token']}"}
