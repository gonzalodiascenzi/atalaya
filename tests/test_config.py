"""
ATALAYA // Traducción de la cadena de conexión.

Las cadenas de prueba NO llevan usuario ni contraseña: lo que se prueba son
los parámetros, y una URI de Postgres con usuario y contraseña embebidos es
justo lo que TruffleHog detecta — hasta intenta conectarse para verificarla.
(Tampoco se escribe un ejemplo literal acá: el comentario mismo lo dispararía.)

Neon entrega `?sslmode=require&channel_binding=require` y asyncpg no acepta
ninguno de los dos: la API reventaba en producción con un TypeError en la
primera consulta. Estos tests fijan la traducción — sin red.
"""

import ssl

import pytest

from config import split_tls

NEON = (
    "postgresql+asyncpg://ep-x.us-east-2.aws.neon.tech/neondb"
    "?sslmode=require&channel_binding=require"
)


def test_la_url_de_neon_queda_sin_parametros_de_libpq():
    url, _ = split_tls(NEON)
    assert "sslmode" not in url
    assert "channel_binding" not in url


def test_channel_binding_se_compensa_verificando_el_certificado():
    """Perder channel binding en silencio sería una degradación de seguridad.

    Era la protección contra un intermediario; se reemplaza por verificar la
    cadena y el nombre de host contra el almacén del sistema.
    """
    _, args = split_tls(NEON)
    ctx = args["ssl"]
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode is ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_verificar_no_se_escribe_como_texto():
    """`ssl=verify-full` como cadena busca ~/.postgresql/root.crt.

    En Lambda ese archivo no existe y la API no conectaría nunca. Tiene que
    ser un SSLContext, que usa los certificados del sistema.
    """
    _, args = split_tls("postgresql+asyncpg://h/db?sslmode=verify-full")
    assert not isinstance(args["ssl"], str)


def test_verify_ca_no_chequea_el_nombre_de_host():
    """Misma semántica que libpq: verify-ca valida la cadena, no el host."""
    _, args = split_tls("postgresql+asyncpg://h/db?sslmode=verify-ca")
    assert args["ssl"].verify_mode is ssl.CERT_REQUIRED
    assert args["ssl"].check_hostname is False


@pytest.mark.parametrize("modo", ["require", "prefer", "disable"])
def test_los_demas_modos_se_pasan_tal_cual(modo):
    """Sin channel binding no hay nada que compensar: se respeta lo pedido."""
    _, args = split_tls(f"postgresql+asyncpg://h/db?sslmode={modo}")
    assert args == {"ssl": modo}


def test_sin_parametros_no_toca_nada():
    dsn = "postgresql+asyncpg://postgres@/atalaya?host=/tmp/pg"
    assert split_tls(dsn) == (dsn, {})


def test_los_otros_parametros_sobreviven():
    url, _ = split_tls(
        "postgresql+asyncpg://h/db?sslmode=require&application_name=atalaya"
    )
    assert "application_name=atalaya" in url


def test_el_esquema_postgresql_se_normaliza(monkeypatch):
    """Los proveedores entregan `postgresql://`; SQLAlchemy async necesita el driver."""
    from config import Settings

    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql://ep-x.neon.tech/neondb?sslmode=require&channel_binding=require",
    )
    s = Settings()
    assert s.async_database_url.startswith("postgresql+asyncpg://")
    assert isinstance(s.database_connect_args["ssl"], ssl.SSLContext)
