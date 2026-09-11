"""
ATALAYA // Configuración de la API.

Todo valor sensible entra por variables de entorno (12-factor). Nada de
constantes hardcodeadas: si mañana esto corre en ECS, el mismo binario sirve.
"""

import os
import ssl
from functools import lru_cache
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuración tipada de la torre."""

    model_config = SettingsConfigDict(
        env_file=(".env", "../../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ── Identidad ────────────────────────────────────────────────────
    atalaya_env: str = "local"
    api_host: str = "0.0.0.0"  # nosec B104 - escuchar en todas las interfaces
    # es lo correcto DENTRO de un contenedor: quien restringe el acceso es la
    # red (Compose, Cloud Run, firewall), no el bind del proceso.
    api_port: int = 8000
    api_log_level: str = "info"

    # Clave de firma. El default sólo existe para que `--help` no explote:
    # si el entorno es prod y sigue siendo el default, arrancamos en rojo.
    api_secret_key: str = "insecure-dev-key-change-me"

    # ── CORS ─────────────────────────────────────────────────────────
    # Se guarda como string crudo a propósito: pydantic-settings intenta
    # parsear listas como JSON y una lista separada por comas lo rompe.
    api_cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"

    # ── Limitación de tasa ───────────────────────────────────────────
    # Configurable porque el valor correcto depende del despliegue: una demo
    # pública, un aula de treinta personas detrás de un mismo NAT y una suite
    # de tests no toleran el mismo techo. Con todos saliendo por la misma IP
    # pública, un límite por IP castiga al grupo entero.
    api_rate_limit: int = 120
    api_rate_window: float = 60.0
    #: Cabecera de la que sale la IP del cliente para el limitador. Vacía =
    #: la IP de la conexión. En AWS la escribe una CloudFront Function (ver
    #: infra/terraform/cdn.tf); sólo se puede confiar en ella porque la
    #: Function URL rechaza todo pedido que no venga firmado por CloudFront.
    api_client_ip_header: str = ""

    # ── Persistencia ─────────────────────────────────────────────────
    # Sin default utilizable a propósito: la API ya no guarda progresión en
    # memoria. Arrancar sin base sería arrancar perdiendo datos en silencio.
    database_url: str = ""
    db_pool_size: int = 5
    db_max_overflow: int = 5
    db_echo: bool = False

    # ── Feed ─────────────────────────────────────────────────────────
    api_feed_page_size: int = 20
    api_feed_max_page_size: int = 100

    # ── Umbrales de rango (XP acumulada) ─────────────────────────────
    xp_novato: int = 0
    xp_analista_junior: int = 250
    xp_analista_senior: int = 1200
    xp_cazador_de_amenazas: int = 4000

    # ── Integraciones (la API sólo lee; escribe el conector) ─────────
    opencti_url: str = "http://opencti:8080"
    misp_baseurl: str = "https://localhost:8443"
    default_tlp: str = "TLP:CLEAR"

    @property
    def cors_origins(self) -> list[str]:
        """Convierte la lista separada por comas en algo usable.

        `none` = ningún origen cruzado: la consola y la API comparten dominio.
        Hace falta una palabra porque Lambda descarta las variables vacías, y
        sin la variable se aplicaría el valor por defecto de desarrollo.
        """
        if self.api_cors_origins.strip().lower() == "none":
            return []
        return [o.strip() for o in self.api_cors_origins.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.atalaya_env.lower() in {"prod", "production"}

    #: Longitud mínima de la clave de firma. Con HS256, la fuerza del token
    #: es exactamente la fuerza de esta cadena: una clave corta se rompe por
    #: fuerza bruta fuera de línea y a partir de ahí se firman sesiones de
    #: administrador sin tocar el servidor.
    MIN_SECRET_KEY_LENGTH: int = 32

    def assert_production_ready(self) -> None:
        """Verifica que no se arranque en producción con valores de juguete.

        Se ABORTA en vez de sólo advertir. Un aviso en el log es un aviso que
        nadie lee, y el costo de equivocarse acá es que cualquiera que lea el
        repositorio pueda firmarse un token de ADMIN.
        """
        if not self.is_production:
            return

        problemas: list[str] = []
        if self.api_secret_key.startswith("insecure-dev"):
            problemas.append(
                "API_SECRET_KEY sigue en el valor por defecto del repositorio: "
                "cualquiera puede firmar tokens válidos"
            )
        elif len(self.api_secret_key) < self.MIN_SECRET_KEY_LENGTH:
            problemas.append(
                f"API_SECRET_KEY tiene {len(self.api_secret_key)} caracteres; "
                f"hacen falta al menos {self.MIN_SECRET_KEY_LENGTH}"
            )
        if "*" in self.api_cors_origins:
            problemas.append(
                "API_CORS_ORIGINS contiene '*' y la API envía cookies de sesión: "
                "cualquier sitio podría operar en nombre del analista"
            )
        locales = [o for o in self.cors_origins if "localhost" in o or "127.0.0.1" in o]
        if locales:
            problemas.append(
                f"API_CORS_ORIGINS admite orígenes locales ({', '.join(locales)}): "
                "es el valor de desarrollo. Si la consola comparte dominio con la "
                "API, poné API_CORS_ORIGINS=none"
            )
        if not self.database_url.strip():
            problemas.append("DATABASE_URL no está configurada")

        if problemas:
            detalle = "\n  · ".join(problemas)
            raise RuntimeError(
                "ATALAYA no arranca en producción con esta configuración:\n  · "
                f"{detalle}\n\n"
                "Generá los secretos con:  openssl rand -hex 32"
            )

    @property
    def async_database_url(self) -> str:
        """Normaliza el DSN al driver asíncrono.

        Casi todos los proveedores (Neon, Supabase, Cloud SQL) entregan la
        cadena como `postgresql://`. SQLAlchemy async necesita el driver
        explícito, y el error que tira cuando falta no dice eso.
        """
        dsn = self.database_url.strip()
        if not dsn:
            raise RuntimeError(
                "DATABASE_URL no está configurada. La API necesita PostgreSQL:\n"
                "  · local  -> make db-up\n"
                "  · nube   -> cargá el DSN en el secreto atalaya-database-url"
            )
        for prefijo in ("postgresql://", "postgres://"):
            if dsn.startswith(prefijo):
                dsn = "postgresql+asyncpg://" + dsn[len(prefijo) :]
                break
        return split_tls(dsn)[0]

    @property
    def database_connect_args(self) -> dict:
        """Argumentos TLS para el driver. Ver `split_tls`."""
        return split_tls(self.database_url.strip())[1]


def split_tls(dsn: str) -> tuple[str, dict]:
    """Separa los parámetros TLS de libpq de la URL y los traduce para asyncpg.

    Neon, Supabase y Cloud SQL entregan la cadena en dialecto libpq:
    `?sslmode=require&channel_binding=require`. asyncpg no acepta ninguno de
    los dos en la URL y revienta con `TypeError: connect() got an unexpected
    keyword argument 'sslmode'` — en producción, en la primera consulta.

    Devuelve (URL sin esos parámetros, connect_args para el motor).

    Por qué la verificación va como SSLContext y no como texto en la URL:
    `ssl=verify-full` escrito como cadena sigue la semántica de libpq y busca
    un certificado raíz en ~/.postgresql/root.crt, que en Lambda o en un
    contenedor no existe: la API no conectaría nunca. Un SSLContext de
    `ssl.create_default_context()` verifica cadena y nombre de host contra el
    almacén de certificados del sistema. Las dos cosas fueron verificadas
    contra un endpoint real de Neon.

    Reglas:
      · channel_binding presente → se quita (asyncpg no lo implementa) y se
        compensa verificando el certificado: era la protección contra un
        intermediario, y no se pierde en silencio.
      · verify-full / verify-ca  → SSLContext (verify-ca sin chequeo de host).
      · require / prefer / ...   → se pasa tal cual: misma semántica que libpq.
    """
    partes = urlsplit(dsn)
    params = dict(parse_qsl(partes.query, keep_blank_values=True))
    if "sslmode" not in params and "channel_binding" not in params:
        # Nada que traducir: la cadena vuelve intacta. Reconstruirla igual
        # re-codificaría valores como `host=/tmp/pg` → `host=%2Ftmp%2Fpg`.
        return dsn, {}
    modo = params.pop("sslmode", None)
    canal = params.pop("channel_binding", None)
    url = urlunsplit(partes._replace(query=urlencode(params, safe="/")))

    if canal in {"require", "prefer"} or modo in {"verify-full", "verify-ca"}:
        contexto = ssl.create_default_context()
        if modo == "verify-ca":
            contexto.check_hostname = False
        return url, {"ssl": contexto}
    if modo:
        return url, {"ssl": modo}
    return url, {}


#: Variable de entorno → variable que se completa con el valor leído de SSM.
#: En Lambda, las variables de entorno sólo traen el NOMBRE del parámetro; el
#: secreto se lee en el arranque. Así no queda en la configuración de la
#: función, ni en la consola de AWS, ni en el estado de Terraform.
_SECRETOS_SSM = {
    "DATABASE_URL_SSM": "DATABASE_URL",
    "API_SECRET_KEY_SSM": "API_SECRET_KEY",
}


def load_ssm_secrets(cliente=None) -> list[str]:
    """Completa el entorno con los secretos de SSM Parameter Store.

    Sólo actúa si hay variables `*_SSM` (o sea, en AWS). Localmente no hace
    nada y ni siquiera importa boto3. Devuelve qué variables completó.

    Falla FUERTE si un parámetro declarado no se puede leer: arrancar sin la
    clave de firma o sin la base es peor que no arrancar.
    """
    pedidos = {env: destino for env, destino in _SECRETOS_SSM.items() if os.getenv(env)}
    if not pedidos:
        return []

    if cliente is None:
        import boto3  # sólo en AWS

        cliente = boto3.client("ssm")

    nombres = [os.environ[env] for env in pedidos]
    respuesta = cliente.get_parameters(Names=nombres, WithDecryption=True)
    faltan = respuesta.get("InvalidParameters") or []
    if faltan:
        raise RuntimeError(
            "No se pudieron leer estos secretos de SSM: "
            + ", ".join(faltan)
            + ". ¿Se cargaron con `aws ssm put-parameter`? Ver outputs de Terraform."
        )

    valores = {p["Name"]: p["Value"] for p in respuesta["Parameters"]}
    completadas = []
    for env, destino in pedidos.items():
        os.environ[destino] = valores[os.environ[env]]
        completadas.append(destino)
    return completadas


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Singleton cacheado: se lee el entorno una sola vez por proceso.

    En AWS, primero trae los secretos de SSM: tienen que estar en el entorno
    ANTES de construir Settings, porque `assert_production_ready` los valida.
    """
    load_ssm_secrets()
    return Settings()
