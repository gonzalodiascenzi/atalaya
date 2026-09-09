"""
ATALAYA // Configuración de la API.

Todo valor sensible entra por variables de entorno (12-factor). Nada de
constantes hardcodeadas: si mañana esto corre en ECS, el mismo binario sirve.
"""

from functools import lru_cache

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
        """Convierte la lista separada por comas en algo usable."""
        return [o.strip() for o in self.api_cors_origins.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.atalaya_env.lower() in {"prod", "production"}

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
        if dsn.startswith("postgresql+asyncpg://"):
            return dsn
        if dsn.startswith("postgresql://"):
            return dsn.replace("postgresql://", "postgresql+asyncpg://", 1)
        if dsn.startswith("postgres://"):
            return dsn.replace("postgres://", "postgresql+asyncpg://", 1)
        return dsn


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Singleton cacheado: se lee el entorno una sola vez por proceso."""
    return Settings()
