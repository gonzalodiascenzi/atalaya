"""
ATALAYA // Contrato común de los conectores.

Todo conector hace lo mismo: hablar con una fuente y devolver
`RawIndicator`. La normalización a STIX, el conteo de corroboración y la
resolución de la verdad ocurren después, una sola vez, para todos.

La pieza no obvia de este módulo es `SourceFamily`.

    Contar "fuentes independientes" contando nombres de fuente es un error
    silencioso: ThreatFox, URLhaus y MalwareBazaar son tres APIs distintas
    del MISMO operador (abuse.ch). Un indicador presente en las tres no está
    corroborado por tres partes: está corroborado por una, tres veces.

    Si eso contara como 3, cruzaría el umbral de corroboración solo y el
    sistema declararía verdades que nadie verificó de forma independiente.
    Por eso la unidad de conteo es la FAMILIA, no el nombre.
"""

from __future__ import annotations

import hashlib
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)


class SourceFamily(str, Enum):
    """Operador detrás de la fuente. Es la unidad de independencia real."""

    ABUSE_CH = "abuse.ch"
    ALIENVAULT = "alienvault"
    CISA = "cisa"
    SPIDERFOOT = "spiderfoot"
    INTERNAL = "internal"


class SourceName(str, Enum):
    """Fuente concreta. Varias pueden compartir familia."""

    OTX = "AlienVault OTX"
    THREATFOX = "abuse.ch ThreatFox"
    URLHAUS = "abuse.ch URLhaus"
    CISA_KEV = "CISA KEV"

    @property
    def family(self) -> SourceFamily:
        return _FAMILIES[self]


_FAMILIES: dict[SourceName, SourceFamily] = {
    SourceName.OTX: SourceFamily.ALIENVAULT,
    SourceName.THREATFOX: SourceFamily.ABUSE_CH,
    SourceName.URLHAUS: SourceFamily.ABUSE_CH,
    SourceName.CISA_KEV: SourceFamily.CISA,
}


class IndicatorKind(str, Enum):
    """Tipo de observable, en el vocabulario que después usa el patrón STIX."""

    IPV4 = "ipv4-addr"
    DOMAIN = "domain-name"
    URL = "url"
    SHA256 = "file:sha256"
    MD5 = "file:md5"
    CVE = "vulnerability"


#: Rangos reservados por RFC 5737 y dominios de RFC 2606. Un indicador que
#: cae acá viene de una fuente que se equivocó o de una prueba: publicarlo
#: como amenaza real haría que alguien bloquee documentación.
_RESERVADOS = (
    re.compile(r"^192\.0\.2\."),
    re.compile(r"^198\.51\.100\."),
    re.compile(r"^203\.0\.113\."),
    re.compile(r"^10\."),
    re.compile(r"^127\."),
    re.compile(r"^169\.254\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"\.(example|invalid|test|localhost)$", re.I),
)


@dataclass(frozen=True)
class RawIndicator:
    """Un indicador tal como lo reportó una fuente, ya normalizado de forma.

    Los campos no son decorativos: son exactamente lo que el bucle de
    verificación necesita para poder calificar (ver docs/VERIFICACION.md §6).
    Un conector que devuelva sólo "IP maliciosa" no sirve para nada.
    """

    value: str
    kind: IndicatorKind
    source: SourceName
    source_reference: str
    source_confidence: int
    first_reported_at: datetime
    malware_family: str | None = None
    attack_technique: str | None = None
    description: str | None = None
    sample_available: bool = False
    kev_listed: bool = False
    tags: tuple[str, ...] = field(default_factory=tuple)

    @property
    def fingerprint(self) -> str:
        """Clave de deduplicación entre fuentes.

        Se normaliza para que `EVIL.COM.` y `evil.com` sean el mismo hecho:
        sin esto, la misma amenaza reportada por dos fuentes contaría como
        dos indicadores distintos y jamás alcanzaría el umbral.
        """
        v = self.value.strip().lower().rstrip(".")
        if self.kind is IndicatorKind.URL:
            v = v.rstrip("/")
        return f"{self.kind.value}:{v}"

    @property
    def is_reserved(self) -> bool:
        """True si el observable cae en rango reservado o dominio de ejemplo."""
        return any(p.search(self.value) for p in _RESERVADOS)

    def stix_pattern(self) -> str:
        """Patrón STIX 2.1 correspondiente a este observable."""
        v = self.value.replace("'", "\\'")
        if self.kind is IndicatorKind.SHA256:
            return f"[file:hashes.'SHA-256' = '{v}']"
        if self.kind is IndicatorKind.MD5:
            return f"[file:hashes.'MD5' = '{v}']"
        if self.kind is IndicatorKind.CVE:
            return f"[vulnerability:name = '{v}']"
        return f"[{self.kind.value}:value = '{v}']"


class ConnectorError(Exception):
    """La fuente no pudo consultarse. Nunca aborta la corrida completa."""


class ConnectorDisabled(ConnectorError):
    """Falta la credencial de la fuente. Es un aviso, no un error."""


class RateLimiter:
    """Espaciado mínimo entre peticiones a una misma fuente.

    Las APIs OSINT gratuitas se sostienen con buena fe. Golpearlas sin freno
    consigue que te bloqueen —y de paso arruina la fuente para el resto—, así
    que el límite es parte del conector, no una opción.
    """

    def __init__(self, min_interval_seconds: float) -> None:
        self._interval = min_interval_seconds
        self._last = 0.0

    def wait(self) -> None:
        transcurrido = time.monotonic() - self._last
        if transcurrido < self._interval:
            time.sleep(self._interval - transcurrido)
        self._last = time.monotonic()


class Connector(ABC):
    """Base de todos los conectores."""

    name: SourceName
    #: Variable de entorno sin la cual la fuente no puede consultarse.
    requires_env: str | None = None
    #: Segundos mínimos entre peticiones.
    min_interval: float = 1.0
    #: Confianza por defecto cuando la fuente no informa una.
    default_confidence: int = 50

    def __init__(self, client: httpx.Client | None = None) -> None:
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(20.0),
            headers={"User-Agent": "ATALAYA-CTI/1.0 (academia; +cti@atalaya.local)"},
            follow_redirects=True,
        )
        self._limiter = RateLimiter(self.min_interval)

    # ── Contrato ────────────────────────────────────────────────────
    @abstractmethod
    def fetch(self, limit: int) -> list[RawIndicator]:
        """Consulta la fuente y devuelve indicadores normalizados."""

    def check_credentials(self, env: dict[str, str]) -> None:
        """Lanza ConnectorDisabled si falta lo necesario para consultar."""
        if self.requires_env is None:
            return
        valor = (env.get(self.requires_env) or "").strip()
        if not valor or valor.startswith("PENDIENTE") or "CAMBIAR" in valor:
            raise ConnectorDisabled(
                f"{self.name.value}: falta {self.requires_env} en el entorno. "
                f"La fuente queda fuera de esta corrida."
            )

    # ── HTTP con reintentos ─────────────────────────────────────────
    @retry(
        stop=stop_after_attempt(3),
        # Espera creciente: 2s, 4s, 8s. Reintentar al toque contra una API
        # que está saturada sólo la satura más.
        wait=wait_exponential(multiplier=2, min=2, max=10),
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.NetworkError)),
        reraise=True,
    )
    def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        self._limiter.wait()
        try:
            res = self._client.request(method, url, **kwargs)
        except httpx.HTTPError as exc:
            raise ConnectorError(f"{self.name.value}: {exc}") from exc

        # 429 y 5xx no se reintentan en caliente: si la fuente pide calma, se
        # respeta y se sale limpio hasta la próxima corrida programada.
        if res.status_code == 429:
            raise ConnectorError(
                f"{self.name.value}: límite de tasa alcanzado (429). "
                "Se corta la corrida; reintenta el próximo ciclo."
            )
        if res.status_code >= 500:
            raise ConnectorError(
                f"{self.name.value}: la fuente devolvió {res.status_code}."
            )
        if res.status_code >= 400:
            raise ConnectorError(
                f"{self.name.value}: {res.status_code} — revisá la credencial."
            )
        return res

    def close(self) -> None:
        self._client.close()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_timestamp(valor: str | None) -> datetime:
    """Fechas de las fuentes, que vienen en formatos distintos cada una."""
    if not valor:
        return utcnow()
    texto = valor.strip().replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S"):
        try:
            momento = (
                datetime.fromisoformat(texto)
                if fmt is None
                else datetime.strptime(texto, fmt)
            )
            return momento if momento.tzinfo else momento.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return utcnow()


def deduplicate(indicadores: Iterable[RawIndicator]) -> dict[str, list[RawIndicator]]:
    """Agrupa por huella. Cada grupo es un hecho visto por N fuentes."""
    grupos: dict[str, list[RawIndicator]] = {}
    for ind in indicadores:
        grupos.setdefault(ind.fingerprint, []).append(ind)
    return grupos


def independent_families(indicadores: Iterable[RawIndicator]) -> int:
    """Cuántos OPERADORES distintos reportaron esto.

    No cuántas APIs: cuántas organizaciones. Ver la nota del encabezado.
    """
    return len({ind.source.family for ind in indicadores})


def mission_id_for(fingerprint: str) -> str:
    """ID de misión estable y derivado del indicador.

    Determinista a propósito: reingerir el mismo IoC tiene que actualizar la
    misión existente, no crear una nueva cada quince minutos.
    """
    return "MSN-" + hashlib.sha256(fingerprint.encode()).hexdigest()[:8].upper()
