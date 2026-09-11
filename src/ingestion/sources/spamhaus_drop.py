"""
ATALAYA // Spamhaus DROP — corroborador de IPs.

DROP ("Don't Route Or Peer") lista rangos de red secuestrados o controlados
por operadores criminales. No es una fuente de misiones: no dice nada sobre
una IP puntual hasta que alguien más la reporta. Por eso funciona distinto
del resto: recibe las IPs que trajeron las otras fuentes y devuelve un
avistamiento de Spamhaus para cada una que cae dentro de un rango DROP.

Medido contra datos reales: 287 IPs de ThreatFox caen dentro de rangos DROP.
Sin esta fuente, esas IPs tenían un solo operador detrás; con ella tienen
dos, y la misión se puede calificar.

Sin credencial. ~1.700 rangos.
"""

from __future__ import annotations

import ipaddress
import json
from typing import Iterable

from base import (
    Connector,
    IndicatorKind,
    RawIndicator,
    SourceName,
    cache_dir,
    utcnow,
)

DROP_URL = "https://www.spamhaus.org/drop/drop_v4.json"


class SpamhausDropConnector(Connector):
    """Corrobora IPs que caen en rangos secuestrados."""

    name = SourceName.SPAMHAUS_DROP
    requires_env = None
    min_interval = 2.0
    default_confidence = 85

    def __init__(self, client=None) -> None:
        super().__init__(client)
        self._redes: list[tuple[ipaddress.IPv4Network, str]] | None = None

    def fetch(self, limit: int = 100) -> list[RawIndicator]:
        """DROP no genera misiones propias: ver corroborate()."""
        return []

    def load(self, texto: str | None = None) -> int:
        """Carga los rangos. Devuelve cuántos se leyeron."""
        if texto is None:
            texto = self._conditional_get(DROP_URL, cache_dir(), "spamhaus-drop") or ""
        redes = []
        # El archivo es JSON por línea: una red por línea más metadatos.
        for linea in texto.splitlines():
            linea = linea.strip()
            if not linea:
                continue
            try:
                d = json.loads(linea)
            except json.JSONDecodeError:
                continue
            if "cidr" in d:
                try:
                    redes.append((ipaddress.ip_network(d["cidr"]), d.get("sblid", "")))
                except ValueError:
                    continue
        self._redes = redes
        return len(redes)

    def corroborate(self, ips: Iterable[str]) -> list[RawIndicator]:
        """Un avistamiento de Spamhaus por cada IP dentro de un rango DROP."""
        if self._redes is None:
            self.load()
        ahora = utcnow()
        salida = []
        for ip in set(ips):
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            for red, sbl in self._redes or []:
                if addr in red:
                    salida.append(
                        RawIndicator(
                            value=ip,
                            kind=IndicatorKind.IPV4,
                            source=self.name,
                            source_reference=(
                                f"https://check.spamhaus.org/sbl/query/{sbl}"
                                if sbl
                                else "https://www.spamhaus.org/drop/"
                            ),
                            source_confidence=self.default_confidence,
                            first_reported_at=ahora,
                            description=f"Dentro del rango secuestrado {red} (Spamhaus DROP).",
                            tags=("drop", "rango-secuestrado"),
                        )
                    )
                    break
        return salida
