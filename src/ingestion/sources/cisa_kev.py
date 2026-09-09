"""
ATALAYA // CISA Known Exploited Vulnerabilities.

La fuente más valiosa del conjunto y la más simple: un JSON público, sin
credenciales. Que un CVE esté en KEV no es una opinión de nadie — significa
que CISA observó explotación activa. Es la única verdad de referencia
inmediata y dura que tiene el sistema.

El archivo pesa más de un megabyte y cambia pocas veces por semana. Bajarlo
entero cada quince minutos sería maleducado y lento, así que se usa una
petición condicional: si no cambió, la fuente responde 304 y no se
transfiere nada.

MEDIDO CONTRA EL SERVIDOR REAL: el CDN de CISA **expone** un ETag pero
**ignora** `If-None-Match` (responde 200 igual). Sí honra `If-Modified-Since`
con el `Last-Modified`. Por eso se mandan los dos encabezados y el que
realmente ahorra el megabyte es el segundo. Confiar sólo en el ETag —que es
lo que uno escribiría por costumbre— deja la optimización como código
muerto sin que nada falle a la vista.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from base import (
    Connector,
    IndicatorKind,
    RawIndicator,
    SourceName,
    parse_timestamp,
)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CisaKevConnector(Connector):
    """Catálogo KEV. Público, sin API key."""

    name = SourceName.CISA_KEV
    requires_env = None  # es público
    min_interval = 2.0
    default_confidence = 100  # explotación observada, no inferida

    def __init__(self, client=None, cache_dir: str | None = None) -> None:
        super().__init__(client)
        # Nada de "/tmp/..." fijo: en una máquina compartida, un directorio
        # predecible bajo /tmp es un punto clásico de ataque por enlace
        # simbólico. Se respeta XDG y se cae al temporal del sistema.
        predeterminado = (
            Path(os.getenv("XDG_CACHE_HOME") or tempfile.gettempdir()) / "atalaya-cti"
        )
        self._cache = Path(cache_dir or os.getenv("INGEST_CACHE_DIR") or predeterminado)
        # 0700: la caché guarda el catálogo entero; no hace falta que lo lea
        # ningún otro usuario de la máquina.
        self._cache.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._etag_file = self._cache / "kev.etag"
        self._modified_file = self._cache / "kev.last-modified"
        self._body_file = self._cache / "kev.json"

    def fetch(self, limit: int = 100) -> list[RawIndicator]:
        datos = self._descargar()
        if datos is None:
            return []

        vulnerabilidades = datos.get("vulnerabilities", [])
        # Las más recientes primero: una vulnerabilidad agregada ayer entrena
        # mejor que una de 2021 que ya está parcheada en todos lados.
        vulnerabilidades.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)

        indicadores: list[RawIndicator] = []
        for v in vulnerabilidades[:limit]:
            cve = v.get("cveID")
            if not cve:
                continue
            producto = f"{v.get('vendorProject', '')} {v.get('product', '')}".strip()
            indicadores.append(
                RawIndicator(
                    value=cve,
                    kind=IndicatorKind.CVE,
                    source=self.name,
                    source_reference=f"https://nvd.nist.gov/vuln/detail/{cve}",
                    source_confidence=self.default_confidence,
                    first_reported_at=parse_timestamp(v.get("dateAdded")),
                    malware_family=(
                        "Ransomware conocido"
                        if v.get("knownRansomwareCampaignUse") == "Known"
                        else None
                    ),
                    # Explotar una aplicación expuesta es, casi por definición,
                    # el patrón de acceso inicial de una entrada del KEV.
                    attack_technique="T1190",
                    description=(
                        f"{producto}: {v.get('vulnerabilityName', '')}. "
                        f"{v.get('shortDescription', '')}".strip()
                    ),
                    kev_listed=True,
                    tags=("kev", "explotacion-activa")
                    + (
                        ("ransomware",)
                        if v.get("knownRansomwareCampaignUse") == "Known"
                        else ()
                    ),
                )
            )
        return indicadores

    def _descargar(self) -> dict | None:
        """Baja el catálogo, o devuelve el cacheado si no cambió."""
        cabeceras: dict[str, str] = {}
        # Se mandan los dos: If-None-Match para servidores que lo respetan y
        # If-Modified-Since para el CDN de CISA, que es el que de verdad
        # devuelve 304. Un servidor que honre cualquiera de los dos ahorra
        # la transferencia.
        if self._etag_file.exists():
            cabeceras["If-None-Match"] = self._etag_file.read_text().strip()
        if self._modified_file.exists():
            cabeceras["If-Modified-Since"] = self._modified_file.read_text().strip()

        res = self._request("GET", KEV_URL, headers=cabeceras)

        if res.status_code == 304:
            # No cambió: se usa la copia local y no se transfiere el megabyte.
            if self._body_file.exists():
                return json.loads(self._body_file.read_text())
            return None

        if etag := res.headers.get("ETag"):
            self._etag_file.write_text(etag)
        if modificado := res.headers.get("Last-Modified"):
            self._modified_file.write_text(modificado)
        self._body_file.write_text(res.text)
        return res.json()
