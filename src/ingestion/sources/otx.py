"""
ATALAYA // AlienVault OTX.

Inteligencia comunitaria organizada en "pulsos": conjuntos de indicadores
que un investigador publica alrededor de una campaña. El pulso aporta algo
que las otras fuentes no dan — contexto narrativo — y de ahí salen la
familia de malware y las técnicas ATT&CK de la misión.

Contracara: al ser comunitaria, la calidad varía. Por eso la confianza por
defecto es más baja que la de KEV, y por eso un IoC visto SÓLO en OTX entra
como ambiguo y espera corroboración en vez de darse por verdad.
"""

from __future__ import annotations

import os
import re

from base import (
    Connector,
    IndicatorKind,
    RawIndicator,
    SourceName,
    parse_timestamp,
)

OTX_BASE = "https://otx.alienvault.com/api/v1"

_TIPOS = {
    "IPv4": IndicatorKind.IPV4,
    "domain": IndicatorKind.DOMAIN,
    "hostname": IndicatorKind.DOMAIN,
    "URL": IndicatorKind.URL,
    "FileHash-SHA256": IndicatorKind.SHA256,
    "FileHash-MD5": IndicatorKind.MD5,
    "CVE": IndicatorKind.CVE,
}

_TECNICA = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


class OtxConnector(Connector):
    """Indicadores de los pulsos suscritos."""

    name = SourceName.OTX
    requires_env = "OTX_API_KEY"
    min_interval = 1.0
    default_confidence = 60

    def fetch(self, limit: int = 100) -> list[RawIndicator]:
        self.check_credentials(dict(os.environ))
        clave = os.environ[self.requires_env].strip()
        pulsos_max = int(os.getenv("OTX_PULSE_LIMIT", "50"))

        res = self._request(
            "GET",
            f"{OTX_BASE}/pulses/subscribed",
            headers={"X-OTX-API-KEY": clave},
            params={"limit": min(pulsos_max, 50)},
        )
        pulsos = res.json().get("results", [])

        indicadores: list[RawIndicator] = []
        for pulso in pulsos:
            if len(indicadores) >= limit:
                break
            indicadores.extend(self._del_pulso(pulso, limit - len(indicadores)))
        return indicadores

    def _del_pulso(self, pulso: dict, restantes: int) -> list[RawIndicator]:
        """Extrae los indicadores de un pulso, heredándole el contexto."""
        pulse_id = pulso.get("id", "")
        nombre = (pulso.get("name") or "").strip()
        etiquetas = tuple((pulso.get("tags") or [])[:6])

        # La técnica ATT&CK puede venir estructurada o suelta en el título.
        tecnica = None
        for ref in pulso.get("attack_ids") or []:
            candidato = ref if isinstance(ref, str) else ref.get("id", "")
            if _TECNICA.fullmatch(candidato or ""):
                tecnica = candidato
                break
        if tecnica is None:
            hallado = _TECNICA.search(nombre)
            tecnica = hallado.group(0) if hallado else None

        familia = None
        for m in pulso.get("malware_families") or []:
            familia = m if isinstance(m, str) else m.get("display_name")
            if familia:
                break

        salida: list[RawIndicator] = []
        for ind in (pulso.get("indicators") or [])[:restantes]:
            tipo = _TIPOS.get(ind.get("type", ""))
            valor = (ind.get("indicator") or "").strip()
            if tipo is None or not valor:
                continue
            salida.append(
                RawIndicator(
                    value=valor,
                    kind=tipo,
                    source=self.name,
                    source_reference=f"https://otx.alienvault.com/pulse/{pulse_id}",
                    source_confidence=self.default_confidence,
                    first_reported_at=parse_timestamp(
                        ind.get("created") or pulso.get("created")
                    ),
                    malware_family=familia,
                    attack_technique=tecnica,
                    description=nombre or None,
                    tags=etiquetas,
                )
            )
        return salida
