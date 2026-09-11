"""
ATALAYA // abuse.ch ThreatFox — export público.

IoCs de mando y control con familia de malware asociada, que es justamente lo
que hace entrenable una misión: no "IP mala" suelta, sino "esta IP es el C2 de
esta familia".

Se usa el EXPORT PÚBLICO y no la API. La API exige una Auth-Key, y abuse.ch
dejó de ofrecer alta con correo: sólo se entra con una cuenta de X, Google,
LinkedIn o GitHub, algo que no siempre se puede. El export trae los mismos
campos —familia, confianza, primera aparición, etiquetas— sin credencial
alguna. Verificado contra el servidor real: ~11.800 IoCs por descarga.

Pesa ~7 MB. Por eso va con petición condicional: si no cambió desde la
última corrida, no se transfiere nada.

OJO con la independencia: ThreatFox, URLhaus y MalwareBazaar son del MISMO
operador (`SourceFamily.ABUSE_CH`). Un indicador en las tres cuenta como UNA
corroboración, no como tres.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from base import (
    Connector,
    IndicatorKind,
    RawIndicator,
    SourceName,
    cache_dir,
    parse_timestamp,
)

EXPORT_URL = "https://threatfox.abuse.ch/export/json/recent/"

_TIPOS = {
    "ip:port": IndicatorKind.IPV4,
    "domain": IndicatorKind.DOMAIN,
    "url": IndicatorKind.URL,
    "sha256_hash": IndicatorKind.SHA256,
    "md5_hash": IndicatorKind.MD5,
}

_TECNICAS = {
    "botnet_cc": "T1071.001",
    "payload_delivery": "T1105",
    "payload": "T1105",
}

#: Ventana de recencia. El export arrastra entradas de años atrás; entrenar
#: sobre infraestructura de C2 que se apagó en 2021 enseña a perseguir
#: fantasmas.
RECENCIA_DIAS = 7


class ThreatFoxConnector(Connector):
    """IoCs recientes de ThreatFox, sin credencial."""

    name = SourceName.THREATFOX
    requires_env = None
    min_interval = 1.5
    default_confidence = 50

    def fetch(self, limit: int = 100) -> list[RawIndicator]:
        cuerpo = self._conditional_get(EXPORT_URL, cache_dir(), "threatfox")
        if not cuerpo:
            return []
        return self.parse(json.loads(cuerpo), limit)

    def parse(self, datos: dict, limit: int) -> list[RawIndicator]:
        """Normaliza el export. Separado de fetch() para poder probarlo."""
        filas = (
            [f for grupo in datos.values() for f in grupo]
            if isinstance(datos, dict)
            else list(datos)
        )
        umbral = datetime.now(timezone.utc) - timedelta(days=RECENCIA_DIAS)

        recientes = []
        for f in filas:
            visto = parse_timestamp(f.get("first_seen_utc"))
            if visto >= umbral:
                recientes.append((visto, f))
        # Lo más nuevo primero: es lo que todavía puede estar vivo.
        recientes.sort(key=lambda par: par[0], reverse=True)

        indicadores: list[RawIndicator] = []
        for visto, f in recientes:
            if len(indicadores) >= limit:
                break
            tipo = _TIPOS.get(f.get("ioc_type", ""))
            valor = (f.get("ioc_value") or "").strip()
            if tipo is None or not valor:
                continue
            # "1.2.3.4:8080" → el puerto no es parte del observable en STIX y
            # rompería el cruce con fuentes que reportan la IP sola.
            if tipo is IndicatorKind.IPV4 and ":" in valor:
                valor = valor.split(":", 1)[0]

            indicadores.append(
                RawIndicator(
                    value=valor,
                    kind=tipo,
                    source=self.name,
                    source_reference=f.get("reference")
                    or "https://threatfox.abuse.ch/browse/",
                    source_confidence=int(
                        f.get("confidence_level") or self.default_confidence
                    ),
                    first_reported_at=visto,
                    malware_family=(f.get("malware_printable") or "").strip() or None,
                    attack_technique=_TECNICAS.get(f.get("threat_type", "")),
                    description=(
                        f"{f.get('malware_printable') or 'Malware'}: "
                        f"{(f.get('threat_type') or 'indicador').replace('_', ' ')}."
                    ),
                    # El export no trae la lista de muestras; se usa la
                    # presencia de un hash como señal de que hay binario.
                    sample_available=tipo in (IndicatorKind.SHA256, IndicatorKind.MD5),
                    tags=(
                        tuple((f.get("tags") or "").split(","))[:6]
                        if isinstance(f.get("tags"), str)
                        else tuple(f.get("tags") or ())[:6]
                    ),
                )
            )
        return indicadores
