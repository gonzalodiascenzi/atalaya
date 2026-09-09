"""
ATALAYA // abuse.ch ThreatFox.

IoCs de mando y control con familia de malware asociada, que es justamente
lo que hace entrenable una misión: no un "IP mala" suelto, sino "esta IP es
el C2 de esta familia".

Desde 2024 abuse.ch exige una Auth-Key aunque el servicio siga siendo
gratuito. Se saca de https://auth.abuse.ch/ y va en ABUSECH_AUTH_KEY.

OJO con la independencia: ThreatFox, URLhaus y MalwareBazaar son del MISMO
operador. Comparten `SourceFamily.ABUSE_CH` para que un indicador presente
en las tres cuente como UNA corroboración, no como tres.
"""

from __future__ import annotations

import os

from base import (
    Connector,
    IndicatorKind,
    RawIndicator,
    SourceName,
    parse_timestamp,
)

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"

#: Traducción del vocabulario de ThreatFox al nuestro.
_TIPOS = {
    "ip:port": IndicatorKind.IPV4,
    "domain": IndicatorKind.DOMAIN,
    "url": IndicatorKind.URL,
    "sha256_hash": IndicatorKind.SHA256,
    "md5_hash": IndicatorKind.MD5,
}

#: Técnica ATT&CK inferida del tipo de amenaza que declara la fuente.
_TECNICAS = {
    "botnet_cc": "T1071.001",
    "payload_delivery": "T1105",
    "payload": "T1105",
}


class ThreatFoxConnector(Connector):
    """IoCs recientes de ThreatFox."""

    name = SourceName.THREATFOX
    requires_env = "ABUSECH_AUTH_KEY"
    min_interval = 1.5
    default_confidence = 50

    def fetch(self, limit: int = 100) -> list[RawIndicator]:
        self.check_credentials(dict(os.environ))
        clave = os.environ[self.requires_env].strip()

        # `days: 1` acota a lo reciente: un IoC de C2 de hace un mes casi
        # seguro ya está muerto, y entrenar sobre infraestructura apagada
        # enseña a perseguir fantasmas.
        res = self._request(
            "POST",
            THREATFOX_URL,
            headers={"Auth-Key": clave, "Content-Type": "application/json"},
            json={"query": "get_iocs", "days": 1},
        )
        cuerpo = res.json()
        if cuerpo.get("query_status") != "ok":
            return []

        indicadores: list[RawIndicator] = []
        for ioc in (cuerpo.get("data") or [])[:limit]:
            tipo = _TIPOS.get(ioc.get("ioc_type", ""))
            if tipo is None:
                continue

            valor = (ioc.get("ioc") or "").strip()
            if not valor:
                continue
            # ThreatFox entrega "1.2.3.4:8080"; el puerto no es parte del
            # observable en STIX y rompería la deduplicación entre fuentes.
            if tipo is IndicatorKind.IPV4 and ":" in valor:
                valor = valor.split(":", 1)[0]

            familia = (ioc.get("malware_printable") or "").strip() or None
            indicadores.append(
                RawIndicator(
                    value=valor,
                    kind=tipo,
                    source=self.name,
                    source_reference=(
                        f"https://threatfox.abuse.ch/ioc/{ioc.get('id', '')}/"
                    ),
                    source_confidence=int(
                        ioc.get("confidence_level") or self.default_confidence
                    ),
                    first_reported_at=parse_timestamp(ioc.get("first_seen")),
                    malware_family=familia,
                    attack_technique=_TECNICAS.get(ioc.get("threat_type", "")),
                    description=(ioc.get("threat_type_desc") or "").strip() or None,
                    # Que exista una muestra asociada es corroboración fuerte:
                    # alguien tiene el binario, no sólo una sospecha.
                    sample_available=bool(ioc.get("malware_samples")),
                    tags=tuple(ioc.get("tags") or ())[:6],
                )
            )
        return indicadores
