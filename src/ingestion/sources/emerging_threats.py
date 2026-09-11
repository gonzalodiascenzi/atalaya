"""
ATALAYA // Emerging Threats — IPs comprometidas.

Lista pública de Proofpoint con hosts comprometidos que están siendo usados
para atacar. Aporta poco contexto —sólo la IP, sin familia ni técnica—, pero
aporta lo que más escasea: un OPERADOR DISTINTO. Proofpoint no copia de
abuse.ch ni de Spamhaus, así que una IP que aparece acá y en ThreatFox está
corroborada por dos organizaciones independientes de verdad.

Sin credencial. ~600 IPs, actualizada varias veces por día.
"""

from __future__ import annotations

import ipaddress

from base import (
    Connector,
    IndicatorKind,
    RawIndicator,
    SourceName,
    cache_dir,
    utcnow,
)

ET_URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"


class EmergingThreatsConnector(Connector):
    """IPs comprometidas según Proofpoint Emerging Threats."""

    name = SourceName.EMERGING_THREATS
    requires_env = None
    min_interval = 2.0
    #: Confianza moderada: está comprometida, pero la lista no dice para qué.
    default_confidence = 65

    def fetch(self, limit: int = 100) -> list[RawIndicator]:
        cuerpo = self._conditional_get(ET_URL, cache_dir(), "emerging-threats")
        return self.parse(cuerpo or "", limit)

    def parse(self, texto: str, limit: int) -> list[RawIndicator]:
        ahora = utcnow()
        salida: list[RawIndicator] = []
        for linea in texto.splitlines():
            if len(salida) >= limit:
                break
            linea = linea.strip()
            if not linea or linea.startswith("#"):
                continue
            try:
                ip = str(ipaddress.ip_address(linea))
            except ValueError:
                # Una línea que no es IP no se adivina: se descarta.
                continue
            salida.append(
                RawIndicator(
                    value=ip,
                    kind=IndicatorKind.IPV4,
                    source=self.name,
                    source_reference=ET_URL,
                    source_confidence=self.default_confidence,
                    first_reported_at=ahora,
                    attack_technique="T1584.004",
                    description="Host comprometido reportado por Proofpoint Emerging Threats.",
                    tags=("comprometido",),
                )
            )
        return salida
