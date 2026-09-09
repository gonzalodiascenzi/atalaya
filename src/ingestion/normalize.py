"""
ATALAYA // De indicador crudo a misión.

Toma un grupo de `RawIndicator` que hablan del MISMO observable (misma
huella, distintas fuentes) y produce:

  · un bundle STIX 2.1 con el grafo indicador → malware → técnica
  · el diccionario de misión que consume la plataforma

La severidad y la verdad de referencia NO se inventan acá: salen de las
señales que trajeron los conectores, con las reglas de `scoring.py`. Si una
misión entra como ambigua es porque la evidencia realmente lo es, y ese es
justamente el material del que se alimenta la corroboración diferida.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from base import (
    IndicatorKind,
    RawIndicator,
    SourceName,
    independent_families,
    mission_id_for,
)
from misp_stix_connector import (
    ATALAYA_IDENTITY_SEED,
    TLP_AMBER,
    TLP_CLEAR,
    TLP_GREEN,
    defang,
    stix_id,
    ts,
)

# `scoring` vive del lado de la API pero define las reglas del juego. Se
# importa en vez de duplicarse: dos definiciones del umbral de corroboración
# terminarían discrepando, y el sistema calificaría con una y explicaría con
# la otra.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
from scoring import (  # noqa: E402
    CORROBORATION_THRESHOLD,
    corroboration_verdict,
)

#: Técnica por defecto según el tipo de observable, cuando la fuente no la da.
_TECNICA_POR_TIPO = {
    IndicatorKind.IPV4: ("T1071.001", "command-and-control"),
    IndicatorKind.DOMAIN: ("T1071.001", "command-and-control"),
    IndicatorKind.URL: ("T1105", "command-and-control"),
    IndicatorKind.SHA256: ("T1204.002", "execution"),
    IndicatorKind.MD5: ("T1204.002", "execution"),
    IndicatorKind.CVE: ("T1190", "initial-access"),
}

_TACTICA_POR_TECNICA = {
    "T1190": "initial-access",
    "T1071.001": "command-and-control",
    "T1105": "command-and-control",
    "T1204.002": "execution",
    "T1486": "impact",
    "T1566.002": "initial-access",
    "T1555.003": "credential-access",
    "T1059.001": "execution",
    "T1046": "discovery",
}

_XP_POR_SEVERIDAD = {"low": 40, "medium": 80, "high": 160, "critical": 300}
_DIFICULTAD_POR_SEVERIDAD = {"low": 2, "medium": 3, "high": 4, "critical": 5}


def derive_severity(grupo: list[RawIndicator]) -> str:
    """Severidad a partir de la evidencia, no del gusto de nadie.

    El KEV manda: explotación activa confirmada es crítica sin discusión.
    Después pesa la corroboración entre operadores distintos, y recién
    después la confianza que declara la fuente.
    """
    if any(i.kev_listed for i in grupo):
        return "critical"

    familias = independent_families(grupo)
    confianza = max(i.source_confidence for i in grupo)
    con_muestra = any(i.sample_available for i in grupo)

    if familias >= CORROBORATION_THRESHOLD:
        return "critical"
    if familias >= 2 or (con_muestra and confianza >= 75):
        return "high"
    if confianza >= 75 or con_muestra:
        return "medium"
    return "low"


def _tlp(grupo: list[RawIndicator]) -> str:
    """Marcado de compartición.

    Lo público se marca público: el KEV y abuse.ch ya son abiertos, y
    sobre-restringirlos sólo entorpece el trabajo sin proteger nada.
    """
    if any(i.source is SourceName.CISA_KEV for i in grupo):
        return "TLP:CLEAR"
    if any(i.source.family.value == "abuse.ch" for i in grupo):
        return "TLP:GREEN"
    return "TLP:AMBER"


def _objetivos(principal: RawIndicator, familias: int) -> list[str]:
    """Objetivos de la operación, adaptados a lo que hay para investigar."""
    base = [
        "Pivotear el observable y listar la infraestructura asociada",
        "Contrastar contra fuentes independientes de las que ya lo reportan",
    ]
    if principal.kev_listed:
        base = [
            "Confirmar exposición: ¿algún activo propio corre el producto afectado?",
            "Verificar la fecha límite de remediación que fija CISA",
            "Revisar los logs del activo buscando indicios post-explotación",
        ]
    elif familias < CORROBORATION_THRESHOLD:
        base.append(
            "Estimar si la evidencia alcanza para un veredicto o hay que esperar"
        )
    if principal.sample_available:
        base.append("Analizar la muestra asociada y extraer su configuración")
    base.append("Emitir veredicto declarando tu nivel de confianza")
    return base


def build_mission(
    grupo: list[RawIndicator], ttl_minutes: int = 240
) -> dict[str, Any] | None:
    """Arma la misión completa a partir de un grupo de avistamientos.

    Devuelve None si el observable cae en rango reservado: publicarlo como
    amenaza real haría que alguien bloquee documentación o su propia LAN.
    """
    if not grupo:
        return None

    # El de mayor confianza manda para el contexto narrativo.
    principal = max(grupo, key=lambda i: i.source_confidence)
    if principal.is_reserved:
        return None

    familias = independent_families(grupo)
    kev = any(i.kev_listed for i in grupo)
    severidad = derive_severity(grupo)
    tlp_nombre = _tlp(grupo)
    tlp_ref = {"TLP:CLEAR": TLP_CLEAR, "TLP:GREEN": TLP_GREEN, "TLP:AMBER": TLP_AMBER}[
        tlp_nombre
    ]

    verdad, fuente_verdad = corroboration_verdict(familias, kev)

    tecnica = principal.attack_technique
    if not tecnica:
        tecnica, _ = _TECNICA_POR_TIPO.get(principal.kind, ("T1071.001", "c2"))
    tactica = _TACTICA_POR_TECNICA.get(tecnica, "command-and-control")

    familia_malware = next(
        (i.malware_family for i in grupo if i.malware_family), "Sin atribución"
    )

    objetos = _stix_objects(
        principal, grupo, tecnica, tactica, familia_malware, tlp_ref
    )
    fingerprint = principal.fingerprint

    fuentes = sorted({i.source.value for i in grupo})
    return {
        "mission_id": mission_id_for(fingerprint),
        "fingerprint": fingerprint,
        "title": _titulo(principal, familia_malware),
        "briefing": _briefing(principal, grupo, familias),
        "severity": severidad,
        "difficulty": _DIFICULTAD_POR_SEVERIDAD[severidad],
        "xp_reward": _XP_POR_SEVERIDAD[severidad],
        "required_rank": "ANALISTA_JUNIOR" if severidad == "critical" else "NOVATO",
        "source": ", ".join(fuentes)[:64],
        "tlp": tlp_nombre,
        "attack_technique": tecnica,
        "attack_tactic": tactica,
        "malware_family": familia_malware,
        "ioc_defanged": defang(principal.value),
        "ioc_pattern": principal.stix_pattern(),
        "objectives": _objetivos(principal, familias),
        "detected_at": ts(),
        "expires_in_minutes": ttl_minutes,
        "status": "OPEN",
        # ── Señales del bucle de verificación ──
        "ground_truth": verdad.value,
        "truth_source": fuente_verdad.value if fuente_verdad else None,
        "source_confidence": principal.source_confidence,
        "independent_sources": familias,
        "kev_listed": kev,
        "sample_available": any(i.sample_available for i in grupo),
        "object_refs": [o["id"] for o in objetos],
        "objects": objetos,
    }


def _titulo(principal: RawIndicator, familia: str) -> str:
    if principal.kev_listed:
        return f"Vulnerabilidad explotada activamente — {principal.value}"
    if familia != "Sin atribución":
        return f"Infraestructura de {familia} — {defang(principal.value)}"
    return f"Observable sin atribuir — {defang(principal.value)}"


def _briefing(principal: RawIndicator, grupo: list[RawIndicator], familias: int) -> str:
    fuentes = ", ".join(sorted({i.source.value for i in grupo}))
    partes = [principal.description or "Indicador reportado por fuentes OSINT."]

    if principal.kev_listed:
        partes.append(
            "CISA lo sumó a su catálogo de vulnerabilidades explotadas "
            "activamente: la explotación está observada, no supuesta."
        )
    elif familias >= CORROBORATION_THRESHOLD:
        partes.append(
            f"Corroborado por {familias} operadores independientes ({fuentes}). "
            "La evidencia converge."
        )
    else:
        partes.append(
            f"Reportado por {familias} operador(es) ({fuentes}). La evidencia "
            "todavía NO alcanza el umbral de corroboración: vas a tener que "
            "decidir con información incompleta y el tiempo te va a dar o "
            "quitar la razón."
        )

    if any(i.sample_available for i in grupo):
        partes.append("Hay una muestra asociada disponible para análisis.")
    return " ".join(partes)


def _stix_objects(
    principal: RawIndicator,
    grupo: list[RawIndicator],
    tecnica: str,
    tactica: str,
    familia: str,
    tlp_ref: str,
) -> list[dict[str, Any]]:
    """Grafo STIX 2.1: indicador → malware → técnica."""
    creado = ts()
    autor = stix_id("identity", ATALAYA_IDENTITY_SEED)
    comun = {
        "spec_version": "2.1",
        "created": creado,
        "modified": creado,
        "created_by_ref": autor,
        "object_marking_refs": [tlp_ref],
    }

    attack_pattern = {
        "type": "attack-pattern",
        "id": stix_id("attack-pattern", tecnica),
        **comun,
        "name": tecnica,
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": tecnica,
                "url": f"https://attack.mitre.org/techniques/{tecnica.replace('.', '/')}/",
            }
        ],
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack", "phase_name": tactica}
        ],
    }

    malware = {
        "type": "malware",
        "id": stix_id("malware", familia),
        **comun,
        "name": familia,
        "is_family": familia != "Sin atribución",
        "malware_types": ["unknown"],
    }

    indicator = {
        "type": "indicator",
        "id": stix_id("indicator", principal.stix_pattern()),
        **comun,
        "name": f"{familia} — {defang(principal.value)}",
        "indicator_types": ["malicious-activity"],
        "pattern": principal.stix_pattern(),
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": creado,
        "confidence": principal.source_confidence,
        "labels": sorted({t for i in grupo for t in i.tags})[:8] or ["osint"],
        "external_references": [
            {"source_name": i.source.value, "url": i.source_reference}
            for i in grupo
            if i.source_reference
        ][:5],
        "x_atalaya_defanged": defang(principal.value),
        "x_atalaya_independent_sources": independent_families(grupo),
        "x_opencti_score": min(100, principal.source_confidence + 10 * len(grupo)),
    }

    relaciones = [
        {
            "type": "relationship",
            "id": stix_id("relationship", f"{principal.fingerprint}:indicates"),
            **comun,
            "relationship_type": "indicates",
            "source_ref": indicator["id"],
            "target_ref": malware["id"],
        },
        {
            "type": "relationship",
            "id": stix_id("relationship", f"{principal.fingerprint}:uses"),
            **comun,
            "relationship_type": "uses",
            "source_ref": malware["id"],
            "target_ref": attack_pattern["id"],
        },
    ]
    return [attack_pattern, malware, indicator, *relaciones]


def missions_from(
    indicadores: list[RawIndicator], max_missions: int = 50
) -> list[dict[str, Any]]:
    """Agrupa por huella y produce misiones, las más corroboradas primero."""
    from base import deduplicate

    misiones = []
    for grupo in deduplicate(indicadores).values():
        mision = build_mission(grupo)
        if mision is not None:
            misiones.append(mision)

    misiones.sort(
        key=lambda m: (
            m["kev_listed"],
            m["independent_sources"],
            m["source_confidence"],
        ),
        reverse=True,
    )
    return misiones[:max_missions]
