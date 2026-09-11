#!/usr/bin/env python3
"""
ATALAYA // Orquestador de ingesta.

Uso:

    python3 run.py --dry-run            # consulta y muestra, sin escribir nada
    python3 run.py --ingest             # consulta y persiste en PostgreSQL
    python3 run.py --resolve            # resuelve la corroboración vencida
    python3 run.py --loop               # ciclo continuo cada INGEST_INTERVAL_MINUTES
    python3 run.py --dry-run --source cisa_kev

Principio de operación: **una fuente caída no tumba la corrida**. Cada
conector se aísla; si falla, se registra y se sigue con los demás. Una
plataforma de inteligencia que se queda sin feed porque una API devolvió 500
no sirve para nada.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from base import (  # noqa: E402
    ConnectorDisabled,
    ConnectorError,
    IndicatorKind,
    RawIndicator,
    SourceName,
)
from normalize import missions_from  # noqa: E402
from scoring import CORROBORATION_THRESHOLD  # noqa: E402
from sources import ALL_CONNECTORS, SpamhausDropConnector  # noqa: E402

#: Qué tipos de indicador puede reportar cada fuente. Con esto se decide qué
#: misiones son calificables (ver `corroborable_kinds`).
TIPOS_POR_FUENTE: dict[SourceName, set[IndicatorKind]] = {
    SourceName.CISA_KEV: {IndicatorKind.CVE},
    SourceName.THREATFOX: {
        IndicatorKind.IPV4,
        IndicatorKind.DOMAIN,
        IndicatorKind.URL,
        IndicatorKind.SHA256,
        IndicatorKind.MD5,
    },
    SourceName.URLHAUS: {IndicatorKind.URL},
    SourceName.EMERGING_THREATS: {IndicatorKind.IPV4},
    SourceName.SPAMHAUS_DROP: {IndicatorKind.IPV4},
    SourceName.OTX: {
        IndicatorKind.IPV4,
        IndicatorKind.DOMAIN,
        IndicatorKind.URL,
        IndicatorKind.SHA256,
        IndicatorKind.MD5,
        IndicatorKind.CVE,
    },
}


def corroborable_kinds(activas: set[SourceName]) -> set[IndicatorKind]:
    """Tipos de indicador que ALGUNA VEZ se podrían corroborar.

    Un tipo es corroborable si, entre las fuentes que respondieron en esta
    corrida, hay al menos CORROBORATION_THRESHOLD operadores DISTINTOS capaces
    de reportarlo. Si no los hay, una misión de ese tipo nunca alcanzaría el
    umbral: vencería a las 72 h sin calificar y el analista habría apostado
    para nada.

    Con las fuentes sin cuenta de hoy, los hashes y los dominios sólo los
    reporta abuse.ch: no se crean misiones de esos tipos. Cuando se sume la
    clave de OTX (otro operador que sí los reporta), pasan a ser calificables
    solos, sin tocar este código.
    """
    familias_por_tipo: dict[IndicatorKind, set] = {}
    for fuente in activas:
        for tipo in TIPOS_POR_FUENTE.get(fuente, set()):
            familias_por_tipo.setdefault(tipo, set()).add(fuente.family)
    return {
        t
        for t, fams in familias_por_tipo.items()
        if len(fams) >= CORROBORATION_THRESHOLD
    }


logging.basicConfig(
    level=getattr(logging, os.getenv("CONNECTOR_LOG_LEVEL", "INFO").upper(), 20),
    format="%(asctime)s | %(levelname)-8s | atalaya.ingesta | %(message)s",
)
log = logging.getLogger("atalaya.ingesta")


def recolectar(
    limite_por_fuente: int, solo: str | None = None
) -> tuple[list[RawIndicator], dict[str, str]]:
    """Consulta todas las fuentes disponibles. Nunca aborta por una sola.

    Después de las fuentes que generan misiones, Spamhaus DROP corrobora las
    IPs que trajeron, y se descartan los tipos de indicador que no se podrían
    calificar nunca con las fuentes que respondieron.
    """
    indicadores: list[RawIndicator] = []
    estado: dict[str, str] = {}
    activas: set[SourceName] = set()

    for cls in ALL_CONNECTORS:
        clave = cls.__name__.replace("Connector", "").lower()
        if solo and solo.replace("_", "") != clave:
            continue

        conector = cls()
        try:
            lote = conector.fetch(limite_por_fuente)
            indicadores.extend(lote)
            activas.add(conector.name)
            estado[conector.name.value] = f"✓ {len(lote)} indicadores"
            log.info("%s · %d indicadores", conector.name.value, len(lote))
        except ConnectorDisabled as exc:
            # Falta la credencial: es un aviso de configuración, no una falla.
            estado[conector.name.value] = "○ sin credencial"
            log.warning("%s", exc)
        except ConnectorError as exc:
            estado[conector.name.value] = f"✗ {exc}"
            log.error("%s", exc)
        except Exception as exc:  # noqa: BLE001 - una fuente rota no tumba el resto
            estado[conector.name.value] = f"✗ inesperado: {type(exc).__name__}"
            log.exception("Fallo inesperado en %s", conector.name.value)
        finally:
            conector.close()

    # ── Spamhaus DROP: corrobora, no genera ──────────────────────────
    ips = [i.value for i in indicadores if i.kind is IndicatorKind.IPV4]
    if ips and not solo:
        drop = SpamhausDropConnector()
        try:
            rangos = drop.load()
            corroboraciones = drop.corroborate(ips)
            indicadores.extend(corroboraciones)
            activas.add(drop.name)
            estado[drop.name.value] = (
                f"✓ {rangos} rangos · corrobora {len(corroboraciones)} IPs"
            )
        except (ConnectorError, Exception) as exc:  # noqa: BLE001
            estado[drop.name.value] = f"✗ {exc}"
            log.error("Spamhaus DROP: %s", exc)
        finally:
            drop.close()

    # ── Descarte de lo que nunca se podría calificar ─────────────────
    calificables = corroborable_kinds(activas)
    antes = len(indicadores)
    indicadores = [i for i in indicadores if i.kev_listed or i.kind in calificables]
    descartados = antes - len(indicadores)
    if descartados:
        estado["(no calificables)"] = (
            f"○ {descartados} descartados: su tipo no tiene {CORROBORATION_THRESHOLD} "
            "operadores que lo puedan corroborar"
        )
    return indicadores, estado


def avistamientos_de(grupo: list[RawIndicator]) -> list[dict[str, Any]]:
    """Un avistamiento por FUENTE, no por fila.

    ThreatFox reporta la misma IP varias veces con distintos puertos
    (`1.2.3.4:443`, `1.2.3.4:8080`). Al sacar el puerto quedan varias filas de
    la misma fuente para el mismo indicador, y eso no son varias
    corroboraciones: es un solo operador diciendo lo mismo tres veces. Se
    colapsan quedándose con la mejor señal de cada una — mayor confianza,
    aparición más temprana, y "hay muestra" si cualquiera la tenía.

    Descubierto contra datos reales: el primer volcado de ThreatFox chocó
    contra el índice único de avistamientos.
    """
    por_fuente: dict[str, dict[str, Any]] = {}
    for i in grupo:
        previo = por_fuente.get(i.source.value)
        if previo is None:
            por_fuente[i.source.value] = {
                "source_name": i.source.value,
                "source_family": i.source.family.value,
                "source_reference": i.source_reference,
                "source_confidence": i.source_confidence,
                "first_reported_at": i.first_reported_at,
                "sample_available": i.sample_available,
                "kev_listed": i.kev_listed,
            }
            continue
        previo["source_confidence"] = max(
            previo["source_confidence"], i.source_confidence
        )
        previo["first_reported_at"] = min(
            previo["first_reported_at"], i.first_reported_at
        )
        previo["sample_available"] = previo["sample_available"] or i.sample_available
        previo["kev_listed"] = previo["kev_listed"] or i.kev_listed
    return list(por_fuente.values())


async def persistir(misiones: list[dict[str, Any]], crudos: list[RawIndicator]) -> dict:
    """Escribe misiones y avistamientos en PostgreSQL."""
    from db import dispose_engine, get_session_factory
    from ingestion_repository import IngestionRepository

    from base import deduplicate

    grupos = deduplicate(crudos)
    resumen = {"creada": 0, "corroborada": 0, "sin-cambios": 0}

    factory = get_session_factory()
    try:
        async with factory() as session:
            repo = IngestionRepository(session)
            for mision in misiones:
                grupo = grupos.get(mision["fingerprint"], [])
                estado = await repo.upsert_mission(mision, avistamientos_de(grupo))
                resumen[estado] = resumen.get(estado, 0) + 1
            await session.commit()
            stats = await repo.stats()
    finally:
        await dispose_engine()

    return {**resumen, "estado_global": stats}


async def resolver() -> dict:
    """Cierra la corroboración de las misiones cuya ventana venció."""
    from db import dispose_engine, get_session_factory
    from ingestion_repository import IngestionRepository
    from repository import AnalystRepository, VerdictRepository
    from gamification import ProgressionEngine
    from scoring import GroundTruth

    resumen = {"resueltas": 0, "expiradas": 0, "veredictos_calificados": 0}
    factory = get_session_factory()
    try:
        async with factory() as session:
            ingesta = IngestionRepository(session)
            veredictos = VerdictRepository(
                session, AnalystRepository(session, ProgressionEngine())
            )

            for mission in await ingesta.due_for_resolution():
                verdad, fuente, motivo = await ingesta.verdict_for(mission)

                if verdad is GroundTruth.UNKNOWN or fuente is None:
                    # No se inventa una verdad para poder puntuar.
                    await ingesta.expire_unresolvable(mission)
                    resumen["expiradas"] += 1
                    log.info(
                        "%s · expirada sin calificar (%s)", mission.mission_id, motivo
                    )
                    continue

                salida = await veredictos.resolve(mission.mission_id, verdad, fuente)
                resumen["resueltas"] += 1
                resumen["veredictos_calificados"] += salida["verdicts_graded"]
                log.info(
                    "%s · %s (%s) · %d veredicto(s) calificados",
                    mission.mission_id,
                    verdad.value,
                    motivo,
                    salida["verdicts_graded"],
                )
            await session.commit()
    finally:
        await dispose_engine()
    return resumen


def imprimir_dry_run(misiones: list[dict], estado: dict[str, str]) -> None:
    print("\n╔══════════════════════════════════════════════════════════════════╗")
    print("║  ATALAYA · Ingesta en seco (no se escribió nada)                 ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print("\n  Fuentes:")
    for fuente, res in estado.items():
        print(f"    {fuente:<24} {res}")

    print(f"\n  Misiones candidatas: {len(misiones)}\n")
    print(
        f"    {'MISIÓN':<14} {'SEV':<9} {'VERDAD':<10} {'OP':<3} {'KEV':<4} INDICADOR"
    )
    print("    " + "─" * 74)
    for m in misiones[:15]:
        print(
            f"    {m['mission_id']:<14} {m['severity']:<9} {m['ground_truth']:<10} "
            f"{m['independent_sources']:<3} {'sí' if m['kev_listed'] else '—':<4} "
            f"{m['ioc_defanged'][:34]}"
        )
    ambiguas = sum(1 for m in misiones if m["ground_truth"] == "UNKNOWN")
    print(
        f"\n  {ambiguas} de {len(misiones)} entran AMBIGUAS y esperan corroboración.\n"
        "  Ese es el material de la calificación diferida: el analista apuesta\n"
        "  hoy y el tiempo le da o le quita la razón."
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="run",
        description="ATALAYA · orquestador de ingesta OSINT",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    modo = p.add_mutually_exclusive_group(required=True)
    modo.add_argument(
        "--dry-run", action="store_true", help="Consulta y muestra, sin escribir."
    )
    modo.add_argument("--ingest", action="store_true", help="Consulta y persiste.")
    modo.add_argument(
        "--resolve", action="store_true", help="Resuelve corroboración vencida."
    )
    modo.add_argument("--loop", action="store_true", help="Ciclo continuo.")
    p.add_argument("--source", help="Una sola fuente: cisa_kev | threatfox | otx")
    p.add_argument(
        "--limit", type=int, default=int(os.getenv("INGEST_MAX_IOCS_PER_RUN", "100"))
    )
    p.add_argument("-o", "--out", metavar="ARCHIVO", help="Vuelca las misiones a JSON.")
    args = p.parse_args(argv)

    if args.resolve:
        print(json.dumps(asyncio.run(resolver()), indent=2, ensure_ascii=False))
        return 0

    if args.loop:
        intervalo = int(os.getenv("INGEST_INTERVAL_MINUTES", "15")) * 60
        log.info(
            "Ciclo de ingesta cada %d minutos. Ctrl-C para cortar.", intervalo // 60
        )
        while True:
            try:
                _ciclo(args)
                log.info("Resolución: %s", asyncio.run(resolver()))
            except KeyboardInterrupt:
                log.info("Ciclo detenido.")
                return 0
            except Exception:  # noqa: BLE001 - el ciclo no muere por una corrida
                log.exception("Fallo en el ciclo; se reintenta en el próximo turno.")
            time.sleep(intervalo)

    return _ciclo(args)


def _ciclo(args) -> int:
    # Las fuentes de volcado se descargan enteras de todos modos: se parsea
    # un lote amplio y el tope de verdad se aplica sobre las misiones, que es
    # donde se balancean las categorías.
    crudos, estado = recolectar(max(args.limit * 10, 1000), args.source)
    if not crudos:
        log.warning(
            "Ninguna fuente devolvió indicadores. Revisá las credenciales en .env "
            "(OTX_API_KEY, ABUSECH_AUTH_KEY). CISA KEV no necesita ninguna."
        )
    misiones = missions_from(crudos, max_missions=args.limit)

    if args.out:
        Path(args.out).write_text(
            json.dumps(misiones, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        print(f"[+] {len(misiones)} misiones escritas en {args.out}")

    if args.dry_run:
        imprimir_dry_run(misiones, estado)
        return 0

    resumen = asyncio.run(persistir(misiones, crudos))
    print(json.dumps(resumen, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
