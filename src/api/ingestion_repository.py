"""
ATALAYA // Persistencia de la ingesta y resolución de la corroboración.

Dos trabajos, y el segundo es el que hace que el bucle de verificación cierre:

  1. `upsert_mission`  — registra la misión y el avistamiento de cada fuente.
  2. `resolve_due`     — pasadas las 72 h, mira cuántos OPERADORES distintos
                          terminaron corroborando y fija la verdad.

Hasta ahora la corroboración diferida era una promesa del diseño: las
misiones nacían ambiguas y nadie las resolvía nunca. Esto es lo que la
convierte en un hecho.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from models import IndicatorSighting, MissionRecord
from scoring import (
    CORROBORATION_THRESHOLD,
    GroundTruth,
    TruthSource,
    corroboration_verdict,
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class IngestionRepository:
    """Escribe lo que traen los conectores y resuelve lo que el tiempo aclara."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # ══════════════════════════════════════════════════════════════════
    #  Ingesta
    # ══════════════════════════════════════════════════════════════════

    async def upsert_mission(
        self, mision: dict[str, Any], avistamientos: list[dict[str, Any]]
    ) -> str:
        """Registra o actualiza una misión con los avistamientos que la sostienen.

        Devuelve: "creada", "corroborada" (sumó un operador nuevo) o "sin-cambios".

        Regla dura: si la misión ya tiene verdad de referencia fijada, NO se
        toca. Cambiarla después de que la gente apostó sería mover el arco.
        """
        existente = await self._session.get(MissionRecord, mision["mission_id"])
        familias_antes = await self._independent_families(mision["mission_id"])

        if existente is None:
            ambigua = mision["ground_truth"] == "UNKNOWN"
            existente = MissionRecord(
                mission_id=mision["mission_id"],
                fingerprint=mision.get("fingerprint"),
                title=mision["title"][:200],
                severity=mision["severity"],
                base_xp=mision["xp_reward"],
                required_rank=mision["required_rank"],
                source=mision["source"][:64],
                ground_truth=mision["ground_truth"],
                truth_source=mision.get("truth_source"),
                source_confidence=mision["source_confidence"],
                independent_sources=mision["independent_sources"],
                kev_listed=mision["kev_listed"],
                resolves_at=(utcnow() + _ventana() if ambigua else None),
                resolved_at=None if ambigua else utcnow(),
            )
            self._session.add(existente)
            await self._session.flush()
            estado = "creada"
        else:
            estado = "sin-cambios"

        for a in avistamientos:
            await self._upsert_sighting(existente.mission_id, mision, a)
        await self._session.flush()

        familias_despues = await self._independent_families(existente.mission_id)
        if familias_despues != existente.independent_sources:
            existente.independent_sources = familias_despues
            if estado != "creada" and familias_despues > familias_antes:
                estado = "corroborada"

        # Un KEV que llega después convierte una misión ambigua en verdad dura
        # de inmediato: no hay nada que esperar cuando CISA ya lo confirmó.
        if any(a.get("kev_listed") for a in avistamientos) and not existente.kev_listed:
            existente.kev_listed = True

        await self._session.flush()
        return estado

    async def _upsert_sighting(
        self, mission_id: str, mision: dict[str, Any], a: dict[str, Any]
    ) -> None:
        fila = await self._session.scalar(
            select(IndicatorSighting)
            .where(IndicatorSighting.mission_id == mission_id)
            .where(IndicatorSighting.source_name == a["source_name"])
        )
        if fila is None:
            self._session.add(
                IndicatorSighting(
                    mission_id=mission_id,
                    fingerprint=mision.get("fingerprint", "")[:512],
                    source_name=a["source_name"][:64],
                    source_family=a["source_family"][:32],
                    source_reference=(a.get("source_reference") or "")[:512] or None,
                    source_confidence=a.get("source_confidence", 50),
                    first_reported_at=a["first_reported_at"],
                    sample_available=a.get("sample_available", False),
                    kev_listed=a.get("kev_listed", False),
                )
            )
            return

        # Ya la habíamos visto por esta fuente: se refresca lo que puede
        # mejorar (confianza, muestra disponible) y nada más.
        fila.observed_at = utcnow()
        fila.source_confidence = max(
            fila.source_confidence, a.get("source_confidence", 0)
        )
        fila.sample_available = fila.sample_available or a.get(
            "sample_available", False
        )
        fila.kev_listed = fila.kev_listed or a.get("kev_listed", False)

    async def _independent_families(self, mission_id: str) -> int:
        """Operadores distintos que reportaron esta misión."""
        n = await self._session.scalar(
            select(func.count(func.distinct(IndicatorSighting.source_family))).where(
                IndicatorSighting.mission_id == mission_id
            )
        )
        return int(n or 0)

    # ══════════════════════════════════════════════════════════════════
    #  Resolución de la corroboración diferida
    # ══════════════════════════════════════════════════════════════════

    async def due_for_resolution(self, limit: int = 200) -> list[MissionRecord]:
        """Misiones ambiguas cuya ventana de corroboración ya venció."""
        return list(
            (
                await self._session.scalars(
                    select(MissionRecord)
                    .where(MissionRecord.ground_truth == "UNKNOWN")
                    .where(MissionRecord.resolves_at.is_not(None))
                    .where(MissionRecord.resolves_at <= utcnow())
                    .order_by(MissionRecord.resolves_at)
                    .limit(limit)
                )
            ).all()
        )

    async def verdict_for(
        self, mission: MissionRecord
    ) -> tuple[GroundTruth, TruthSource | None, str]:
        """Qué dice la evidencia acumulada sobre esta misión.

        Tres desenlaces posibles, y el tercero es el honesto:

          MALICIOUS  — alcanzó el umbral de operadores independientes, o KEV.
          BENIGN     — la ventana venció con una sola fuente y la que lo
                       reportó era de baja confianza. Nadie más lo vio: el
                       peso de la evidencia dice que fue ruido.
          UNKNOWN    — quedó a mitad de camino. No se inventa una verdad para
                       poder puntuar; la misión expira sin calificar y se le
                       avisa al analista.
        """
        familias = await self._independent_families(mission.mission_id)
        verdad, fuente = corroboration_verdict(familias, mission.kev_listed)
        if verdad is not GroundTruth.UNKNOWN:
            return verdad, fuente, f"{familias} operadores independientes"

        confianza_max = await self._session.scalar(
            select(func.max(IndicatorSighting.source_confidence)).where(
                IndicatorSighting.mission_id == mission.mission_id
            )
        )
        con_muestra = await self._session.scalar(
            select(func.count(IndicatorSighting.id))
            .where(IndicatorSighting.mission_id == mission.mission_id)
            .where(IndicatorSighting.sample_available.is_(True))
        )

        # Una sola fuente, de baja confianza, sin muestra y pasadas 72 h sin
        # que nadie más lo viera: la mejor explicación es que fue un falso
        # positivo. Estas son las misiones que enseñan a NO bloquear.
        if familias <= 1 and int(confianza_max or 0) < 60 and not int(con_muestra or 0):
            return (
                GroundTruth.BENIGN,
                TruthSource.CORROBORATION,
                "ninguna corroboración en la ventana y baja confianza de origen",
            )

        return (
            GroundTruth.UNKNOWN,
            None,
            f"evidencia insuficiente ({familias} fuente/s)",
        )

    async def expire_unresolvable(self, mission: MissionRecord) -> None:
        """Cierra una misión que nunca se va a poder calificar.

        Dejarla colgada para siempre sería peor: el analista queda con un
        veredicto pendiente que jamás puntúa y sin saber por qué.
        """
        mission.resolves_at = None
        mission.truth_source = None
        await self._session.flush()

    async def stats(self) -> dict[str, Any]:
        por_verdad = dict(
            (
                await self._session.execute(
                    select(
                        MissionRecord.ground_truth, func.count(MissionRecord.mission_id)
                    ).group_by(MissionRecord.ground_truth)
                )
            ).all()
        )
        por_familia = dict(
            (
                await self._session.execute(
                    select(
                        IndicatorSighting.source_family,
                        func.count(func.distinct(IndicatorSighting.mission_id)),
                    ).group_by(IndicatorSighting.source_family)
                )
            ).all()
        )
        pendientes = await self._session.scalar(
            select(func.count(MissionRecord.mission_id))
            .where(MissionRecord.ground_truth == "UNKNOWN")
            .where(MissionRecord.resolves_at.is_not(None))
        )
        return {
            "missions_by_truth": {k: int(v) for k, v in por_verdad.items()},
            "missions_by_source_family": {k: int(v) for k, v in por_familia.items()},
            "awaiting_corroboration": int(pendientes or 0),
            "corroboration_threshold": CORROBORATION_THRESHOLD,
        }


def _ventana():
    from datetime import timedelta

    from scoring import CORROBORATION_WINDOW_HOURS

    return timedelta(hours=CORROBORATION_WINDOW_HOURS)
