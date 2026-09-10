"""
ATALAYA // Persistencia de la progresión.

Todo lo que el analista "es" se **deriva** de `xp_events`. No hay contadores
mutables: no hay forma de que la XP mostrada y los eventos que la produjeron
digan cosas distintas.

Las tres agregaciones que alimentan el panel del analista:

    xp                  = SUM(xp_delta_applied)
    misiones_completadas= COUNT(event = 'mission_triage')
    iocs_verificados    = COUNT(event IN ('ioc_verified','correlation_confirmed'))

y la racha, que necesita una función de ventana porque no es un conteo sino
"cuántos eventos positivos consecutivos hay desde el más reciente hacia atrás".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from gamification import ProgressionEngine, Rank, RankSpec, XPEvent
from models import Analyst, MissionRecord, Verdict
from models import XPEvent as XPEventRow
from scoring import (
    CORROBORATION_WINDOW_HOURS,
    Call,
    GroundTruth,
    TruthSource,
    calibration_score,
    grade_verdict,
    overconfidence,
    requires_rationale,
)

#: Eventos que cuentan como "IoC verificado" en las métricas del panel.
VERIFICATION_EVENTS = ("ioc_verified", "correlation_confirmed")


@dataclass
class AnalystSnapshot:
    """Foto del analista en un instante. Todo derivado, nada almacenado."""

    callsign: str
    xp: int
    spec: RankSpec
    missions_completed: int
    iocs_verified: int
    streak: int
    joined_at: datetime
    last_event_at: datetime | None
    recent_events: list[dict[str, Any]] = field(default_factory=list)


class AnalystRepository:
    """Acceso a datos de la progresión. Una instancia por petición."""

    def __init__(self, session: AsyncSession, engine: ProgressionEngine) -> None:
        self._session = session
        self._engine = engine

    # ══════════════════════════════════════════════════════════════════
    #  Lectura
    # ══════════════════════════════════════════════════════════════════

    async def find(self, callsign: str) -> Analyst | None:
        """Busca sin crear.

        Los endpoints de LECTURA usan esto y no `get_or_create`: con el otro,
        un simple GET a /api/v1/analysts/loquesea daba de alta un analista, y
        eso es una forma barata de llenar la tabla de basura.
        """
        return await self._session.scalar(
            select(Analyst).where(Analyst.callsign == callsign)
        )

    async def get_or_create(self, callsign: str) -> Analyst:
        """Devuelve el analista, creándolo si es su primera aparición.

        La carrera de dos peticiones simultáneas del mismo callsign se resuelve
        contra el índice único: si la inserción choca, se relee. Comprobar
        primero y después insertar (check-then-act) es exactamente la carrera
        que hay que evitar.
        """
        found = await self._session.scalar(
            select(Analyst).where(Analyst.callsign == callsign)
        )
        if found is not None:
            return found

        analyst = Analyst(callsign=callsign)
        self._session.add(analyst)
        try:
            await self._session.flush()
        except IntegrityError:
            await self._session.rollback()
            analyst = await self._session.scalar(
                select(Analyst).where(Analyst.callsign == callsign)
            )
            if analyst is None:  # pragma: no cover - sólo si la base miente
                raise
        return analyst

    async def _aggregates(self, analyst_id) -> tuple[int, int, int, datetime | None]:
        """XP total, misiones, IoCs verificados y fecha del último evento."""
        stmt = select(
            func.coalesce(func.sum(XPEventRow.xp_delta_applied), 0),
            func.count(XPEventRow.id).filter(XPEventRow.event == "mission_triage"),
            func.count(XPEventRow.id).filter(XPEventRow.event.in_(VERIFICATION_EVENTS)),
            func.max(XPEventRow.created_at),
        ).where(XPEventRow.analyst_id == analyst_id)

        xp, missions, iocs, last = (await self._session.execute(stmt)).one()
        return int(xp), int(missions), int(iocs), last

    async def _streak(self, analyst_id) -> int:
        """Eventos positivos consecutivos desde el más reciente hacia atrás.

        Se recorre el historial en orden descendente contando cuántos eventos
        no positivos quedaron por encima de cada fila; las filas con cero
        cortes son, exactamente, la racha vigente.
        """
        stmt = text("""
            SELECT COUNT(*) AS racha FROM (
                SELECT SUM(CASE WHEN xp_delta_applied <= 0 THEN 1 ELSE 0 END)
                       OVER (ORDER BY id DESC ROWS UNBOUNDED PRECEDING) AS cortes
                FROM xp_events
                WHERE analyst_id = :analyst_id
            ) t
            WHERE cortes = 0
            """)
        result = await self._session.execute(stmt, {"analyst_id": analyst_id})
        return int(result.scalar_one() or 0)

    async def _recent(self, analyst_id, limit: int = 10) -> list[dict[str, Any]]:
        """Últimos eventos, para la bitácora del panel lateral."""
        stmt = (
            select(XPEventRow)
            .where(XPEventRow.analyst_id == analyst_id)
            .order_by(XPEventRow.id.desc())
            .limit(limit)
        )
        rows = (await self._session.scalars(stmt)).all()
        return [
            {
                "event": row.event,
                "mission_id": row.mission_id,
                "severity": row.severity,
                "xp_delta": row.xp_delta_applied,
                "at": row.created_at.isoformat(),
            }
            for row in rows
        ]

    async def snapshot(self, callsign: str, history: int = 10) -> AnalystSnapshot:
        """Estado completo del analista."""
        analyst = await self.get_or_create(callsign)
        xp, missions, iocs, last = await self._aggregates(analyst.id)
        return AnalystSnapshot(
            callsign=analyst.callsign,
            xp=xp,
            spec=self._engine.rank_for_xp(xp),
            missions_completed=missions,
            iocs_verified=iocs,
            streak=await self._streak(analyst.id),
            joined_at=analyst.joined_at,
            last_event_at=last,
            recent_events=await self._recent(analyst.id, history),
        )

    async def current_rank(self, callsign: str) -> Rank:
        """Rango actual. Consulta mínima: la usa el feed para marcar bloqueos."""
        analyst = await self.get_or_create(callsign)
        xp = await self._session.scalar(
            select(func.coalesce(func.sum(XPEventRow.xp_delta_applied), 0)).where(
                XPEventRow.analyst_id == analyst.id
            )
        )
        return self._engine.rank_for_xp(int(xp or 0)).rank

    async def leaderboard(self, limit: int = 10) -> list[dict[str, Any]]:
        """Ranking de la torre, calculado sobre los eventos."""
        xp_col = func.coalesce(func.sum(XPEventRow.xp_delta_applied), 0).label("xp")
        iocs_col = func.count(XPEventRow.id).filter(
            XPEventRow.event.in_(VERIFICATION_EVENTS)
        )
        stmt = (
            select(Analyst.callsign, xp_col, iocs_col)
            .select_from(Analyst)
            .outerjoin(XPEventRow, XPEventRow.analyst_id == Analyst.id)
            .group_by(Analyst.id, Analyst.callsign)
            .order_by(xp_col.desc(), Analyst.callsign)
            .limit(limit)
        )
        rows = (await self._session.execute(stmt)).all()
        return [
            {
                "callsign": callsign,
                "xp": int(xp),
                "rank": self._engine.rank_for_xp(int(xp)).rank.value,
                "iocs_verified": int(iocs),
            }
            for callsign, xp, iocs in rows
        ]

    async def count_analysts(self) -> int:
        return int(await self._session.scalar(select(func.count(Analyst.id))) or 0)

    # ══════════════════════════════════════════════════════════════════
    #  Escritura
    # ══════════════════════════════════════════════════════════════════

    async def award_computed(
        self,
        analyst: Analyst,
        event: XPEvent,
        delta: int,
        mission_id: str | None = None,
        severity: str = "medium",
    ) -> int:
        """Registra un evento con un delta ya calculado afuera.

        Lo usa la calificación de veredictos, cuya XP sale del Brier y no de
        la tabla fija. Aplica el mismo piso en cero que `award`, para que
        `SUM(xp_delta_applied)` siga siendo exacta.
        """
        xp_before, _, _, _ = await self._aggregates(analyst.id)
        applied = max(delta, -xp_before) if delta < 0 else delta

        self._session.add(
            XPEventRow(
                analyst_id=analyst.id,
                event=event.value,
                mission_id=mission_id,
                severity=severity,
                xp_delta_nominal=delta,
                xp_delta_applied=applied,
            )
        )
        await self._session.flush()
        return applied

    async def award(
        self,
        callsign: str,
        event: XPEvent,
        severity: str = "medium",
        mission_id: str | None = None,
        multiplier: float = 1.0,
    ) -> dict[str, Any]:
        """Registra un evento de XP y devuelve el resultado del ascenso."""
        analyst = await self.get_or_create(callsign)

        # Bloqueo de fila del analista: serializa las concesiones de XP de una
        # misma persona. Sin esto, dos peticiones simultáneas leen el mismo
        # saldo y ambas aplican una penalización completa, dejando la XP
        # total en negativo — un estado que el piso en cero debería impedir.
        await self._session.execute(
            select(Analyst.id).where(Analyst.id == analyst.id).with_for_update()
        )

        xp_before, _, _, _ = await self._aggregates(analyst.id)
        rank_before = self._engine.rank_for_xp(xp_before)

        nominal = self._engine.compute_delta(event, severity, multiplier)
        # El piso en cero se resuelve acá y se guarda ya aplicado, para que
        # SUM(xp_delta_applied) siga siendo exacta. Castigamos el error, no
        # expulsamos al que aprende.
        applied = max(nominal, -xp_before) if nominal < 0 else nominal

        row = XPEventRow(
            analyst_id=analyst.id,
            event=event.value,
            mission_id=mission_id,
            severity=severity,
            xp_delta_nominal=nominal,
            xp_delta_applied=applied,
        )

        already_awarded = False
        try:
            # SAVEPOINT, no la transacción entera. Si el insert choca contra
            # el índice anti-farmeo, un `rollback()` completo se llevaría
            # puesto también el alta del analista y el bloqueo FOR UPDATE que
            # tomamos arriba — y habría que rehacer todo el trabajo previo.
            # El punto de guardado revierte exactamente la fila que falló.
            async with self._session.begin_nested():
                self._session.add(row)
                await self._session.flush()
        except IntegrityError:
            # Esta misión ya acreditó este evento para este analista. No es un
            # error del cliente: es la defensa anti-farmeo funcionando.
            # El rollback del punto de guardado ya sacó la fila pendiente de
            # la sesión; llamar a expunge() acá tira InvalidRequestError.
            already_awarded = True
            applied = 0

        xp_after = xp_before + applied
        rank_after = self._engine.rank_for_xp(xp_after)
        promoted = rank_after.level > rank_before.level
        nxt = self._engine.next_rank(rank_after.rank)

        return {
            "callsign": analyst.callsign,
            "event": event.value,
            "xp_delta": applied,
            "xp_total": xp_after,
            "rank": rank_after.rank.value,
            "rank_label": rank_after.label,
            "level": rank_after.level,
            "clearance": rank_after.clearance,
            "promoted": promoted,
            "previous_rank": rank_before.rank.value,
            "unlocked": list(rank_after.unlocks) if promoted else [],
            "next_rank": nxt.rank.value if nxt else None,
            "xp_to_next": max(0, nxt.xp_required - xp_after) if nxt else 0,
            "progress": round(self._engine.progress_to_next(xp_after), 4),
            "streak": await self._streak(analyst.id),
            "already_awarded": already_awarded,
            "message": self._engine.flavor(promoted, rank_after, applied),
        }


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class VerdictRepository:
    """El bucle de verificación: apuestas, verdad de referencia y calificación.

    Ver `docs/VERIFICACION.md`. Resumen: el analista declara qué cree y con
    cuánta confianza; cuando la verdad se resuelve, se lo califica con una
    regla de puntuación propia que premia la calibración, no la suerte.
    """

    def __init__(self, session: AsyncSession, analysts: AnalystRepository) -> None:
        self._session = session
        self._analysts = analysts

    # ══════════════════════════════════════════════════════════════════
    #  Catálogo
    # ══════════════════════════════════════════════════════════════════

    async def seed_missions(self, missions: list[dict[str, Any]]) -> int:
        """Sincroniza el catálogo con la tabla. Idempotente.

        Sólo inserta lo que falta: si una misión ya tiene veredictos emitidos,
        reescribirle la verdad de referencia sería cambiar las reglas después
        de que la gente apostó.
        """
        existentes = {
            r.mission_id: r
            for r in (await self._session.scalars(select(MissionRecord))).all()
        }
        nuevas = 0
        for m in missions:
            if m["mission_id"] in existentes:
                # Relleno del contenido en misiones sembradas antes de que
                # existiera la columna. Sólo el contenido: la verdad de
                # referencia de una misión ya jugada no se toca nunca.
                fila = existentes[m["mission_id"]]
                if fila.payload is None:
                    fila.payload = mission_payload(m)
                continue
            resuelta = m.get("ground_truth", "UNKNOWN") != "UNKNOWN"
            self._session.add(
                MissionRecord(
                    mission_id=m["mission_id"],
                    title=m["title"][:200],
                    severity=m["severity"],
                    base_xp=m["xp_reward"],
                    required_rank=m["required_rank"],
                    source=m["source"][:64],
                    ground_truth=m.get("ground_truth", "UNKNOWN"),
                    truth_source=m.get("truth_source"),
                    source_confidence=m.get("source_confidence", 50),
                    independent_sources=m.get("independent_sources", 1),
                    kev_listed=m.get("kev_listed", False),
                    resolves_at=(
                        None
                        if resuelta
                        else utcnow() + timedelta(hours=CORROBORATION_WINDOW_HOURS)
                    ),
                    resolved_at=utcnow() if resuelta else None,
                    payload=mission_payload(m),
                )
            )
            nuevas += 1
        if nuevas:
            await self._session.flush()
        return nuevas

    async def get_mission(self, mission_id: str) -> MissionRecord | None:
        return await self._session.get(MissionRecord, mission_id.upper())

    # ══════════════════════════════════════════════════════════════════
    #  Emisión de veredictos
    # ══════════════════════════════════════════════════════════════════

    async def submit(
        self,
        callsign: str,
        mission_id: str,
        call: Call,
        confidence: int,
        rationale: str | None = None,
    ) -> dict[str, Any]:
        """Registra el veredicto y, si la verdad ya está, lo califica en el acto."""
        mission = await self.get_mission(mission_id)
        if mission is None:
            raise LookupError(f"Misión {mission_id} inexistente.")

        if requires_rationale(confidence) and not (rationale or "").strip():
            raise ValueError(
                f"Con confianza >= {confidence}% hace falta fundamento escrito. "
                "Una certeza alta sin argumento no es análisis."
            )

        analyst = await self._analysts.get_or_create(callsign)

        verdict = Verdict(
            analyst_id=analyst.id,
            mission_id=mission.mission_id,
            call=call.value,
            confidence=confidence,
            rationale=(rationale or "").strip() or None,
        )
        try:
            async with self._session.begin_nested():
                self._session.add(verdict)
                await self._session.flush()
        except IntegrityError:
            raise PermissionError(
                "Ya emitiste tu veredicto sobre esta misión. No se puede "
                "cambiar una llamada después de hacerla."
            )

        truth = GroundTruth(mission.ground_truth)

        # ── ¿Es un veredicto fuera de término? ───────────────────────
        # La regla aplica SÓLO a las misiones que nacieron ambiguas y se
        # resolvieron después (las que tienen ventana de corroboración, o
        # sea `resolves_at`). Ahí sí, apostar una vez conocida la respuesta
        # no mide criterio: mide capacidad de leer el resultado.
        #
        # Las misiones que nacen con verdad conocida —KEV, curadas,
        # multi-fuente— no tienen "respuesta filtrada" que esperar: el
        # analista tiene que ir a buscarla, y eso es exactamente el ejercicio.
        # Tratarlas como tardías dejaba sin calificar a todo el mundo.
        nacio_ambigua = mission.resolves_at is not None
        tardio = nacio_ambigua and mission.resolved_at is not None

        if truth is GroundTruth.UNKNOWN:
            return self._respuesta(
                verdict,
                mission,
                calificado=False,
                xp=0,
                mensaje=(
                    ">> VEREDICTO SELLADO :: la verdad de referencia todavía no "
                    f"se resolvió :: corroboración en curso ({mission.independent_sources}"
                    f" fuente/s)"
                ),
            )

        if tardio:
            return self._respuesta(
                verdict,
                mission,
                calificado=False,
                xp=0,
                mensaje=(
                    ">> VEREDICTO FUERA DE TÉRMINO :: la verdad ya era pública "
                    ":: registrado sin puntaje"
                ),
            )

        xp = await self._grade_one(verdict, mission, analyst)
        resultado = grade_verdict(call, confidence, truth, mission.base_xp)
        return self._respuesta(
            verdict, mission, calificado=True, xp=xp, mensaje=resultado.explanation
        )

    async def _grade_one(
        self, verdict: Verdict, mission: MissionRecord, analyst: Analyst
    ) -> int:
        """Califica un veredicto y asienta la XP resultante."""
        resultado = grade_verdict(
            Call(verdict.call),
            verdict.confidence,
            GroundTruth(mission.ground_truth),
            mission.base_xp,
        )
        verdict.graded_at = utcnow()
        verdict.brier_score = resultado.brier
        verdict.was_correct = resultado.was_correct
        verdict.xp_awarded = resultado.xp

        aplicado = 0
        if resultado.xp != 0:
            aplicado = await self._analysts.award_computed(
                analyst=analyst,
                event=XPEvent.VERDICT_GRADED,
                delta=resultado.xp,
                mission_id=mission.mission_id,
                severity=mission.severity,
            )
        await self._session.flush()
        return aplicado

    def _respuesta(
        self,
        verdict: Verdict,
        mission: MissionRecord,
        calificado: bool,
        xp: int,
        mensaje: str,
    ) -> dict[str, Any]:
        return {
            "mission_id": mission.mission_id,
            "call": verdict.call,
            "confidence": verdict.confidence,
            "submitted_at": (verdict.submitted_at or utcnow()).isoformat(),
            "graded": calificado,
            "brier_score": verdict.brier_score,
            "xp_awarded": xp,
            "was_correct": verdict.was_correct,
            "ground_truth": mission.ground_truth if calificado else None,
            "truth_source": mission.truth_source if calificado else None,
            "message": mensaje,
        }

    # ══════════════════════════════════════════════════════════════════
    #  Resolución de la verdad
    # ══════════════════════════════════════════════════════════════════

    async def resolve(
        self, mission_id: str, truth: GroundTruth, source: TruthSource
    ) -> dict[str, Any]:
        """Fija la verdad de una misión y califica todo lo pendiente.

        Es el punto de entrada del trabajo de corroboración diferida: pasadas
        las 72 h, se mira cuántas fuentes independientes corroboraron y se
        califica de una sola vez a todos los que apostaron a ciegas.
        """
        mission = await self.get_mission(mission_id)
        if mission is None:
            raise LookupError(f"Misión {mission_id} inexistente.")
        if mission.ground_truth != "UNKNOWN":
            raise PermissionError(
                "Esa misión ya tiene verdad de referencia. Cambiarla sería "
                "modificar las reglas después de que la gente apostó."
            )

        mission.ground_truth = truth.value
        mission.truth_source = source.value
        mission.resolved_at = utcnow()

        pendientes = (
            await self._session.scalars(
                select(Verdict)
                .where(Verdict.mission_id == mission.mission_id)
                .where(Verdict.graded_at.is_(None))
            )
        ).all()

        calificados = 0
        for verdict in pendientes:
            analyst = await self._session.get(Analyst, verdict.analyst_id)
            if analyst is None:  # pragma: no cover
                continue
            await self._grade_one(verdict, mission, analyst)
            calificados += 1

        await self._session.flush()
        return {
            "mission_id": mission.mission_id,
            "ground_truth": truth.value,
            "truth_source": source.value,
            "verdicts_graded": calificados,
        }

    # ══════════════════════════════════════════════════════════════════
    #  Calibración
    # ══════════════════════════════════════════════════════════════════

    async def calibration(self, callsign: str) -> dict[str, Any]:
        """Cuánto vale la palabra del analista.

        La XP dice cuánto trabajó. Esto dice si acierta cuando dice que está
        seguro — que es la pregunta que un jefe de SOC realmente hace.
        """
        analyst = await self._analysts.get_or_create(callsign)
        filas = (
            await self._session.execute(
                select(Verdict.brier_score, Verdict.confidence, Verdict.was_correct)
                .where(Verdict.analyst_id == analyst.id)
                .where(Verdict.graded_at.is_not(None))
                .where(Verdict.brier_score.is_not(None))
            )
        ).all()

        pendientes = await self._session.scalar(
            select(func.count(Verdict.id))
            .where(Verdict.analyst_id == analyst.id)
            .where(Verdict.graded_at.is_(None))
        )

        briers = [f[0] for f in filas]
        confianzas = [f[1] for f in filas]
        aciertos = [bool(f[2]) for f in filas]

        return {
            "callsign": analyst.callsign,
            "verdicts_graded": len(filas),
            "verdicts_pending": int(pendientes or 0),
            "calibration": calibration_score(briers),
            "mean_brier": round(sum(briers) / len(briers), 4) if briers else None,
            "accuracy": (round(sum(aciertos) / len(aciertos), 4) if aciertos else None),
            "mean_confidence": (
                round(sum(confianzas) / len(confianzas), 2) if confianzas else None
            ),
            "overconfidence": overconfidence(confianzas, aciertos),
        }

    async def my_verdict(self, callsign: str, mission_id: str) -> Verdict | None:
        analyst = await self._analysts.get_or_create(callsign)
        return await self._session.scalar(
            select(Verdict)
            .where(Verdict.analyst_id == analyst.id)
            .where(Verdict.mission_id == mission_id.upper())
        )


#: Campos de la misión que NO van al payload porque ya viven en columnas, o
#: porque cambian con el tiempo y tienen que leerse de su fuente de verdad.
_FUERA_DEL_PAYLOAD = {
    "ground_truth",
    "truth_source",
    "independent_sources",
    "kev_listed",
    "locked",
}


def mission_payload(mision: dict[str, Any]) -> dict[str, Any]:
    """El contenido de la misión, listo para servir desde el feed."""
    return {
        k: (v.isoformat() if isinstance(v, datetime) else v)
        for k, v in mision.items()
        if k not in _FUERA_DEL_PAYLOAD
    }


class FeedRepository:
    """Lectura del feed de misiones desde la base.

    Hasta ahora el feed servía un catálogo fijo en memoria. Leer de la tabla
    es lo que hace que lo que traen los conectores —CVEs del KEV, C2 de
    ThreatFox— llegue efectivamente a la pantalla del analista.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def page(
        self, offset: int, limit: int, severity: str | None = None
    ) -> tuple[list[MissionRecord], int]:
        """Una página del feed y el total disponible con ese filtro."""
        base = select(MissionRecord).where(MissionRecord.payload.is_not(None))
        if severity:
            base = base.where(MissionRecord.severity == severity)

        total = await self._session.scalar(
            select(func.count()).select_from(base.subquery())
        )
        filas = (
            await self._session.scalars(
                base.order_by(
                    MissionRecord.first_reported_at.desc(), MissionRecord.mission_id
                )
                .offset(offset)
                .limit(limit)
            )
        ).all()
        return list(filas), int(total or 0)

    async def get(self, mission_id: str) -> MissionRecord | None:
        return await self._session.get(MissionRecord, mission_id.upper())

    async def verdicts_of(
        self, analyst_id, mission_ids: list[str]
    ) -> dict[str, Verdict]:
        """Veredictos del analista sobre las misiones de esta página.

        Una sola consulta para toda la página: sin esto, mostrar "ya emitiste
        tu veredicto" en cada tarjeta serían veinte consultas por pantalla.
        """
        if not mission_ids:
            return {}
        filas = (
            await self._session.scalars(
                select(Verdict)
                .where(Verdict.analyst_id == analyst_id)
                .where(Verdict.mission_id.in_(mission_ids))
            )
        ).all()
        return {v.mission_id: v for v in filas}

    async def counts(self) -> dict[str, Any]:
        por_sev = dict(
            (
                await self._session.execute(
                    select(MissionRecord.severity, func.count(MissionRecord.mission_id))
                    .where(MissionRecord.payload.is_not(None))
                    .group_by(MissionRecord.severity)
                )
            ).all()
        )
        fuentes = (
            await self._session.scalars(
                select(MissionRecord.source).distinct().limit(20)
            )
        ).all()
        return {
            "total": sum(int(v) for v in por_sev.values()),
            "by_severity": {k: int(v) for k, v in por_sev.items()},
            "sources": sorted(set(fuentes)),
        }
