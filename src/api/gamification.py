"""
ATALAYA // Motor de progresión.

Doctrina: la XP no se regala por hacer scroll. Se gana por producir
inteligencia verificable. Un falso positivo confirmado RESTA, porque en un SOC
real gritar "lobo" tiene costo operativo.

Este módulo es **puro**: define las reglas y no sabe nada de bases de datos.
El estado del analista se persiste en `repository.AnalystRepository`.

Rangos:
    0 · NOVATO                 -> acceso de lectura al feed
    1 · ANALISTA_JUNIOR        -> puede enriquecer y reportar IoCs
    2 · ANALISTA_SENIOR        -> puede verificar y correlacionar campañas
    3 · CAZADOR_DE_AMENAZAS    -> puede publicar a MISP y crear misiones
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Rank(str, Enum):
    """Rangos del analista. El orden de declaración ES la progresión."""

    NOVATO = "NOVATO"
    ANALISTA_JUNIOR = "ANALISTA_JUNIOR"
    ANALISTA_SENIOR = "ANALISTA_SENIOR"
    CAZADOR_DE_AMENAZAS = "CAZADOR_DE_AMENAZAS"


@dataclass(frozen=True)
class RankSpec:
    """Ficha de un rango: qué es, qué cuesta y qué desbloquea."""

    rank: Rank
    level: int
    label: str
    xp_required: int
    clearance: str
    unlocks: tuple[str, ...]
    color: str  # token de color del frontend (paleta cyberpunk)


# Los umbrales se sobrescriben desde el entorno en build_ladder().
DEFAULT_LADDER: tuple[RankSpec, ...] = (
    RankSpec(
        rank=Rank.NOVATO,
        level=1,
        label="Novato",
        xp_required=0,
        clearance="OBSERVADOR",
        unlocks=("feed:read", "mission:triage"),
        color="neon-green",
    ),
    RankSpec(
        rank=Rank.ANALISTA_JUNIOR,
        level=2,
        label="Analista Junior",
        xp_required=250,
        clearance="CONTRIBUYENTE",
        unlocks=("ioc:enrich", "mission:report", "sandbox:submit"),
        color="neon-cyan",
    ),
    RankSpec(
        rank=Rank.ANALISTA_SENIOR,
        level=3,
        label="Analista Senior",
        xp_required=1200,
        clearance="VERIFICADOR",
        unlocks=("ioc:verify", "campaign:correlate", "peer:review", "graph:pivot"),
        color="neon-magenta",
    ),
    RankSpec(
        rank=Rank.CAZADOR_DE_AMENAZAS,
        level=4,
        label="Cazador de Amenazas",
        xp_required=4000,
        clearance="OPERADOR",
        unlocks=(
            "misp:publish",
            "mission:author",
            "yara:deploy",
            "attribution:propose",
        ),
        color="neon-amber",
    ),
)


def build_ladder(
    xp_novato: int = 0,
    xp_junior: int = 250,
    xp_senior: int = 1200,
    xp_cazador: int = 4000,
) -> tuple[RankSpec, ...]:
    """Reconstruye la escalera con los umbrales del entorno.

    Se valida que sea estrictamente creciente: una escalera desordenada
    haría que el cálculo de rango devuelva cualquier cosa.
    """
    thresholds = (xp_novato, xp_junior, xp_senior, xp_cazador)
    if list(thresholds) != sorted(thresholds) or len(set(thresholds)) != 4:
        raise ValueError(
            f"Umbrales de XP inválidos {thresholds}: deben ser estrictamente crecientes."
        )
    return tuple(
        RankSpec(
            rank=spec.rank,
            level=spec.level,
            label=spec.label,
            xp_required=threshold,
            clearance=spec.clearance,
            unlocks=spec.unlocks,
            color=spec.color,
        )
        for spec, threshold in zip(DEFAULT_LADDER, thresholds)
    )


class XPEvent(str, Enum):
    """Acciones que mueven la aguja. El valor es el que se envía por API."""

    MISSION_TRIAGE = "mission_triage"
    IOC_ENRICHED = "ioc_enriched"
    IOC_VERIFIED = "ioc_verified"
    CORRELATION_CONFIRMED = "correlation_confirmed"
    CAMPAIGN_ATTRIBUTED = "campaign_attributed"
    YARA_RULE_ACCEPTED = "yara_rule_accepted"
    PEER_REVIEW = "peer_review"
    FIRST_BLOOD = "first_blood"  # primero en resolver una misión crítica
    #: Calificación de un veredicto. Su XP NO sale de XP_TABLE: la calcula
    #: `scoring.grade_verdict` a partir del Brier, y puede ser negativa.
    VERDICT_GRADED = "verdict_graded"
    FALSE_POSITIVE_PUBLISHED = "false_positive_published"  # penalización
    MISSION_EXPIRED = "mission_expired"  # penalización leve


#: Cuánta XP vale cada acción. Los negativos son penalizaciones deliberadas.
XP_TABLE: dict[XPEvent, int] = {
    XPEvent.MISSION_TRIAGE: 10,
    XPEvent.IOC_ENRICHED: 25,
    XPEvent.IOC_VERIFIED: 60,
    XPEvent.CORRELATION_CONFIRMED: 120,
    XPEvent.CAMPAIGN_ATTRIBUTED: 300,
    XPEvent.YARA_RULE_ACCEPTED: 200,
    XPEvent.PEER_REVIEW: 40,
    XPEvent.FIRST_BLOOD: 150,
    XPEvent.VERDICT_GRADED: 0,  # calculada aparte; ver scoring.py
    XPEvent.FALSE_POSITIVE_PUBLISHED: -75,
    XPEvent.MISSION_EXPIRED: -15,
}

#: Multiplicador según la severidad de la misión que originó el evento.
SEVERITY_MULTIPLIER: dict[str, float] = {
    "low": 1.0,
    "medium": 1.25,
    "high": 1.6,
    "critical": 2.0,
}


class ProgressionEngine:
    """Reglas de progresión. **Puro**: sin estado, sin base de datos.

    Separar las reglas de la persistencia es lo que permite testear la
    aritmética de rangos sin levantar un Postgres, y cambiar el almacenamiento
    sin tocar una sola regla del juego. La persistencia vive en
    `repository.AnalystRepository`.
    """

    def __init__(self, ladder: tuple[RankSpec, ...] | None = None) -> None:
        self._ladder = ladder or DEFAULT_LADDER

    # ── Escalera ─────────────────────────────────────────────────────
    @property
    def ladder(self) -> tuple[RankSpec, ...]:
        return self._ladder

    def spec_for(self, rank: Rank) -> RankSpec:
        return next(s for s in self._ladder if s.rank is rank)

    def rank_for_xp(self, xp: int) -> RankSpec:
        """Devuelve el rango más alto cuyo umbral fue alcanzado."""
        earned = self._ladder[0]
        for spec in self._ladder:
            if xp >= spec.xp_required:
                earned = spec
            else:
                break
        return earned

    def next_rank(self, current: Rank) -> RankSpec | None:
        """Siguiente escalón, o None si ya está en la cima."""
        idx = next(i for i, s in enumerate(self._ladder) if s.rank is current)
        return self._ladder[idx + 1] if idx + 1 < len(self._ladder) else None

    def progress_to_next(self, xp: int) -> float:
        """Progreso [0.0, 1.0] hacia el próximo rango. 1.0 si está en la cima."""
        current = self.rank_for_xp(xp)
        nxt = self.next_rank(current.rank)
        if nxt is None:
            return 1.0
        span = nxt.xp_required - current.xp_required
        if span <= 0:  # defensivo: build_ladder ya lo impide
            return 1.0
        return max(0.0, min(1.0, (xp - current.xp_required) / span))

    # ── Aritmética de XP ─────────────────────────────────────────────
    @staticmethod
    def compute_delta(
        event: XPEvent, severity: str = "medium", multiplier: float = 1.0
    ) -> int:
        """XP nominal de un evento, antes de aplicar el piso en cero.

        Las penalizaciones NO se amplifican por severidad ni por bonus:
        castigar el doble por equivocarse en algo difícil desincentiva
        justamente lo que se quiere fomentar, que es meterse con lo difícil.
        """
        base = XP_TABLE[event]
        if base < 0:
            return base
        sev_mult = SEVERITY_MULTIPLIER.get(severity.lower(), 1.0)
        return round(base * sev_mult * multiplier)

    @staticmethod
    def flavor(promoted: bool, spec: RankSpec, delta: int) -> str:
        """Texto que ve el analista en la consola. La inmersión también es UX."""
        if promoted:
            return (
                f">> ASCENSO CONFIRMADO :: {spec.label.upper()} :: "
                f"clearance {spec.clearance} otorgado"
            )
        if delta < 0:
            return ">> INTELIGENCIA REFUTADA :: -XP aplicada :: revisá tu metodología"
        if delta == 0:
            return ">> MISIÓN YA ACREDITADA :: sin XP adicional"
        return f">> +{delta} XP :: registrado en la torre"
