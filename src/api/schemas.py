"""
ATALAYA // Contratos de la API (Pydantic v2).

Estos modelos son el contrato con el frontend. Si cambian acá, cambian en
`src/frontend/lib/types.ts`. Mantenerlos sincronizados no es opcional.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

Severity = Literal["low", "medium", "high", "critical"]


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"] = "ok"
    service: str = "atalaya-api"
    version: str
    environment: str
    stix_spec: str = "2.1"
    uptime_seconds: float


class MissionSummary(BaseModel):
    """Una misión tal como la consume el feed del frontend."""

    mission_id: str
    title: str
    briefing: str
    severity: Severity
    difficulty: int = Field(ge=1, le=5)
    xp_reward: int
    required_rank: str
    source: str
    tlp: str
    attack_technique: str
    attack_tactic: str
    malware_family: str
    ioc_defanged: str
    ioc_pattern: str
    objectives: list[str]
    detected_at: str
    expires_in_minutes: int
    status: str
    object_refs: list[str]
    locked: bool = Field(
        default=False,
        description="True si el rango del analista no alcanza para operarla.",
    )


class FeedResponse(BaseModel):
    """Página del feed de misiones + el bundle STIX que la respalda."""

    missions: list[MissionSummary]
    bundle: dict[str, Any] = Field(
        description="STIX 2.1 Bundle con todos los objetos de esta página."
    )
    next_cursor: str | None = Field(
        default=None, description="Cursor opaco para la siguiente página."
    )
    has_more: bool
    total: int
    generated_at: str
    viewer_rank: str


class RankInfo(BaseModel):
    rank: str
    level: int
    label: str
    xp_required: int
    clearance: str
    unlocks: list[str]
    color: str


class LevelUpRequest(BaseModel):
    """Evento de progresión enviado por el frontend.

    ⚠️ NO lleva `callsign`, y esa ausencia es la corrección de seguridad más
    importante del proyecto. Mientras el analista venía en el cuerpo,
    cualquiera podía otorgarle —o quitarle— XP a cualquiera con un `curl`.
    Ahora la identidad sale del token y sólo del token.
    """

    event: str = Field(
        examples=["ioc_verified"],
        description="Acción realizada. Ver GET /api/v1/xp-table.",
    )
    mission_id: str | None = Field(default=None, examples=["MSN-1A2B3C4D"])
    severity: Severity = "medium"
    multiplier: float = Field(
        default=1.0, ge=1.0, le=3.0, description="Bonus de evento (ej: CTF x2)."
    )


class LevelUpResponse(BaseModel):
    callsign: str
    event: str
    xp_delta: int
    xp_total: int
    rank: str
    rank_label: str
    level: int
    clearance: str
    promoted: bool
    previous_rank: str
    unlocked: list[str]
    next_rank: str | None
    xp_to_next: int
    progress: float = Field(ge=0.0, le=1.0)
    streak: int
    already_awarded: bool = Field(
        default=False,
        description=(
            "True si esa misión ya había acreditado ese evento para este "
            "analista. La XP otorgada es 0: es la defensa anti-farmeo."
        ),
    )
    message: str


class AnalystState(BaseModel):
    """Estado completo del analista: alimenta el panel lateral."""

    callsign: str
    xp: int
    rank: str
    rank_label: str
    level: int
    clearance: str
    unlocks: list[str]
    next_rank: str | None
    xp_to_next: int
    progress: float
    missions_completed: int
    iocs_verified: int
    streak: int
    joined_at: str
    last_event_at: str | None
    recent_events: list[dict[str, Any]]


class LeaderboardEntry(BaseModel):
    position: int
    callsign: str
    xp: int
    rank: str
    iocs_verified: int


class ErrorResponse(BaseModel):
    error: str
    detail: str
    trace_id: str | None = None


# ══════════════════════════════════════════════════════════════════════
#  Bucle de verificación (docs/VERIFICACION.md)
# ══════════════════════════════════════════════════════════════════════

CallLiteral = Literal["MALICIOUS", "BENIGN", "INCONCLUSIVE"]


class VerdictRequest(BaseModel):
    """La apuesta del analista. Se emite una vez y no se edita.

    Sin `callsign`: la identidad sale del token. Ver LevelUpRequest.
    """

    call: CallLiteral = Field(
        description="Tu llamada. INCONCLUSIVE no puntúa ni penaliza."
    )
    confidence: int = Field(
        ge=50,
        le=100,
        examples=[75],
        description=(
            "Cuánta certeza tenés EN TU LLAMADA, de 50 a 100. Por debajo de 50 "
            "el veredicto se contradice: 'malicioso con 30%' es, en realidad, "
            "'benigno con 70%'. Declarar 50 paga exactamente 0 XP: cubrirse "
            "no es una estrategia."
        ),
    )
    rationale: str | None = Field(
        default=None,
        max_length=2000,
        description="Obligatorio si confidence >= 80.",
    )


class VerdictResponse(BaseModel):
    mission_id: str
    call: CallLiteral
    confidence: int
    submitted_at: str
    graded: bool
    brier_score: float | None = None
    xp_awarded: int = 0
    was_correct: bool | None = None
    ground_truth: str | None = None
    truth_source: str | None = None
    message: str


class ResolveRequest(BaseModel):
    """Fija la verdad de una misión. Lo usa el trabajo de corroboración."""

    ground_truth: Literal["MALICIOUS", "BENIGN"]
    truth_source: Literal["KEV", "MULTI_SOURCE", "CORROBORATION", "CURATED", "PEER"]


class CalibrationResponse(BaseModel):
    """Cuánto vale la palabra del analista."""

    callsign: str
    verdicts_graded: int
    verdicts_pending: int
    calibration: float | None = Field(
        default=None, description="1 - brier medio. Arriba de 0.75 es bueno."
    )
    mean_brier: float | None = None
    accuracy: float | None = None
    mean_confidence: float | None = None
    overconfidence: float | None = Field(
        default=None,
        description=(
            "Confianza media menos tasa de acierto. Positivo = cree saber más "
            "de lo que sabe."
        ),
    )


# ══════════════════════════════════════════════════════════════════════
#  Identidad
# ══════════════════════════════════════════════════════════════════════


def _sanitize_callsign(v: str) -> str:
    """Un callsign es un identificador, no texto libre.

    Se normaliza y se restringe el alfabeto: termina renderizado en el
    frontend y persistido, así que no queremos payloads raros dando vueltas.
    """
    cleaned = "".join(c for c in v.strip().lower() if c.isalnum() or c in "-_.")
    if len(cleaned) < 2:
        raise ValueError(
            "callsign inválido: usá 2-32 caracteres alfanuméricos, '-', '_' o '.'"
        )
    return cleaned


class RegisterRequest(BaseModel):
    callsign: str = Field(min_length=2, max_length=32, examples=["gon"])
    password: str = Field(
        min_length=12,
        max_length=256,
        description=(
            "Mínimo 12 caracteres. Una frase larga rinde más que un revoltijo "
            "corto, y se recuerda sin anotarla en un post-it."
        ),
    )
    email: str | None = Field(default=None, max_length=254)

    @field_validator("callsign")
    @classmethod
    def _cs(cls, v: str) -> str:
        return _sanitize_callsign(v)


class LoginRequest(BaseModel):
    callsign: str = Field(min_length=2, max_length=32)
    password: str = Field(min_length=1, max_length=256)

    @field_validator("callsign")
    @classmethod
    def _cs(cls, v: str) -> str:
        return _sanitize_callsign(v)


class TokenResponse(BaseModel):
    """El access token viaja además en cookie httpOnly.

    Se devuelve también en el cuerpo para clientes que no son navegador
    (curl, scripts, el conector de ingesta). El navegador debería ignorarlo y
    quedarse con la cookie: un token en JavaScript es un token que un XSS
    puede leer.
    """

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    callsign: str
    role: str


class MeResponse(BaseModel):
    callsign: str
    role: str
    email: str | None = None
    joined_at: str
    last_login_at: str | None = None
    active_sessions: int
