"""
ATALAYA // Modelo de datos de la progresión.

Decisión central: **la XP no se guarda como un contador mutable**.

Un campo `analysts.xp` que se actualiza a mano es una segunda fuente de verdad,
y toda segunda fuente de verdad termina desincronizada. Acá la XP es la suma de
los eventos: `xp_events` es un registro append-only que además es la auditoría
completa de cómo cada analista llegó a su rango.

El detalle que hace que esto funcione: cada evento guarda DOS deltas.

    xp_delta_nominal  -> lo que dice la tabla de XP (ej: -75)
    xp_delta_applied  -> lo que realmente movió el saldo (ej: -30, si sólo
                         tenía 30 puntos y la XP tiene piso en cero)

Sin esa distinción, `SUM(delta)` no coincide con aplicar los eventos en orden
con el piso en cero, y la suma daría un número negativo imposible. Con ella,
`SUM(xp_delta_applied)` es exacta siempre, y el nominal queda como evidencia de
qué se intentó cobrar.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Identity,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base declarativa. Alembic descubre las tablas desde acá."""


class Analyst(Base):
    """El analista. Identidad y nada más: su estado se deriva de los eventos."""

    __tablename__ = "analysts"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    callsign: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    joined_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # ── Credenciales ─────────────────────────────────────────────────
    # `password_hash` admite NULL: un analista creado por un proveedor OIDC
    # no tiene contraseña local, y forzar una sería inventarle un secreto.
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # El nombre del constraint es explícito a propósito: `unique=True` genera
    # uno anónimo, y un constraint sin nombre no se puede soltar en el
    # downgrade. Una migración irreversible es una migración sin retirada.
    email: Mapped[str | None] = mapped_column(String(254), nullable=True)
    # `server_default` además de `default`: el primero vive en el esquema y es
    # lo que permite agregar estas columnas NOT NULL sobre una tabla que ya
    # tiene filas. Declararlo acá mantiene modelo y base diciendo lo mismo —
    # si no, cada autogenerate propone borrarlos.
    role: Mapped[str] = mapped_column(
        String(16), nullable=False, default="ANALYST", server_default="ANALYST"
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ── Defensa contra fuerza bruta ──────────────────────────────────
    # Vive en la base y no en memoria del proceso: con N réplicas, un contador
    # por proceso significa N veces los intentos permitidos, y un reinicio
    # borra el bloqueo justo cuando más hace falta.
    failed_login_attempts: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    events: Mapped[list[XPEvent]] = relationship(
        back_populates="analyst",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (
        CheckConstraint("length(callsign) >= 2", name="ck_callsign_min_len"),
        CheckConstraint(
            "role IN ('ANALYST','INSTRUCTOR','ADMIN')", name="ck_role_valido"
        ),
        UniqueConstraint("email", name="uq_analysts_email"),
    )


class XPEvent(Base):
    """Un hecho ocurrido. Append-only: nunca se actualiza ni se borra."""

    __tablename__ = "xp_events"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    analyst_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("analysts.id", ondelete="CASCADE"),
        nullable=False,
    )
    event: Mapped[str] = mapped_column(String(48), nullable=False)
    mission_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")

    xp_delta_nominal: Mapped[int] = mapped_column(Integer, nullable=False)
    xp_delta_applied: Mapped[int] = mapped_column(Integer, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )

    analyst: Mapped[Analyst] = relationship(back_populates="events")

    __table_args__ = (
        # Lectura del historial de un analista, del más nuevo al más viejo.
        Index("ix_xp_events_analyst_recent", "analyst_id", text("id DESC")),
        # ── Anti-farmeo ──────────────────────────────────────────────
        # Sin esto, un analista clickea "Triar" cien veces sobre la misma
        # misión y llega a Cazador de Amenazas sin haber analizado nada.
        # El índice es PARCIAL: sólo aplica cuando hay misión asociada, así
        # que los eventos genéricos (sin mission_id) siguen siendo repetibles.
        Index(
            "uq_xp_events_una_vez_por_mision",
            "analyst_id",
            "mission_id",
            "event",
            unique=True,
            postgresql_where=text("mission_id IS NOT NULL"),
        ),
    )


class MissionRecord(Base):
    """La misión, con las señales que permiten calificarla.

    Hasta ahora las misiones vivían sólo en el catálogo en memoria. Se
    persisten porque el bucle de verificación necesita algo estable contra
    lo cual comparar un veredicto emitido hace tres días.

    Los campos de verdad son el contrato que todo conector de ingesta tiene
    que poder alimentar (ver docs/VERIFICACION.md §6). Un conector que sólo
    devuelva "IP maliciosa" no sirve para calificar nada.
    """

    __tablename__ = "missions"

    mission_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    #: Huella del observable que originó la misión. Permite reconciliar por
    #: indicador aunque el ID de misión cambie de esquema en el futuro.
    fingerprint: Mapped[str | None] = mapped_column(
        String(512), nullable=True, index=True
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    base_xp: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    required_rank: Mapped[str] = mapped_column(String(32), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)

    # ── Verdad de referencia ─────────────────────────────────────────
    ground_truth: Mapped[str] = mapped_column(
        String(16), nullable=False, default="UNKNOWN", index=True
    )
    truth_source: Mapped[str | None] = mapped_column(String(24), nullable=True)
    source_confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    independent_sources: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    kev_listed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    first_reported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    #: Momento a partir del cual la corroboración diferida puede resolverse.
    resolves_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: Momento en que la verdad quedó fijada. Todo veredicto posterior a esta
    #: marca NO puntúa: es la defensa contra esperar a que la verdad sea pública.
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ── Contenido de la misión ───────────────────────────────────────
    # Todo lo que el feed muestra: briefing, objetivos, observable
    # neutralizado, bundle STIX. Va en JSONB y no en veinte columnas porque
    # es contenido, no estado: nadie filtra por "objetivos", y cada conector
    # nuevo puede aportar campos sin una migración.
    #
    # Antes esto no existía, y el feed servía SIEMPRE las ocho misiones del
    # catálogo en memoria: todo lo que ingerían los conectores reales era
    # invisible para los analistas.
    payload: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    verdicts: Mapped[list["Verdict"]] = relationship(
        back_populates="mission", cascade="all, delete-orphan", passive_deletes=True
    )

    __table_args__ = (
        CheckConstraint(
            "ground_truth IN ('MALICIOUS','BENIGN','UNKNOWN')",
            name="ck_ground_truth_valido",
        ),
        # El feed ordena por esto en cada página.
        Index("ix_missions_recientes", text("first_reported_at DESC"), "mission_id"),
    )


class Verdict(Base):
    """La apuesta del analista. Append-only: se emite una vez y no se edita.

    Permitir editar después de conocer el resultado no es análisis: es
    reescribir la historia. Por eso el índice único es por (analista, misión)
    y no hay ningún camino de UPDATE sobre `call` ni `confidence`.
    """

    __tablename__ = "verdicts"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    analyst_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("analysts.id", ondelete="CASCADE"),
        nullable=False,
    )
    mission_id: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("missions.mission_id", ondelete="CASCADE"),
        nullable=False,
    )

    call: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False)
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    submitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # ── Calificación (nula hasta que la verdad se resuelve) ──────────
    graded_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    brier_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    xp_awarded: Mapped[int | None] = mapped_column(Integer, nullable=True)
    was_correct: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    analyst: Mapped[Analyst] = relationship()
    mission: Mapped[MissionRecord] = relationship(back_populates="verdicts")

    __table_args__ = (
        # Un veredicto por analista y por misión. Es la regla anti-reescritura.
        UniqueConstraint("analyst_id", "mission_id", name="uq_un_veredicto_por_mision"),
        CheckConstraint("confidence BETWEEN 50 AND 100", name="ck_confianza_en_rango"),
        CheckConstraint(
            "call IN ('MALICIOUS','BENIGN','INCONCLUSIVE')", name="ck_call_valido"
        ),
        Index(
            "ix_verdicts_sin_calificar",
            "mission_id",
            postgresql_where=text("graded_at IS NULL"),
        ),
    )


class RefreshToken(Base):
    """Sesión de larga duración, revocable.

    Se guarda **sólo el hash** del token, igual que con una contraseña: un
    volcado de esta tabla no entrega sesiones utilizables.

    `replaced_by` encadena las rotaciones. Esa cadena es lo que permite
    detectar reutilización: si aparece un token ya rotado, o alguien clonó la
    sesión o el cliente reintentó mal. Ante la duda se revoca la familia
    entera — es preferible pedirle a la persona que vuelva a entrar antes que
    dejar viva una sesión posiblemente robada.
    """

    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    analyst_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("analysts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    token_hash: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    replaced_by: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), nullable=True
    )

    analyst: Mapped[Analyst] = relationship()

    __table_args__ = (
        Index(
            "ix_refresh_vigentes",
            "analyst_id",
            postgresql_where=text("revoked_at IS NULL"),
        ),
    )


class IndicatorSighting(Base):
    """Qué fuente vio qué indicador, y cuándo.

    Es la tabla que hace real la corroboración diferida. Antes,
    `independent_sources` era un número que alguien escribía a mano; acá se
    **cuenta**: una fila por (misión, fuente), y la independencia es el
    número de FAMILIAS distintas — no de fuentes.

    La distinción importa: ThreatFox, URLhaus y MalwareBazaar son tres APIs
    del mismo operador. Contarlas como tres corroboraciones independientes
    haría que un indicador cruce el umbral solo, y el sistema declararía
    verdades que ninguna segunda parte verificó.
    """

    __tablename__ = "indicator_sightings"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    mission_id: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("missions.mission_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    fingerprint: Mapped[str] = mapped_column(String(512), nullable=False, index=True)

    source_name: Mapped[str] = mapped_column(String(64), nullable=False)
    #: La unidad de independencia. Se guarda desnormalizada a propósito: es
    #: lo que se agrupa en cada consulta y no queremos un join para contarlo.
    source_family: Mapped[str] = mapped_column(String(32), nullable=False)
    source_reference: Mapped[str | None] = mapped_column(String(512), nullable=True)
    source_confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=50)

    first_reported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    sample_available: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    kev_listed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    mission: Mapped[MissionRecord] = relationship()

    __table_args__ = (
        # Una fila por fuente y misión: reingerir el mismo IoC actualiza, no
        # acumula. Sin esto, un conector corriendo cada quince minutos
        # inflaría el conteo de corroboración con sus propias repeticiones.
        UniqueConstraint("mission_id", "source_name", name="uq_sighting_por_fuente"),
    )
