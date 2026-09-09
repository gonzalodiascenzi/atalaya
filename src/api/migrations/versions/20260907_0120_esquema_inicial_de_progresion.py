"""Esquema inicial de la progresión del analista.

Dos tablas y una decisión:

  analysts   - identidad y nada más.
  xp_events  - append-only. La XP del analista ES la suma de esta tabla;
               no existe un contador mutable que pueda discrepar.

El índice `uq_xp_events_una_vez_por_mision` es PARCIAL (sólo cuando hay
mission_id) y es la defensa anti-farmeo: impide cobrar el mismo evento dos
veces sobre la misma misión, sin bloquear los eventos genéricos.

Revision ID: 14d08e68b918
Revises: (ninguna - es la primera)
Create Date: 2026-09-07 01:20:03.760242
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "14d08e68b918"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "analysts",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("callsign", sa.String(length=32), nullable=False),
        sa.Column(
            "joined_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("length(callsign) >= 2", name="ck_callsign_min_len"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_analysts_callsign"), "analysts", ["callsign"], unique=True)
    op.create_table(
        "xp_events",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("analyst_id", sa.UUID(), nullable=False),
        sa.Column("event", sa.String(length=48), nullable=False),
        sa.Column("mission_id", sa.String(length=32), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("xp_delta_nominal", sa.Integer(), nullable=False),
        sa.Column("xp_delta_applied", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["analyst_id"], ["analysts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_xp_events_analyst_recent",
        "xp_events",
        ["analyst_id", sa.text("id DESC")],
        unique=False,
    )
    op.create_index(
        op.f("ix_xp_events_created_at"), "xp_events", ["created_at"], unique=False
    )
    op.create_index(
        "uq_xp_events_una_vez_por_mision",
        "xp_events",
        ["analyst_id", "mission_id", "event"],
        unique=True,
        postgresql_where=sa.text("mission_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_xp_events_una_vez_por_mision",
        table_name="xp_events",
        postgresql_where=sa.text("mission_id IS NOT NULL"),
    )
    op.drop_index(op.f("ix_xp_events_created_at"), table_name="xp_events")
    op.drop_index("ix_xp_events_analyst_recent", table_name="xp_events")
    op.drop_table("xp_events")
    op.drop_index(op.f("ix_analysts_callsign"), table_name="analysts")
    op.drop_table("analysts")
