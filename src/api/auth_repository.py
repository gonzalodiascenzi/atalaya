"""
ATALAYA // Persistencia de identidad y sesiones.

Separado de `repository.py` a propósito: las credenciales son un dominio con
reglas propias (bloqueos, rotación, detección de reutilización) y mezclarlas
con la progresión hace que ninguna de las dos se lea bien.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from auth import (
    LOCKOUT_WINDOW,
    MAX_LOGIN_ATTEMPTS,
    AuthError,
    Role,
    hash_password,
    hash_refresh_token,
    issue_refresh_token,
    needs_rehash,
    validate_password,
    verify_password,
)
from models import Analyst, RefreshToken


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AuthRepository:
    """Alta, autenticación y ciclo de vida de las sesiones."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # ══════════════════════════════════════════════════════════════════
    #  Alta
    # ══════════════════════════════════════════════════════════════════

    async def register(
        self,
        callsign: str,
        password: str,
        email: str | None = None,
        role: Role = Role.ANALYST,
    ) -> Analyst:
        """Registra un analista con contraseña local."""
        validate_password(password, callsign)

        existente = await self._session.scalar(
            select(Analyst).where(Analyst.callsign == callsign)
        )
        if existente is not None:
            # Que el callsign esté tomado es información pública —aparece en
            # el leaderboard— así que decirlo no filtra nada.
            if existente.password_hash is not None:
                raise AuthError(f"El callsign '{callsign}' ya está tomado.")
            # El analista existía sin credenciales (lo creó el motor de
            # progresión antes de que hubiera autenticación). Se le fijan.
            existente.password_hash = hash_password(password)
            existente.email = email
            await self._session.flush()
            return existente

        analyst = Analyst(
            callsign=callsign,
            password_hash=hash_password(password),
            email=email,
            role=role.value,
        )
        self._session.add(analyst)
        try:
            await self._session.flush()
        except IntegrityError:
            raise AuthError("Ese callsign o ese correo ya están registrados.")
        return analyst

    # ══════════════════════════════════════════════════════════════════
    #  Autenticación
    # ══════════════════════════════════════════════════════════════════

    async def authenticate(self, callsign: str, password: str) -> Analyst:
        """Valida credenciales. Cualquier fallo devuelve el mismo mensaje.

        No se distingue "no existe" de "contraseña incorrecta": esa diferencia
        es un oráculo para enumerar cuentas.
        """
        analyst = await self._session.scalar(
            select(Analyst).where(Analyst.callsign == callsign)
        )

        ahora = utcnow()
        if analyst is not None and analyst.locked_until is not None:
            if analyst.locked_until > ahora:
                restante = int((analyst.locked_until - ahora).total_seconds() / 60) + 1
                raise AuthError(
                    f"Cuenta bloqueada por intentos fallidos. Reintentá en "
                    f"{restante} minuto(s)."
                )
            # El bloqueo venció: se limpia y se le da otra oportunidad.
            analyst.locked_until = None
            analyst.failed_login_attempts = 0

        # Se verifica SIEMPRE, exista o no la cuenta, para que el tiempo de
        # respuesta no revele qué callsigns están registrados.
        ok = verify_password(password, analyst.password_hash if analyst else None)

        if not ok:
            if analyst is not None:
                analyst.failed_login_attempts += 1
                if analyst.failed_login_attempts >= MAX_LOGIN_ATTEMPTS:
                    analyst.locked_until = ahora + LOCKOUT_WINDOW
                # Se CONFIRMA acá y no al final de la petición. La petición va
                # a terminar en 401, y el rollback de la sesión se llevaría
                # puesto el contador — dejando el bloqueo por fuerza bruta sin
                # ningún efecto. Un flush() no alcanza: no sobrevive al
                # rollback.
                await self._session.commit()
            raise AuthError("Callsign o contraseña incorrectos.")

        if not analyst.is_active:
            raise AuthError("Esta cuenta está desactivada.")

        # Login exitoso: se limpia el contador y se migra el hash si los
        # parámetros de Argon2 se endurecieron desde la última vez.
        analyst.failed_login_attempts = 0
        analyst.locked_until = None
        analyst.last_login_at = ahora
        if analyst.password_hash and needs_rehash(analyst.password_hash):
            analyst.password_hash = hash_password(password)
        await self._session.flush()
        return analyst

    async def get_by_id(self, analyst_id: uuid.UUID) -> Analyst | None:
        return await self._session.get(Analyst, analyst_id)

    # ══════════════════════════════════════════════════════════════════
    #  Sesiones
    # ══════════════════════════════════════════════════════════════════

    async def create_refresh_token(self, analyst: Analyst) -> tuple[str, datetime]:
        """Emite un refresh token nuevo. Devuelve el valor en claro una vez."""
        raw, hashed, expires = issue_refresh_token()
        self._session.add(
            RefreshToken(analyst_id=analyst.id, token_hash=hashed, expires_at=expires)
        )
        await self._session.flush()
        return raw, expires

    async def rotate_refresh_token(self, raw: str) -> tuple[Analyst, str, datetime]:
        """Canjea un refresh token por uno nuevo, con detección de reutilización.

        Si llega un token ya rotado o revocado, se asume compromiso: se revoca
        **toda la familia** del analista. Es la recomendación del BCP de OAuth
        2.0, y el razonamiento es simple — obligar a alguien a volver a entrar
        molesta; dejar viva una sesión robada, no se arregla después.
        """
        hashed = hash_refresh_token(raw)
        token = await self._session.scalar(
            select(RefreshToken).where(RefreshToken.token_hash == hashed)
        )

        if token is None:
            raise AuthError("Refresh token inválido.")

        if token.revoked_at is not None:
            await self.revoke_all(token.analyst_id)
            # Mismo motivo que en `authenticate`: sin este commit, la
            # revocación se pierde en el rollback y habríamos detectado el
            # token robado para después dejarlo vivo.
            await self._session.commit()
            raise AuthError(
                "Este token de sesión ya había sido usado. Por seguridad se "
                "cerraron todas tus sesiones: volvé a entrar."
            )

        if token.expires_at <= utcnow():
            raise AuthError("La sesión venció. Volvé a entrar.")

        analyst = await self._session.get(Analyst, token.analyst_id)
        if analyst is None or not analyst.is_active:
            raise AuthError("Cuenta inexistente o desactivada.")

        raw_nuevo, hash_nuevo, expires = issue_refresh_token()
        nuevo = RefreshToken(
            analyst_id=analyst.id, token_hash=hash_nuevo, expires_at=expires
        )
        self._session.add(nuevo)
        await self._session.flush()

        token.revoked_at = utcnow()
        token.replaced_by = nuevo.id
        await self._session.flush()

        return analyst, raw_nuevo, expires

    async def revoke(self, raw: str) -> bool:
        """Cierra una sesión puntual. Idempotente."""
        token = await self._session.scalar(
            select(RefreshToken).where(
                RefreshToken.token_hash == hash_refresh_token(raw)
            )
        )
        if token is None or token.revoked_at is not None:
            return False
        token.revoked_at = utcnow()
        await self._session.flush()
        return True

    async def revoke_all(self, analyst_id: uuid.UUID) -> int:
        """Cierra todas las sesiones vigentes de un analista."""
        result = await self._session.execute(
            update(RefreshToken)
            .where(RefreshToken.analyst_id == analyst_id)
            .where(RefreshToken.revoked_at.is_(None))
            .values(revoked_at=utcnow())
        )
        await self._session.flush()
        return int(result.rowcount or 0)

    async def active_sessions(self, analyst_id: uuid.UUID) -> list[dict[str, Any]]:
        filas = (
            await self._session.scalars(
                select(RefreshToken)
                .where(RefreshToken.analyst_id == analyst_id)
                .where(RefreshToken.revoked_at.is_(None))
                .where(RefreshToken.expires_at > utcnow())
                .order_by(RefreshToken.issued_at.desc())
            )
        ).all()
        return [
            {
                "issued_at": t.issued_at.isoformat(),
                "expires_at": t.expires_at.isoformat(),
            }
            for t in filas
        ]
