"""
ATALAYA // Identidad y credenciales.

Módulo **puro**: hashea, firma y verifica. No toca la base ni HTTP, así que se
puede testear la criptografía sin levantar nada.

Diseño de tokens — dos piezas con trabajos distintos:

    access   JWT firmado (HS256), 15 minutos, sin estado.
             Rápido de validar, imposible de revocar. Por eso dura poco.

    refresh  Cadena opaca aleatoria, 30 días, guardada HASHEADA en la base.
             Revocable, rotatoria y auditable. Por eso dura mucho.

Un refresh en JWT sería cómodo y equivocado: no se podría cerrar sesión de
verdad, ni cortarle el acceso a un token robado antes de su vencimiento.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

ALGORITHM = "HS256"
ACCESS_TTL = timedelta(minutes=15)
REFRESH_TTL = timedelta(days=30)

#: Longitud mínima de contraseña. Doce caracteres sin reglas de composición
#: rinde más que ocho con "una mayúscula y un símbolo": las reglas empujan a
#: la gente a Password1! y a variaciones predecibles.
MIN_PASSWORD_LENGTH = 12

#: Umbral de intentos fallidos antes de bloquear temporalmente.
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_WINDOW = timedelta(minutes=15)

#: Argon2id con los parámetros por defecto de argon2-cffi, alineados con la
#: RFC 9106. No se usa bcrypt: trunca en 72 bytes de forma silenciosa.
_hasher = PasswordHasher()

#: Hash señuelo. Verificar contra esto cuando el analista no existe hace que
#: el login tarde lo mismo exista o no la cuenta. Sin esto, el tiempo de
#: respuesta revela qué callsigns están registrados.
_DUMMY_HASH = _hasher.hash("callsign-inexistente-relleno-antitiming")


class Role(str, Enum):
    """Qué puede hacer cada quien."""

    ANALYST = "ANALYST"
    #: Puede fijar la verdad de referencia de una misión. Es un permiso
    #: delicado: quien fija la verdad, decide quién gana XP.
    INSTRUCTOR = "INSTRUCTOR"
    ADMIN = "ADMIN"


@dataclass(frozen=True)
class TokenClaims:
    """Contenido verificado de un access token."""

    analyst_id: uuid.UUID
    callsign: str
    role: Role
    expires_at: datetime


class AuthError(Exception):
    """Credenciales, token o permisos inválidos."""


# ══════════════════════════════════════════════════════════════════════
#  Contraseñas
# ══════════════════════════════════════════════════════════════════════


def validate_password(password: str, callsign: str) -> None:
    """Reglas mínimas. Lanza AuthError con un motivo accionable."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise AuthError(
            f"La contraseña necesita al menos {MIN_PASSWORD_LENGTH} caracteres. "
            "Una frase larga es más fuerte y más fácil de recordar que un "
            "revoltijo corto."
        )
    if callsign.lower() in password.lower():
        raise AuthError("La contraseña no puede contener tu callsign.")
    if password.lower() in {
        "contrasena123",
        "atalaya12345",
        "password1234",
        "123456789012",
        "qwertyuiop12",
    }:
        raise AuthError("Esa contraseña está en las listas públicas de filtraciones.")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, stored_hash: str | None) -> bool:
    """Verifica en tiempo constante respecto de la existencia de la cuenta.

    Si `stored_hash` es None (el analista no existe o nunca fijó contraseña),
    igual se hace una verificación contra el señuelo. Devuelve False, pero
    tarda lo mismo — que es el punto.
    """
    try:
        _hasher.verify(stored_hash or _DUMMY_HASH, password)
        return stored_hash is not None
    except (VerifyMismatchError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """True si el hash quedó viejo respecto de los parámetros actuales.

    Permite endurecer Argon2 con el tiempo y migrar a cada login, sin pedirle
    a nadie que cambie la contraseña.
    """
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return True


# ══════════════════════════════════════════════════════════════════════
#  Access token (JWT)
# ══════════════════════════════════════════════════════════════════════


def issue_access_token(
    secret: str, analyst_id: uuid.UUID, callsign: str, role: Role
) -> tuple[str, datetime]:
    """Firma un access token de vida corta."""
    now = datetime.now(timezone.utc)
    expires = now + ACCESS_TTL
    payload = {
        "sub": str(analyst_id),
        "callsign": callsign,
        "role": role.value,
        "iat": int(now.timestamp()),
        "exp": int(expires.timestamp()),
        "jti": secrets.token_urlsafe(12),
        "typ": "access",
        "iss": "atalaya",
    }
    return jwt.encode(payload, secret, algorithm=ALGORITHM), expires


def decode_access_token(secret: str, token: str) -> TokenClaims:
    """Valida firma, vencimiento y tipo. Cualquier fallo es AuthError."""
    try:
        payload = jwt.decode(
            token,
            secret,
            algorithms=[ALGORITHM],
            issuer="atalaya",
            options={"require": ["exp", "iat", "sub", "iss"]},
        )
    except jwt.ExpiredSignatureError:
        raise AuthError("El token venció. Renovalo con /api/v1/auth/refresh.")
    except jwt.InvalidTokenError as exc:
        raise AuthError(f"Token inválido: {exc}")

    # Un refresh token no sirve como access token, aunque estuviera firmado.
    if payload.get("typ") != "access":
        raise AuthError("Tipo de token incorrecto.")

    try:
        return TokenClaims(
            analyst_id=uuid.UUID(payload["sub"]),
            callsign=payload["callsign"],
            role=Role(payload["role"]),
            expires_at=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
        )
    except (KeyError, ValueError) as exc:
        raise AuthError(f"Contenido de token malformado: {exc}")


# ══════════════════════════════════════════════════════════════════════
#  Refresh token (opaco)
# ══════════════════════════════════════════════════════════════════════


def issue_refresh_token() -> tuple[str, str, datetime]:
    """Genera un refresh token.

    Devuelve (token_claro, hash_para_guardar, vencimiento). El claro se le da
    al cliente una sola vez; la base guarda **sólo el hash**, igual que con
    una contraseña. Si alguien se lleva un volcado de la tabla, no se lleva
    sesiones utilizables.

    Se usa SHA-256 y no Argon2 a propósito: el token ya tiene 256 bits de
    entropía real, así que no hay nada que un ataque de diccionario pueda
    hacer, y el refresh se verifica en cada renovación — tiene que ser barato.
    """
    raw = secrets.token_urlsafe(32)
    return raw, hash_refresh_token(raw), datetime.now(timezone.utc) + REFRESH_TTL


def hash_refresh_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()
