"""
ATALAYA // API de la torre.

FastAPI que expone el Feed de Misiones (STIX 2.1) y el motor de progresión
del analista.

Levantar en desarrollo:
    cd src/api && uvicorn main:app --reload --port 8000

Documentación viva:
    http://localhost:8000/docs
"""

from __future__ import annotations

import logging
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import (
    Cookie,
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
    Request,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from auth import (
    ACCESS_TTL,
    REFRESH_TTL,
    AuthError,
    Role,
    WeakPasswordError,
    decode_access_token,
    issue_access_token,
)
from auth_repository import AuthRepository
from config import get_settings
from db import dispose_engine, get_session, get_session_factory
from models import Analyst
from gamification import (
    XP_TABLE,
    ProgressionEngine,
    Rank,
    XPEvent,
    build_ladder,
)
from repository import AnalystRepository, FeedRepository, VerdictRepository
from scoring import Call, GroundTruth, TruthSource
from schemas import (
    AnalystState,
    CalibrationResponse,
    ErrorResponse,
    FeedResponse,
    HealthResponse,
    LeaderboardEntry,
    LevelUpRequest,
    LevelUpResponse,
    LoginRequest,
    MeResponse,
    MissionSummary,
    RankInfo,
    RegisterRequest,
    ResolveRequest,
    TokenResponse,
    VerdictRequest,
    VerdictResponse,
)
from stix_feed import as_bundle, decode_cursor, encode_cursor, full_catalog, now_iso

__version__ = "0.1.0"

settings = get_settings()
logging.basicConfig(
    level=getattr(logging, settings.api_log_level.upper(), logging.INFO),
    format="%(asctime)s | %(levelname)-8s | atalaya.api | %(message)s",
)
log = logging.getLogger("atalaya.api")

#: Motor de reglas. Es puro y sin estado, así que un único ejemplar por
#: proceso alcanza y sobra. El estado vive en PostgreSQL.
engine = ProgressionEngine(
    ladder=build_ladder(
        settings.xp_novato,
        settings.xp_analista_junior,
        settings.xp_analista_senior,
        settings.xp_cazador_de_amenazas,
    )
)

#: Catálogo de misiones cargado al arrancar.
_MISSIONS: list[dict] = []
_STARTED_AT = time.monotonic()

#: Rate limiting en proceso. Suficiente para un solo worker de desarrollo;
#: en producción esto va a Redis o al WAF, porque N workers = N contadores.
_RATE_BUCKETS: dict[str, deque[float]] = defaultdict(deque)
_RATE_LIMIT = settings.api_rate_limit
_RATE_WINDOW = settings.api_rate_window
_RATE_LAST_PURGE = 0.0
_RATE_PURGE_EVERY = 300.0  # segundos


def _purge_rate_buckets(now: float) -> None:
    """Descarta los cubos vencidos.

    Sin esto el diccionario crece una entrada por IP vista y no baja nunca:
    alcanza con rotar direcciones de origen para agotar la memoria del
    proceso. Es un limitador de tasa que se convierte en el vector de
    agotamiento que venía a evitar.
    """
    global _RATE_LAST_PURGE
    if now - _RATE_LAST_PURGE < _RATE_PURGE_EVERY:
        return
    _RATE_LAST_PURGE = now
    vencidos = [
        ip
        for ip, marcas in _RATE_BUCKETS.items()
        if not marcas or now - marcas[-1] > _RATE_WINDOW
    ]
    for ip in vencidos:
        del _RATE_BUCKETS[ip]
    if vencidos:
        log.debug("Limitador: %d cubos purgados", len(vencidos))


#: Se marca en el arranque; lo lee la sonda de preparación.
_DB_READY = False


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Arranque y apagado ordenados."""
    global _MISSIONS, _DB_READY
    _MISSIONS = full_catalog()
    log.info("Torre operativa · %d misiones en el catálogo", len(_MISSIONS))

    # Verificación temprana de la base: es preferible enterarse acá y no en
    # la primera petición de un analista.
    try:
        factory = get_session_factory()
        async with factory() as session:
            await session.execute(text("SELECT 1"))
        _DB_READY = True
        log.info("PostgreSQL alcanzable · progresión persistente")

        # El catálogo se sincroniza con la tabla: el bucle de verificación
        # necesita algo estable contra lo cual comparar un veredicto emitido
        # hace tres días. Es idempotente y no pisa misiones ya resueltas.
        async with factory() as session:
            repo = VerdictRepository(session, AnalystRepository(session, engine))
            nuevas = await repo.seed_missions(_MISSIONS)
            await session.commit()
        if nuevas:
            log.info("Catálogo sincronizado · %d misiones nuevas", nuevas)
    except Exception as exc:  # noqa: BLE001 - queremos el motivo en el log
        _DB_READY = False
        log.error("PostgreSQL INALCANZABLE: %s", exc)
        log.error("La progresión no se va a poder registrar. Revisá DATABASE_URL.")

    # En producción esto ABORTA el arranque. Arrancar degradado con una clave
    # de firma pública es peor que no arrancar: el servicio parece sano
    # mientras cualquiera se firma un token de administrador.
    settings.assert_production_ready()
    yield

    await dispose_engine()
    log.info("Torre desmontada · cierre limpio")


async def get_repo(
    session: AsyncSession = Depends(get_session),
) -> AnalystRepository:
    """Dependencia: un repositorio por petición, con su propia sesión."""
    return AnalystRepository(session, engine)


async def get_verdicts(
    session: AsyncSession = Depends(get_session),
) -> VerdictRepository:
    """Dependencia del bucle de verificación."""
    return VerdictRepository(session, AnalystRepository(session, engine))


async def get_auth(session: AsyncSession = Depends(get_session)) -> AuthRepository:
    return AuthRepository(session)


# ══════════════════════════════════════════════════════════════════════
#  Identidad: de dónde sale el analista de una petición
# ══════════════════════════════════════════════════════════════════════
#
# Se aceptan dos formas de presentar el access token:
#
#   · Cookie httpOnly  -> la que usa el navegador. Inaccesible desde
#                         JavaScript, así que un XSS no se la puede llevar.
#   · Authorization    -> para curl, scripts y el conector de ingesta.
#
# La cookie tiene prioridad: si un atacante logra inyectar una cabecera en
# una petición del navegador, la sesión legítima sigue mandando.


def _extract_token(cookie: str | None, header: str | None) -> str | None:
    if cookie:
        return cookie
    if header and header.lower().startswith("bearer "):
        return header[7:].strip()
    return None


async def current_analyst(
    atalaya_access: str | None = Cookie(default=None),
    authorization: str | None = Header(default=None),
    auth: AuthRepository = Depends(get_auth),
) -> Analyst:
    """Analista autenticado. Es la única fuente de identidad de la API.

    Ningún endpoint vuelve a leer un callsign del cuerpo de la petición: si
    lo hiciera, cualquiera podría operar en nombre de cualquiera.
    """
    token = _extract_token(atalaya_access, authorization)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Hace falta autenticarse. Entrá por /api/v1/auth/login.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        claims = decode_access_token(settings.api_secret_key, token)
    except AuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        )

    analyst = await auth.get_by_id(claims.analyst_id)
    if analyst is None or not analyst.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="La cuenta de este token ya no está activa.",
        )
    return analyst


async def optional_analyst(
    atalaya_access: str | None = Cookie(default=None),
    authorization: str | None = Header(default=None),
    auth: AuthRepository = Depends(get_auth),
) -> Analyst | None:
    """Identidad si la hay, None si no. La usa el feed, que es público."""
    if not _extract_token(atalaya_access, authorization):
        return None
    try:
        return await current_analyst(atalaya_access, authorization, auth)
    except HTTPException:
        return None


def require_role(*roles: Role):
    """Exige uno de los roles indicados."""

    async def guard(analyst: Analyst = Depends(current_analyst)) -> Analyst:
        if Role(analyst.role) not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "Permiso insuficiente. Requiere: "
                    + ", ".join(r.value for r in roles)
                ),
            )
        return analyst

    return guard


def _set_auth_cookies(
    response: Response, access: str, refresh: str | None = None
) -> None:
    """Deja los tokens en cookies endurecidas.

    · httpOnly  -> JavaScript no las ve; un XSS no puede robar la sesión.
    · SameSite=strict -> el navegador no las manda en peticiones que nacen
      en otro sitio, que es la defensa contra CSRF.
    · secure -> sólo por HTTPS. Se apaga en local porque ahí no hay TLS.
    """
    seguro = settings.is_production
    response.set_cookie(
        "atalaya_access",
        access,
        max_age=int(ACCESS_TTL.total_seconds()),
        httponly=True,
        secure=seguro,
        samesite="strict",
        path="/",
    )
    if refresh is not None:
        response.set_cookie(
            "atalaya_refresh",
            refresh,
            max_age=int(REFRESH_TTL.total_seconds()),
            httponly=True,
            secure=seguro,
            samesite="strict",
            # Sólo viaja al endpoint que lo necesita: reduce la superficie.
            path="/api/v1/auth",
        )


app = FastAPI(
    title="ATALAYA API",
    description=(
        "**El que vigila desde arriba ve venir la amenaza primero.**\n\n"
        "API de la academia táctica de Threat Intelligence. Sirve el Feed de "
        "Misiones en STIX 2.1 y gestiona la progresión del analista.\n\n"
        "Los indicadores de este entorno son sintéticos (RFC 5737 / RFC 2606); "
        "las familias de malware y técnicas ATT&CK son reales."
    ),
    version=__version__,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_tags=[
        {"name": "salud", "description": "Estado del servicio."},
        {"name": "feed", "description": "Feed de Misiones (STIX 2.1)."},
        {"name": "progresión", "description": "XP, rangos y ascensos."},
    ],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    # X-Callsign ya no existe: la identidad sale del token. Dejarla habilitada
    # era superficie muerta apuntando al modelo viejo.
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,
)


@app.middleware("http")
async def hardening_middleware(request: Request, call_next):
    """Cabeceras de seguridad, trace id y rate limiting básico.

    Nada exótico: es el mínimo que debería tener cualquier API expuesta.
    """
    client_ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    _purge_rate_buckets(now)
    bucket = _RATE_BUCKETS[client_ip]
    while bucket and now - bucket[0] > _RATE_WINDOW:
        bucket.popleft()
    if len(bucket) >= _RATE_LIMIT:
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "error": "rate_limited",
                "detail": f"Máximo {_RATE_LIMIT} peticiones cada {int(_RATE_WINDOW)}s.",
            },
            headers={"Retry-After": str(int(_RATE_WINDOW))},
        )
    bucket.append(now)

    trace_id = request.headers.get("X-Trace-Id") or uuid.uuid4().hex[:16]
    started = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = (time.perf_counter() - started) * 1000

    response.headers["X-Trace-Id"] = trace_id
    response.headers["X-Response-Time-ms"] = f"{elapsed_ms:.1f}"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Errores con forma estable: el frontend no adivina."""
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error=f"http_{exc.status_code}",
            detail=str(exc.detail),
            trace_id=request.headers.get("X-Trace-Id"),
        ).model_dump(),
    )


# ══════════════════════════════════════════════════════════════════════
#  Salud
# ══════════════════════════════════════════════════════════════════════
@app.get("/health", response_model=HealthResponse, tags=["salud"])
async def health() -> HealthResponse:
    """Sonda de VIDA. Deliberadamente sin dependencias externas.

    Si esta sonda consultara la base, un parpadeo de PostgreSQL haría que el
    orquestador reiniciara un proceso que está perfectamente sano. Para saber
    si el servicio puede *atender*, está /health/ready.
    """
    degraded = settings.is_production and settings.api_secret_key.startswith(
        "insecure-dev"
    )
    return HealthResponse(
        status="degraded" if degraded else "ok",
        version=__version__,
        environment=settings.atalaya_env,
        uptime_seconds=round(time.monotonic() - _STARTED_AT, 2),
    )


@app.get("/health/ready", tags=["salud"])
async def readiness(session: AsyncSession = Depends(get_session)) -> dict:
    """Sonda de PREPARACIÓN: incluye la base. La usa Cloud Run al arrancar."""
    try:
        await session.execute(text("SELECT 1"))
        return {"status": "ready", "database": "ok", "persistencia": True}
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"PostgreSQL inalcanzable: {type(exc).__name__}",
        )


@app.get("/", include_in_schema=False)
async def root() -> dict:
    return {
        "service": "ATALAYA",
        "motto": "El que vigila desde arriba ve venir la amenaza primero.",
        "docs": "/docs",
        "feed": "/api/v1/feed",
    }


# ══════════════════════════════════════════════════════════════════════
#  Autenticación
# ══════════════════════════════════════════════════════════════════════
@app.post(
    "/api/v1/auth/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["identidad"],
)
async def register(
    payload: RegisterRequest,
    response: Response,
    auth: AuthRepository = Depends(get_auth),
) -> TokenResponse:
    """Da de alta un analista y lo deja con sesión iniciada."""
    try:
        analyst = await auth.register(
            callsign=payload.callsign, password=payload.password, email=payload.email
        )
    except WeakPasswordError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        )
    except AuthError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))

    access, expires = issue_access_token(
        settings.api_secret_key, analyst.id, analyst.callsign, Role(analyst.role)
    )
    refresh, _ = await auth.create_refresh_token(analyst)
    _set_auth_cookies(response, access, refresh)
    log.info("ALTA · %s", analyst.callsign)
    return TokenResponse(
        access_token=access,
        expires_in=int(ACCESS_TTL.total_seconds()),
        callsign=analyst.callsign,
        role=analyst.role,
    )


@app.post("/api/v1/auth/login", response_model=TokenResponse, tags=["identidad"])
async def login(
    payload: LoginRequest,
    response: Response,
    auth: AuthRepository = Depends(get_auth),
) -> TokenResponse:
    """Inicia sesión.

    Un fallo devuelve siempre el mismo mensaje, exista o no la cuenta: la
    diferencia sería un oráculo para enumerar callsigns.
    """
    try:
        analyst = await auth.authenticate(payload.callsign, payload.password)
    except AuthError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))

    access, _ = issue_access_token(
        settings.api_secret_key, analyst.id, analyst.callsign, Role(analyst.role)
    )
    refresh, _ = await auth.create_refresh_token(analyst)
    _set_auth_cookies(response, access, refresh)
    return TokenResponse(
        access_token=access,
        expires_in=int(ACCESS_TTL.total_seconds()),
        callsign=analyst.callsign,
        role=analyst.role,
    )


@app.post("/api/v1/auth/refresh", response_model=TokenResponse, tags=["identidad"])
async def refresh_session(
    response: Response,
    atalaya_refresh: str | None = Cookie(default=None),
    auth: AuthRepository = Depends(get_auth),
) -> TokenResponse:
    """Renueva la sesión rotando el refresh token.

    Si llega un token ya rotado, se asume que alguien clonó la sesión y se
    revoca la familia entera. Molestar con un nuevo login es barato; dejar
    viva una sesión robada, no se arregla después.
    """
    if not atalaya_refresh:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No hay sesión que renovar.",
        )
    try:
        analyst, nuevo_refresh, _ = await auth.rotate_refresh_token(atalaya_refresh)
    except AuthError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))

    access, _ = issue_access_token(
        settings.api_secret_key, analyst.id, analyst.callsign, Role(analyst.role)
    )
    _set_auth_cookies(response, access, nuevo_refresh)
    return TokenResponse(
        access_token=access,
        expires_in=int(ACCESS_TTL.total_seconds()),
        callsign=analyst.callsign,
        role=analyst.role,
    )


@app.post("/api/v1/auth/logout", tags=["identidad"])
async def logout(
    response: Response,
    todas: bool = Query(default=False, description="Cerrar en todos los dispositivos"),
    atalaya_refresh: str | None = Cookie(default=None),
    analyst: Analyst = Depends(current_analyst),
    auth: AuthRepository = Depends(get_auth),
) -> dict:
    """Cierra la sesión. Revoca del lado del servidor, no sólo borra cookies."""
    cerradas = (
        await auth.revoke_all(analyst.id)
        if todas
        else int(await auth.revoke(atalaya_refresh or ""))
    )
    response.delete_cookie("atalaya_access", path="/")
    response.delete_cookie("atalaya_refresh", path="/api/v1/auth")
    return {"sesiones_cerradas": cerradas, "message": ">> ENLACE TERMINADO"}


@app.get("/api/v1/auth/me", response_model=MeResponse, tags=["identidad"])
async def whoami(
    analyst: Analyst = Depends(current_analyst),
    auth: AuthRepository = Depends(get_auth),
) -> MeResponse:
    """Quién sos, según el token que presentaste."""
    return MeResponse(
        callsign=analyst.callsign,
        role=analyst.role,
        email=analyst.email,
        joined_at=analyst.joined_at.isoformat(),
        last_login_at=(
            analyst.last_login_at.isoformat() if analyst.last_login_at else None
        ),
        active_sessions=len(await auth.active_sessions(analyst.id)),
    )


# ══════════════════════════════════════════════════════════════════════
#  Feed de Misiones
# ══════════════════════════════════════════════════════════════════════
#: Campos de MissionSummary que salen del contenido guardado de la misión.
_CAMPOS_RESUMEN = set(MissionSummary.model_fields) - {
    "locked",
    "independent_sources",
    "awaiting_corroboration",
    "my_verdict",
}


def _resumen(fila, viewer_level: int, veredicto=None) -> MissionSummary:
    """Arma la tarjeta a partir de la fila y del contenido guardado."""
    contenido = {k: v for k, v in (fila.payload or {}).items() if k in _CAMPOS_RESUMEN}
    requerido = Rank(contenido.get("required_rank", "NOVATO"))
    return MissionSummary(
        **contenido,
        # Se marca, no se oculta: ver lo que todavía no podés tocar es la
        # mitad del incentivo para subir de rango.
        locked=engine.spec_for(requerido).level > viewer_level,
        independent_sources=fila.independent_sources,
        awaiting_corroboration=(
            fila.ground_truth == "UNKNOWN" and fila.resolves_at is not None
        ),
        my_verdict=(
            {
                "call": veredicto.call,
                "confidence": veredicto.confidence,
                "graded": veredicto.graded_at is not None,
                "xp_awarded": veredicto.xp_awarded,
                "was_correct": veredicto.was_correct,
                "brier_score": veredicto.brier_score,
            }
            if veredicto is not None
            else None
        ),
    )


@app.get("/api/v1/feed", response_model=FeedResponse, tags=["feed"])
async def get_feed(
    cursor: str | None = Query(
        default=None, description="Cursor opaco de la página anterior."
    ),
    limit: int | None = Query(default=None, ge=1, le=100),
    severity: str | None = Query(
        default=None,
        description="Filtra por severidad: low|medium|high|critical.",
    ),
    repo: AnalystRepository = Depends(get_repo),
    session: AsyncSession = Depends(get_session),
    viewer: Analyst | None = Depends(optional_analyst),
) -> FeedResponse:
    """Página del Feed de Misiones, lista para scroll infinito.

    Lee de la base: lo que traen los conectores reales llega acá. El feed
    **termina** cuando se agotan las misiones — antes reciclaba el mismo
    catálogo en bucle, y con ocho misiones eso se veía a los veinte segundos.

    Devuelve dos vistas de lo mismo:

    * `missions`: metadatos gamificados que renderiza la UI.
    * `bundle`: el STIX 2.1 Bundle crudo, importable en OpenCTI o MISP.
    """
    page_size = min(
        limit or settings.api_feed_page_size, settings.api_feed_max_page_size
    )

    sev = severity.lower() if severity else None
    if sev and sev not in {"low", "medium", "high", "critical"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="severity debe ser low, medium, high o critical.",
        )

    feed = FeedRepository(session)
    offset = decode_cursor(cursor)
    filas, total = await feed.page(offset, page_size, sev)

    # El feed es público: sin sesión se ve todo como Novato. Con sesión, las
    # misiones fuera de rango se marcan como bloqueadas — el rango sale del
    # token, no de un parámetro que cualquiera puede inventar.
    viewer_rank = Rank.NOVATO
    veredictos: dict = {}
    if viewer is not None:
        viewer_rank = await repo.current_rank(viewer.callsign)
        veredictos = await feed.verdicts_of(viewer.id, [f.mission_id for f in filas])
    viewer_level = engine.spec_for(viewer_rank).level

    siguiente = offset + len(filas)
    hay_mas = siguiente < total
    return FeedResponse(
        missions=[
            _resumen(f, viewer_level, veredictos.get(f.mission_id)) for f in filas
        ],
        bundle=as_bundle(
            [{"objects": (f.payload or {}).get("objects", [])} for f in filas]
        ),
        next_cursor=encode_cursor(siguiente) if hay_mas else None,
        has_more=hay_mas,
        total=total,
        generated_at=now_iso(),
        viewer_rank=viewer_rank.value,
    )


@app.get(
    "/api/v1/feed/{mission_id}",
    response_model=MissionSummary,
    tags=["feed"],
    responses={404: {"model": ErrorResponse}},
)
async def get_mission(
    mission_id: str, session: AsyncSession = Depends(get_session)
) -> MissionSummary:
    """Detalle de una misión puntual."""
    fila = await FeedRepository(session).get(mission_id)
    if fila is None or fila.payload is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Misión {mission_id} no encontrada.",
        )
    return _resumen(fila, viewer_level=4)


@app.get("/api/v1/feed/{mission_id}/stix", tags=["feed"])
async def get_mission_stix(
    mission_id: str, session: AsyncSession = Depends(get_session)
) -> dict:
    """Bundle STIX 2.1 crudo de una misión. Importable tal cual en OpenCTI."""
    fila = await FeedRepository(session).get(mission_id)
    if fila is None or fila.payload is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Misión {mission_id} no encontrada.",
        )
    return as_bundle([{"objects": fila.payload.get("objects", [])}])


# ══════════════════════════════════════════════════════════════════════
#  Progresión
# ══════════════════════════════════════════════════════════════════════
@app.post(
    "/api/v1/level-up",
    response_model=LevelUpResponse,
    tags=["progresión"],
    responses={422: {"model": ErrorResponse}},
)
async def level_up(
    payload: LevelUpRequest,
    repo: AnalystRepository = Depends(get_repo),
    analyst: Analyst = Depends(current_analyst),
) -> LevelUpResponse:
    """Registra un evento de XP y devuelve el estado de progresión resultante.

    No es un endpoint de "sumame puntos": el evento describe **qué hizo** el
    analista. La tabla de XP y el multiplicador por severidad viven del lado
    del servidor, para que el cliente no pueda regalarse rangos.
    """
    try:
        event = XPEvent(payload.event)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=(
                f"Evento '{payload.event}' desconocido. "
                f"Válidos: {', '.join(e.value for e in XPEvent)}"
            ),
        )

    result = await repo.award(
        # La identidad sale del token. Éste es el arreglo: mientras el
        # callsign venía en el cuerpo, cualquiera podía ascenderse solo.
        callsign=analyst.callsign,
        event=event,
        severity=payload.severity,
        mission_id=payload.mission_id,
        multiplier=payload.multiplier,
    )
    if result["promoted"]:
        log.info(
            "ASCENSO · %s -> %s (%d XP)",
            result["callsign"],
            result["rank"],
            result["xp_total"],
        )
    return LevelUpResponse(**result)


@app.get("/api/v1/ranks", response_model=list[RankInfo], tags=["progresión"])
async def get_ranks() -> list[RankInfo]:
    """Escalera completa de rangos con umbrales y desbloqueos."""
    return [
        RankInfo(
            rank=spec.rank.value,
            level=spec.level,
            label=spec.label,
            xp_required=spec.xp_required,
            clearance=spec.clearance,
            unlocks=list(spec.unlocks),
            color=spec.color,
        )
        for spec in engine.ladder
    ]


@app.get("/api/v1/xp-table", tags=["progresión"])
async def get_xp_table() -> dict:
    """Tabla de XP: qué acción vale cuánto. Transparencia total con el analista."""
    return {
        "events": {e.value: xp for e, xp in XP_TABLE.items()},
        "severity_multipliers": {
            "low": 1.0,
            "medium": 1.25,
            "high": 1.6,
            "critical": 2.0,
        },
        "nota": (
            "Los valores negativos son penalizaciones. No se multiplican por "
            "severidad: castigamos el error, no la ambición."
        ),
    }


@app.get(
    "/api/v1/analysts/{callsign}",
    response_model=AnalystState,
    tags=["progresión"],
    responses={404: {"model": ErrorResponse}},
)
async def get_analyst(
    callsign: str,
    repo: AnalystRepository = Depends(get_repo),
) -> AnalystState:
    """Estado del analista. Alimenta el panel lateral del frontend.

    Todo lo que devuelve está derivado de `xp_events`: no hay contadores
    guardados que puedan discrepar del historial que los produjo.
    """
    limpio = callsign.strip().lower()
    if await repo.find(limpio) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No hay ningún analista con el callsign '{limpio}'.",
        )
    snap = await repo.snapshot(limpio)
    nxt = engine.next_rank(snap.spec.rank)
    return AnalystState(
        callsign=snap.callsign,
        xp=snap.xp,
        rank=snap.spec.rank.value,
        rank_label=snap.spec.label,
        level=snap.spec.level,
        clearance=snap.spec.clearance,
        unlocks=list(snap.spec.unlocks),
        next_rank=nxt.rank.value if nxt else None,
        xp_to_next=max(0, nxt.xp_required - snap.xp) if nxt else 0,
        progress=round(engine.progress_to_next(snap.xp), 4),
        missions_completed=snap.missions_completed,
        iocs_verified=snap.iocs_verified,
        streak=snap.streak,
        joined_at=snap.joined_at.isoformat(),
        last_event_at=(snap.last_event_at.isoformat() if snap.last_event_at else None),
        recent_events=snap.recent_events,
    )


@app.get(
    "/api/v1/leaderboard",
    response_model=list[LeaderboardEntry],
    tags=["progresión"],
)
async def leaderboard(
    limit: int = Query(default=10, ge=1, le=100),
    repo: AnalystRepository = Depends(get_repo),
):
    """Ranking de la torre, agregado sobre los eventos."""
    return [
        LeaderboardEntry(position=i + 1, **row)
        for i, row in enumerate(await repo.leaderboard(limit))
    ]


# ══════════════════════════════════════════════════════════════════════
#  Bucle de verificación
# ══════════════════════════════════════════════════════════════════════
@app.post(
    "/api/v1/missions/{mission_id}/verdict",
    response_model=VerdictResponse,
    tags=["verificación"],
    responses={404: {"model": ErrorResponse}, 409: {"model": ErrorResponse}},
)
async def submit_verdict(
    mission_id: str,
    payload: VerdictRequest,
    repo: VerdictRepository = Depends(get_verdicts),
    analyst: Analyst = Depends(current_analyst),
) -> VerdictResponse:
    """Emite un veredicto sobre una misión.

    **No es un botón: es una apuesta declarada.** Decís qué creés y con cuánta
    certeza, y se te califica con una regla de puntuación propia (Brier).

    * Declarar 50% paga exactamente 0 XP. Cubrirse no es una estrategia.
    * Equivocarse con certeza cuesta el triple de lo que rinde acertar con
      certeza. Es la proporción correcta en un SOC real.
    * Se emite **una sola vez** y no se puede editar.

    Si la verdad de referencia todavía no se resolvió, el veredicto queda
    sellado y se califica cuando la corroboración cierre.
    """
    try:
        resultado = await repo.submit(
            callsign=analyst.callsign,
            mission_id=mission_id,
            call=Call(payload.call),
            confidence=payload.confidence,
            rationale=payload.rationale,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        )
    return VerdictResponse(**resultado)


@app.post(
    "/api/v1/missions/{mission_id}/resolve",
    tags=["verificación"],
    responses={404: {"model": ErrorResponse}, 409: {"model": ErrorResponse}},
)
async def resolve_mission(
    mission_id: str,
    payload: ResolveRequest,
    repo: VerdictRepository = Depends(get_verdicts),
    _: Analyst = Depends(require_role(Role.INSTRUCTOR, Role.ADMIN)),
) -> dict:
    """Fija la verdad de referencia y califica todo lo pendiente.

    Punto de entrada de la corroboración diferida: pasadas las 72 h se mira
    cuántas fuentes independientes corroboraron y se califica de una sola vez
    a todos los que apostaron a ciegas.

    Requiere rol INSTRUCTOR o ADMIN: quien puede fijar la verdad, decide
    quién gana XP. Es el permiso más delicado del sistema.
    """
    try:
        return await repo.resolve(
            mission_id=mission_id,
            truth=GroundTruth(payload.ground_truth),
            source=TruthSource(payload.truth_source),
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


@app.get(
    "/api/v1/analysts/{callsign}/calibration",
    response_model=CalibrationResponse,
    tags=["verificación"],
)
async def get_calibration(
    callsign: str,
    repo: VerdictRepository = Depends(get_verdicts),
) -> CalibrationResponse:
    """Calibración del analista.

    La XP dice cuánto trabajó. Esto dice si acierta cuando dice estar seguro
    — que es la pregunta que un jefe de SOC realmente hace. `overconfidence`
    positivo significa que cree saber más de lo que sabe.
    """
    limpio = callsign.strip().lower()
    if await repo._analysts.find(limpio) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No hay ningún analista con el callsign '{limpio}'.",
        )
    return CalibrationResponse(**await repo.calibration(limpio))


@app.get("/api/v1/stats", tags=["feed"])
async def stats(
    repo: AnalystRepository = Depends(get_repo),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Métricas del tablero: los contadores de la esquina superior del SOC."""
    conteo = await FeedRepository(session).counts()
    return {
        "missions_total": conteo["total"],
        "by_severity": conteo["by_severity"],
        "analysts_active": await repo.count_analysts(),
        "sources": conteo["sources"],
        "server_time": datetime.now(timezone.utc).isoformat(),
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=settings.api_host,
        port=settings.api_port,
        log_level=settings.api_log_level,
        reload=not settings.is_production,
    )
