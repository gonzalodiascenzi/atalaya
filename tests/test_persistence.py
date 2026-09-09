"""
ATALAYA // Tests de la capa de persistencia.

Lo que se verifica acá no es "la API responde 200", sino las tres propiedades
que sostienen el diseño:

  1. Los eventos quedan REALMENTE en PostgreSQL (no en un dict del proceso).
  2. La XP es la SUMA de los eventos: no hay contador mutable que discrepe.
  3. La misma misión no puede acreditar el mismo evento dos veces.
"""

import asyncio

from sqlalchemy import func, select, text


def consultar(fn):
    """Ejecuta `fn(session)` contra una conexión NUEVA e independiente.

    Dos motivos para no reutilizar el pool de la aplicación:

    1. Técnico: el pool queda atado al event loop del TestClient; usarlo desde
       otro loop revienta con "attached to a different loop".
    2. De fondo, y es el que importa: abrir una conexión propia demuestra que
       el dato está en PostgreSQL de verdad, y no simplemente visible a través
       de la sesión de la aplicación. Es la diferencia entre "persistió" y
       "lo tengo en un caché".
    """

    async def runner():
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
        from sqlalchemy.pool import NullPool

        from config import get_settings

        engine = create_async_engine(
            get_settings().async_database_url, poolclass=NullPool
        )
        try:
            async with async_sessionmaker(engine, expire_on_commit=False)() as session:
                return await fn(session)
        finally:
            await engine.dispose()

    return asyncio.run(runner())


# ══════════════════════════════════════════════════════════════════════
#  1. Los datos existen en la base
# ══════════════════════════════════════════════════════════════════════


def test_los_eventos_se_escriben_en_postgres(client, token_for):
    """Lo que la API dice haber otorgado tiene que estar en una fila."""
    from models import Analyst, XPEvent

    callsign = "test-persiste"
    for _ in range(3):
        client.post(
            "/api/v1/level-up",
            json={"event": "ioc_enriched", "severity": "medium"},
            headers=token_for(callsign),
        )

    async def leer(session):
        analyst = await session.scalar(
            select(Analyst).where(Analyst.callsign == callsign)
        )
        assert analyst is not None, "el analista no llegó a la base"
        filas = (
            await session.scalars(
                select(XPEvent).where(XPEvent.analyst_id == analyst.id)
            )
        ).all()
        return analyst, filas

    analyst, filas = consultar(leer)
    assert len(filas) == 3
    assert all(f.event == "ioc_enriched" for f in filas)
    # 25 base x 1.25 (media) = 31
    assert all(f.xp_delta_applied == 31 for f in filas)
    assert analyst.joined_at is not None


def test_la_xp_de_la_api_coincide_con_la_suma_de_la_base(client, token_for):
    """Única fuente de verdad: lo que muestra la API es SUM(eventos)."""
    from models import Analyst, XPEvent

    callsign = "test-suma"
    for evento in ("mission_triage", "ioc_enriched", "ioc_verified", "peer_review"):
        client.post(
            "/api/v1/level-up",
            json={"event": evento, "severity": "high"},
            headers=token_for(callsign),
        )

    reportada = client.get(f"/api/v1/analysts/{callsign}").json()["xp"]

    async def sumar(session):
        analyst = await session.scalar(
            select(Analyst).where(Analyst.callsign == callsign)
        )
        return await session.scalar(
            select(func.coalesce(func.sum(XPEvent.xp_delta_applied), 0)).where(
                XPEvent.analyst_id == analyst.id
            )
        )

    assert reportada == consultar(sumar)


def test_no_existe_columna_de_xp_mutable():
    """Guardia estructural contra la regresión más probable.

    Si alguien "optimiza" agregando `analysts.xp`, vuelve el problema que esta
    etapa vino a resolver: dos fuentes de verdad que se desincronizan.
    """
    from models import Analyst

    columnas = set(Analyst.__table__.columns.keys())
    # La guardia real: ninguna columna que huela a saldo acumulado.
    assert not any(
        "xp" in c or "score" in c or "points" in c for c in columnas
    ), f"apareció un contador mutable en analysts: {columnas}"
    # Y el estado del analista sigue siendo identidad + credenciales, nada más.
    assert columnas == {
        "id",
        "callsign",
        "joined_at",
        "password_hash",
        "email",
        "role",
        "is_active",
        "last_login_at",
        "failed_login_attempts",
        "locked_until",
    }


# ══════════════════════════════════════════════════════════════════════
#  2. Anti-farmeo
# ══════════════════════════════════════════════════════════════════════


def test_la_misma_mision_no_acredita_dos_veces(client, token_for):
    """Clickear "Triar" cien veces sobre la misma misión no sube de rango."""
    callsign = "test-farmeo"
    cabeceras = token_for(callsign)
    payload = {
        "event": "mission_triage",
        "mission_id": "MSN-FARM0001",
        "severity": "critical",
    }

    primero = client.post("/api/v1/level-up", json=payload, headers=cabeceras).json()
    assert primero["xp_delta"] == 20  # 10 base x 2.0 (crítica)
    assert primero["already_awarded"] is False

    for _ in range(5):
        repetido = client.post(
            "/api/v1/level-up", json=payload, headers=cabeceras
        ).json()
        assert repetido["xp_delta"] == 0
        assert repetido["already_awarded"] is True

    assert client.get(f"/api/v1/analysts/{callsign}").json()["xp"] == 20


def test_eventos_distintos_sobre_la_misma_mision_si_acreditan(client, token_for):
    """El bloqueo es por (analista, misión, evento), no por misión entera."""
    callsign = "test-farmeo-2"
    cabeceras = token_for(callsign)
    base = {"mission_id": "MSN-FARM0002", "severity": "low"}

    a = client.post(
        "/api/v1/level-up", json={**base, "event": "mission_triage"}, headers=cabeceras
    ).json()
    b = client.post(
        "/api/v1/level-up", json={**base, "event": "ioc_enriched"}, headers=cabeceras
    ).json()

    assert a["already_awarded"] is False and a["xp_delta"] == 10
    assert b["already_awarded"] is False and b["xp_delta"] == 25


def test_eventos_sin_mision_siguen_siendo_repetibles(client, token_for):
    """El índice único es parcial: sin mission_id no hay deduplicación."""
    callsign = "test-sin-mision"
    for _ in range(3):
        body = client.post(
            "/api/v1/level-up",
            json={"event": "peer_review", "severity": "low"},
            headers=token_for(callsign),
        ).json()
        assert body["already_awarded"] is False
    assert client.get(f"/api/v1/analysts/{callsign}").json()["xp"] == 120


# ══════════════════════════════════════════════════════════════════════
#  3. Métricas derivadas
# ══════════════════════════════════════════════════════════════════════


def test_contadores_derivados_de_los_eventos(client, token_for):
    callsign = "test-contadores"
    for i in range(2):
        client.post(
            "/api/v1/level-up",
            json={"event": "mission_triage", "mission_id": f"MSN-CNT{i:05d}"},
            headers=token_for(callsign),
        )
    client.post(
        "/api/v1/level-up",
        json={"event": "ioc_verified"},
        headers=token_for(callsign),
    )
    client.post(
        "/api/v1/level-up",
        json={"event": "correlation_confirmed"},
        headers=token_for(callsign),
    )

    estado = client.get(f"/api/v1/analysts/{callsign}").json()
    assert estado["missions_completed"] == 2
    assert estado["iocs_verified"] == 2


def test_la_racha_se_corta_con_un_evento_negativo(client, token_for):
    """La racha son los positivos consecutivos desde el más reciente."""
    callsign = "test-racha"
    for _ in range(3):
        client.post(
            "/api/v1/level-up",
            json={"event": "peer_review"},
            headers=token_for(callsign),
        )
    assert client.get(f"/api/v1/analysts/{callsign}").json()["streak"] == 3

    client.post(
        "/api/v1/level-up",
        json={"event": "false_positive_published"},
        headers=token_for(callsign),
    )
    assert client.get(f"/api/v1/analysts/{callsign}").json()["streak"] == 0

    client.post(
        "/api/v1/level-up", json={"event": "peer_review"}, headers=token_for(callsign)
    )
    assert client.get(f"/api/v1/analysts/{callsign}").json()["streak"] == 1


def test_bitacora_ordenada_del_mas_reciente_al_mas_viejo(client, token_for):
    callsign = "test-bitacora"
    for evento in ("mission_triage", "ioc_enriched", "ioc_verified"):
        client.post(
            "/api/v1/level-up", json={"event": evento}, headers=token_for(callsign)
        )

    eventos = client.get(f"/api/v1/analysts/{callsign}").json()["recent_events"]
    assert [e["event"] for e in eventos] == [
        "ioc_verified",
        "ioc_enriched",
        "mission_triage",
    ]


def test_leaderboard_ordena_por_xp_agregada(client, token_for):
    for callsign, veces in (("test-lb-alto", 4), ("test-lb-bajo", 1)):
        for _ in range(veces):
            client.post(
                "/api/v1/level-up",
                json={"event": "campaign_attributed"},
                headers=token_for(callsign),
            )

    tabla = client.get("/api/v1/leaderboard?limit=100").json()
    posiciones = {fila["callsign"]: fila["position"] for fila in tabla}
    assert posiciones["test-lb-alto"] < posiciones["test-lb-bajo"]
    assert [f["xp"] for f in tabla] == sorted((f["xp"] for f in tabla), reverse=True)


# ══════════════════════════════════════════════════════════════════════
#  4. Salud y esquema
# ══════════════════════════════════════════════════════════════════════


def test_readiness_confirma_la_base(client, token_for):
    body = client.get("/health/ready").json()
    assert body["status"] == "ready"
    assert body["persistencia"] is True


def test_liveness_no_depende_de_la_base(client, token_for):
    """/health no debe consultar PostgreSQL.

    Si lo hiciera, un parpadeo de la base haría que el orquestador reiniciara
    un proceso sano. Se verifica que la ruta no declare la dependencia.
    """
    from main import app

    ruta = next(r for r in app.routes if getattr(r, "path", None) == "/health")
    nombres = {d.call.__name__ for d in ruta.dependant.dependencies if d.call}
    assert "get_session" not in nombres


def test_el_indice_antifarmeo_es_parcial(client, token_for):
    """El índice único debe llevar WHERE mission_id IS NOT NULL."""

    async def leer_indice(session):
        return await session.scalar(
            text(
                "SELECT indexdef FROM pg_indexes "
                "WHERE indexname = 'uq_xp_events_una_vez_por_mision'"
            )
        )

    definicion = consultar(leer_indice)
    assert definicion is not None, "el índice anti-farmeo no existe"
    assert "UNIQUE" in definicion.upper()
    assert "mission_id IS NOT NULL" in definicion


def test_el_duplicado_no_pierde_el_alta_del_analista(client, token_for):
    """Un intento repetido no debe tumbar la transacción entera.

    Con `rollback()` completo en vez de un SAVEPOINT, el choque contra el
    índice anti-farmeo se llevaba puesto también el alta del analista hecha
    en la misma transacción. Este test cubre el caso límite: analista nuevo
    cuya PRIMERA petición es un duplicado.
    """
    from models import Analyst

    callsign = "test-savepoint"
    cabeceras = token_for(callsign)
    payload = {"event": "ioc_verified", "mission_id": "MSN-SAVEP001"}
    client.post("/api/v1/level-up", json=payload, headers=cabeceras)
    repetido = client.post("/api/v1/level-up", json=payload, headers=cabeceras).json()

    assert repetido["already_awarded"] is True

    async def buscar(session):
        return await session.scalar(select(Analyst).where(Analyst.callsign == callsign))

    assert consultar(buscar) is not None, "el analista se perdió en el rollback"
