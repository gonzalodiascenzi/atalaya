"""
ATALAYA // Tests del feed.

El bug que motiva este archivo: el feed servía SIEMPRE las ocho misiones del
catálogo en memoria. Todo lo que ingerían los conectores reales —CVEs del
KEV, C2 de ThreatFox— se escribía en la base y nadie lo veía jamás.
"""

import asyncio
from datetime import datetime, timezone

from base import IndicatorKind, RawIndicator, SourceName


def _ingerir_real(valor: str, kind=IndicatorKind.CVE, kev=True) -> str:
    """Persiste una misión como lo hace el orquestador. Devuelve su ID."""
    import run
    from ingestion_repository import IngestionRepository
    from normalize import build_mission
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import NullPool

    from config import get_settings

    grupo = [
        RawIndicator(
            value=valor,
            kind=kind,
            source=SourceName.CISA_KEV,
            source_reference=f"https://nvd.nist.gov/vuln/detail/{valor}",
            source_confidence=100,
            first_reported_at=datetime.now(timezone.utc),
            kev_listed=kev,
            description=f"{valor}: vulnerabilidad de prueba del feed.",
        )
    ]
    mision = build_mission(grupo)

    async def hacer():
        engine = create_async_engine(
            get_settings().async_database_url, poolclass=NullPool
        )
        try:
            async with async_sessionmaker(engine, expire_on_commit=False)() as s:
                await IngestionRepository(s).upsert_mission(
                    mision, run.avistamientos_de(grupo)
                )
                await s.commit()
        finally:
            await engine.dispose()

    asyncio.run(hacer())
    return mision["mission_id"]


def _todas(client, headers=None, severity=None) -> list[dict]:
    """Recorre el feed completo siguiendo el cursor."""
    misiones, cursor, vueltas = [], None, 0
    while True:
        qs = f"limit=50{f'&cursor={cursor}' if cursor else ''}"
        qs += f"&severity={severity}" if severity else ""
        pagina = client.get(f"/api/v1/feed?{qs}", headers=headers or {}).json()
        misiones.extend(pagina["missions"])
        cursor = pagina["next_cursor"]
        vueltas += 1
        assert vueltas < 50, "el feed no termina nunca: volvió el bucle infinito"
        if not pagina["has_more"]:
            return misiones


def test_lo_que_ingieren_los_conectores_llega_al_feed(client):
    """EL test de este archivo. Antes fallaba siempre."""
    mission_id = _ingerir_real("CVE-2026-11111")
    ids = {m["mission_id"] for m in _todas(client)}
    assert mission_id in ids, "la misión ingerida no aparece en el feed"


def test_la_mision_ingerida_trae_contenido_completo(client):
    mission_id = _ingerir_real("CVE-2026-22222")
    m = client.get(f"/api/v1/feed/{mission_id}").json()
    assert m["title"].startswith("Vulnerabilidad explotada activamente")
    assert m["severity"] == "critical"
    assert m["objectives"], "sin objetivos no hay misión que operar"
    assert m["attack_technique"] == "T1190"


def test_el_feed_termina(client):
    """Antes `has_more` era siempre true y el scroll reciclaba en bucle."""
    ultima = None
    cursor = None
    for _ in range(50):
        pagina = client.get(
            f"/api/v1/feed?limit=7{f'&cursor={cursor}' if cursor else ''}"
        ).json()
        ultima = pagina
        if not pagina["has_more"]:
            break
        cursor = pagina["next_cursor"]
    assert ultima["has_more"] is False
    assert ultima["next_cursor"] is None


def test_el_feed_no_repite_misiones(client):
    """Recorrer el feed entero no debe mostrar la misma misión dos veces."""
    ids = [m["mission_id"] for m in _todas(client)]
    assert len(ids) == len(set(ids)), "hay misiones repetidas en el feed"


def test_el_total_coincide_con_lo_recorrido(client):
    total = client.get("/api/v1/feed?limit=1").json()["total"]
    assert len(_todas(client)) == total


def test_el_filtro_de_severidad_se_aplica_en_la_base(client):
    for m in _todas(client, severity="critical"):
        assert m["severity"] == "critical"


def test_la_tarjeta_indica_si_la_verdad_esta_pendiente(client):
    """La UI necesita saber si se apuesta a ciegas o contra verdad conocida."""
    misiones = _todas(client)
    pendientes = [m for m in misiones if m["awaiting_corroboration"]]
    resueltas = [m for m in misiones if not m["awaiting_corroboration"]]
    assert pendientes, "el catálogo trae misiones ambiguas"
    assert resueltas, "el catálogo trae misiones con verdad conocida"


def test_mi_veredicto_aparece_en_la_tarjeta(client, token_for):
    """Sin esto la UI no puede decir "ya emitiste tu veredicto"."""
    cabeceras = token_for("test-feed-veredicto")
    mission_id = _ingerir_real("CVE-2026-33333")

    antes = {m["mission_id"]: m for m in _todas(client, headers=cabeceras)}[mission_id]
    assert antes["my_verdict"] is None

    client.post(
        f"/api/v1/missions/{mission_id}/verdict",
        json={"call": "MALICIOUS", "confidence": 90, "rationale": "Está en el KEV."},
        headers=cabeceras,
    )

    despues = {m["mission_id"]: m for m in _todas(client, headers=cabeceras)}[
        mission_id
    ]
    assert despues["my_verdict"]["call"] == "MALICIOUS"
    assert despues["my_verdict"]["graded"] is True
    assert despues["my_verdict"]["was_correct"] is True


def test_sin_sesion_nadie_ve_veredictos_ajenos(client, token_for):
    """my_verdict es por analista. Un anónimo no ve el de nadie."""
    for m in _todas(client):
        assert m["my_verdict"] is None
