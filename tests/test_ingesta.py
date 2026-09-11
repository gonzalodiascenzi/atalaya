"""
ATALAYA // Tests de la capa de ingesta.

**Ningún test toca la red.** Las respuestas HTTP vienen de fixtures en disco:
una suite que depende de que abuse.ch esté arriba no es una suite, es un
monitoreo de terceros que falla en rojo por motivos ajenos al código.

Lo que se protege acá:

  1. Que "fuentes independientes" cuente OPERADORES y no APIs.
  2. Que los rangos reservados nunca lleguen al feed como amenaza.
  3. Que una fuente caída no tumbe la corrida completa.
  4. Que la corroboración diferida resuelva de verdad.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from base import (
    ConnectorDisabled,
    IndicatorKind,
    RawIndicator,
    SourceFamily,
    SourceName,
    deduplicate,
    independent_families,
    mission_id_for,
)
from normalize import build_mission, derive_severity, missions_from
from sources import (
    CisaKevConnector,
    EmergingThreatsConnector,
    OtxConnector,
    SpamhausDropConnector,
    ThreatFoxConnector,
)

FIXTURES = Path(__file__).parent / "fixtures"


def cargar(nombre: str) -> dict:
    return json.loads((FIXTURES / nombre).read_text(encoding="utf-8"))


def cliente_falso(payload: dict, status: int = 200, headers: dict | None = None):
    """Cliente httpx que responde siempre lo mismo, sin salir a la red."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=payload, headers=headers or {})

    return httpx.Client(transport=httpx.MockTransport(handler))


def indicador(
    valor: str,
    fuente: SourceName,
    *,
    kind=IndicatorKind.IPV4,
    confianza=60,
    muestra=False,
    kev=False,
) -> RawIndicator:
    return RawIndicator(
        value=valor,
        kind=kind,
        source=fuente,
        source_reference=f"https://ejemplo.invalid/{valor}",
        source_confidence=confianza,
        first_reported_at=datetime.now(timezone.utc),
        sample_available=muestra,
        kev_listed=kev,
    )


# ══════════════════════════════════════════════════════════════════════
#  1. Independencia: operadores, no APIs
# ══════════════════════════════════════════════════════════════════════


def test_las_apis_del_mismo_operador_cuentan_como_una():
    """El error silencioso que este diseño evita.

    ThreatFox y URLhaus son dos APIs de abuse.ch. Contarlas como dos
    corroboraciones independientes haría que un indicador cruce el umbral
    solo, y el sistema declararía verdades que ninguna segunda parte vio.
    """
    mismo_operador = [
        indicador("192.0.2.1", SourceName.THREATFOX),
        indicador("192.0.2.1", SourceName.URLHAUS),
    ]
    assert independent_families(mismo_operador) == 1

    operadores_distintos = [
        indicador("192.0.2.1", SourceName.THREATFOX),
        indicador("192.0.2.1", SourceName.OTX),
        indicador("192.0.2.1", SourceName.CISA_KEV),
    ]
    assert independent_families(operadores_distintos) == 3


def test_las_familias_estan_bien_asignadas():
    assert SourceName.THREATFOX.family is SourceFamily.ABUSE_CH
    assert SourceName.URLHAUS.family is SourceFamily.ABUSE_CH
    assert SourceName.OTX.family is SourceFamily.ALIENVAULT
    assert SourceName.CISA_KEV.family is SourceFamily.CISA


def test_la_huella_normaliza_para_poder_cruzar_fuentes():
    """Sin normalizar, `EVIL.COM.` y `evil.com` nunca se corroborarían."""
    a = indicador("EVIL.COM.", SourceName.OTX, kind=IndicatorKind.DOMAIN)
    b = indicador("evil.com", SourceName.THREATFOX, kind=IndicatorKind.DOMAIN)
    assert a.fingerprint == b.fingerprint
    assert len(deduplicate([a, b])) == 1


def test_el_id_de_mision_es_determinista():
    """Reingerir el mismo IoC actualiza la misión; no crea una nueva."""
    assert mission_id_for("ipv4-addr:1.2.3.4") == mission_id_for("ipv4-addr:1.2.3.4")
    assert mission_id_for("ipv4-addr:1.2.3.4") != mission_id_for("ipv4-addr:1.2.3.5")


# ══════════════════════════════════════════════════════════════════════
#  2. Nada reservado llega al feed
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize(
    "valor",
    [
        "192.0.2.8",
        "198.51.100.1",
        "203.0.113.9",
        "10.0.0.5",
        "127.0.0.1",
        "192.168.1.1",
    ],
)
def test_los_rangos_reservados_se_descartan(valor):
    """Publicar documentación o una LAN privada como amenaza real haría que
    alguien bloquee su propia red."""
    assert indicador(valor, SourceName.THREATFOX).is_reserved
    assert build_mission([indicador(valor, SourceName.THREATFOX)]) is None


def test_los_dominios_de_ejemplo_se_descartan():
    assert indicador(
        "malo.example", SourceName.OTX, kind=IndicatorKind.DOMAIN
    ).is_reserved


# ══════════════════════════════════════════════════════════════════════
#  3. Conectores (con fixtures)
# ══════════════════════════════════════════════════════════════════════


def test_cisa_kev_normaliza_el_catalogo_real(tmp_path):
    """Fixture recortada del feed REAL de CISA."""
    c = CisaKevConnector(
        client=cliente_falso(cargar("cisa_kev.json"), headers={"ETag": '"abc"'}),
        cache_dir=str(tmp_path),
    )
    indicadores = c.fetch(limit=10)

    assert indicadores, "el catálogo no debería venir vacío"
    for i in indicadores:
        assert i.kind is IndicatorKind.CVE
        assert i.value.startswith("CVE-")
        assert i.kev_listed is True
        # KEV es explotación observada: la confianza no se negocia.
        assert i.source_confidence == 100
        assert i.attack_technique == "T1190"


def test_cisa_kev_guarda_los_encabezados_de_cache(tmp_path):
    """Sin esto se retransfiere 1,7 MB en cada corrida."""
    c = CisaKevConnector(
        client=cliente_falso(
            cargar("cisa_kev.json"),
            headers={"ETag": '"abc"', "Last-Modified": "Tue, 08 Sep 2026 18:00:21 GMT"},
        ),
        cache_dir=str(tmp_path),
    )
    c.fetch(limit=1)
    assert (tmp_path / "kev.etag").read_text() == '"abc"'
    # El CDN de CISA ignora If-None-Match y sólo honra If-Modified-Since:
    # guardar Last-Modified no es redundante, es lo que hace funcionar el 304.
    assert "2026" in (tmp_path / "kev.last-modified").read_text()


def test_cisa_kev_usa_la_copia_local_ante_un_304(tmp_path):
    (tmp_path / "kev.etag").write_text('"abc"')
    (tmp_path / "kev.last-modified").write_text("Tue, 08 Sep 2026 18:00:21 GMT")
    (tmp_path / "kev.json").write_text(json.dumps(cargar("cisa_kev.json")))

    c = CisaKevConnector(client=cliente_falso({}, status=304), cache_dir=str(tmp_path))
    assert len(c.fetch(limit=10)) >= 1, "un 304 debe servirse de la caché"


def test_threatfox_normaliza_el_export_publico():
    """El export trae los mismos datos que la API, sin credencial."""
    c = ThreatFoxConnector(client=cliente_falso({}))
    indicadores = c.parse(cargar("threatfox_export.json"), limit=10)
    por_valor = {i.value: i for i in indicadores}

    # El puerto no es parte del observable en STIX: dejarlo rompería el
    # cruce con Emerging Threats, que reporta la misma IP sin puerto.
    assert "198.51.100.77" in por_valor
    assert not any(":" in i.value for i in indicadores if i.kind is IndicatorKind.IPV4)

    akira = por_valor["198.51.100.77"]
    assert akira.malware_family == "Akira"
    assert akira.source_confidence == 100
    assert akira.attack_technique == "T1071.001"
    assert akira.source.family is SourceFamily.ABUSE_CH


def test_threatfox_descarta_lo_viejo():
    """El export arrastra IoCs de 2021: C2 que se apagó hace años no entrena."""
    c = ThreatFoxConnector(client=cliente_falso({}))
    valores = {i.value for i in c.parse(cargar("threatfox_export.json"), limit=10)}
    assert "203.0.113.9" not in valores


def test_threatfox_ya_no_necesita_credencial():
    """El motivo del cambio: abuse.ch ya no da alta con correo."""
    assert ThreatFoxConnector.requires_env is None
    ThreatFoxConnector(client=cliente_falso({})).check_credentials({})


def test_otx_sin_credencial_avisa_y_no_explota():
    """Falta de credencial es configuración, no una falla del sistema."""
    with pytest.raises(ConnectorDisabled) as exc:
        OtxConnector(client=cliente_falso({})).check_credentials({})
    assert "OTX_API_KEY" in str(exc.value)


def test_placeholder_del_env_cuenta_como_sin_credencial():
    """`.env` trae PENDIENTE__... y eso NO es una clave."""
    with pytest.raises(ConnectorDisabled):
        OtxConnector(client=cliente_falso({})).check_credentials(
            {"OTX_API_KEY": "PENDIENTE__crear_cuenta_en_otx_alienvault_com"}
        )


# ══════════════════════════════════════════════════════════════════════
#  Emerging Threats y Spamhaus DROP
# ══════════════════════════════════════════════════════════════════════


def test_emerging_threats_es_otro_operador():
    """Lo que aporta ET no es contexto: es un operador distinto de abuse.ch."""
    c = EmergingThreatsConnector(client=cliente_falso({}))
    ips = c.parse((FIXTURES / "emerging_threats.txt").read_text(), limit=50)
    assert [i.value for i in ips] == ["198.51.100.77", "192.0.2.44", "203.0.113.200"]
    assert all(i.source.family is SourceFamily.PROOFPOINT for i in ips)


def test_emerging_threats_ignora_lo_que_no_es_ip():
    c = EmergingThreatsConnector(client=cliente_falso({}))
    valores = {i.value for i in c.parse("# comentario\nbasura\n\n1.2.3.4\n", limit=10)}
    assert valores == {"1.2.3.4"}


def test_spamhaus_corrobora_solo_lo_que_cae_en_sus_rangos():
    drop = SpamhausDropConnector(client=cliente_falso({}))
    assert drop.load((FIXTURES / "spamhaus_drop.json").read_text()) == 2

    avistamientos = drop.corroborate(["198.51.100.77", "203.0.113.200", "192.0.2.44"])
    valores = {a.value for a in avistamientos}
    assert "198.51.100.77" in valores  # dentro de 198.51.100.0/24
    assert "203.0.113.200" not in valores  # 203.0.113.0/25 termina en .127
    assert "192.0.2.44" not in valores
    assert all(a.source.family is SourceFamily.SPAMHAUS for a in avistamientos)


def test_spamhaus_no_genera_misiones_propias():
    """DROP lista rangos, no IoCs: por sí solo no dice nada de una IP puntual."""
    assert SpamhausDropConnector(client=cliente_falso({})).fetch(100) == []


# ══════════════════════════════════════════════════════════════════════
#  Qué se puede calificar
# ══════════════════════════════════════════════════════════════════════


def test_sin_otx_sólo_las_ips_son_calificables():
    """Hashes y dominios sólo los reporta abuse.ch: nunca alcanzarían el umbral."""
    import run

    activas = {
        SourceName.CISA_KEV,
        SourceName.THREATFOX,
        SourceName.EMERGING_THREATS,
        SourceName.SPAMHAUS_DROP,
    }
    tipos = run.corroborable_kinds(activas)
    assert IndicatorKind.IPV4 in tipos
    assert IndicatorKind.DOMAIN not in tipos
    assert IndicatorKind.SHA256 not in tipos


def test_con_otx_los_dominios_pasan_a_ser_calificables():
    """Sumar un operador que reporta dominios los habilita, sin tocar código."""
    import run

    tipos = run.corroborable_kinds({SourceName.THREATFOX, SourceName.OTX})
    assert IndicatorKind.DOMAIN in tipos
    assert IndicatorKind.SHA256 in tipos


def test_dos_apis_de_abuse_ch_no_habilitan_nada():
    """ThreatFox + URLhaus = un solo operador: no alcanza para calificar URLs."""
    import run

    assert IndicatorKind.URL not in run.corroborable_kinds(
        {SourceName.THREATFOX, SourceName.URLHAUS}
    )


def test_otx_hereda_el_contexto_del_pulso(monkeypatch):
    """El pulso aporta lo que los feeds sueltos no: familia y técnica."""
    monkeypatch.setenv("OTX_API_KEY", "clave-de-prueba")
    c = OtxConnector(client=cliente_falso(cargar("otx.json")))
    indicadores = c.fetch(limit=10)

    assert len(indicadores) == 3
    for i in indicadores:
        assert i.malware_family == "Akira"
        assert i.attack_technique == "T1486"
        assert i.source.family is SourceFamily.ALIENVAULT


# ══════════════════════════════════════════════════════════════════════
#  4. Normalización a misión
# ══════════════════════════════════════════════════════════════════════


def test_el_kev_manda_sobre_todo_lo_demas():
    assert (
        derive_severity([indicador("1.2.3.4", SourceName.CISA_KEV, kev=True)])
        == "critical"
    )


def test_una_sola_fuente_de_baja_confianza_entra_ambigua():
    """El material de la corroboración diferida."""
    m = build_mission([indicador("1.2.3.4", SourceName.OTX, confianza=45)])
    assert m["ground_truth"] == "UNKNOWN"
    assert m["independent_sources"] == 1
    assert "todavía NO alcanza el umbral" in m["briefing"]


def test_dos_operadores_independientes_dan_verdad():
    """El umbral es 2 desde que hay datos reales: ver scoring.py."""
    m = build_mission(
        [
            indicador("1.2.3.4", SourceName.THREATFOX),
            indicador("1.2.3.4", SourceName.EMERGING_THREATS),
        ]
    )
    assert m["ground_truth"] == "MALICIOUS"
    assert m["truth_source"] == "MULTI_SOURCE"
    assert m["independent_sources"] == 2


def test_tres_apis_del_mismo_operador_no_alcanzan():
    """El caso que justifica todo el diseño de familias."""
    m = build_mission(
        [
            indicador("1.2.3.4", SourceName.THREATFOX),
            indicador("1.2.3.4", SourceName.URLHAUS),
            indicador("1.2.3.4", SourceName.THREATFOX, confianza=90),
        ]
    )
    assert m["independent_sources"] == 1
    assert m["ground_truth"] == "UNKNOWN", "abuse.ch no se corrobora a sí mismo"


def test_la_mision_trae_todo_lo_que_el_bucle_necesita():
    """Contrato de docs/VERIFICACION.md §6."""
    m = build_mission([indicador("1.2.3.4", SourceName.THREATFOX, muestra=True)])
    for campo in (
        "source_confidence",
        "independent_sources",
        "kev_listed",
        "sample_available",
        "ground_truth",
        "fingerprint",
    ):
        assert campo in m, f"falta la señal '{campo}'"
    assert m["ioc_defanged"] == "1[.]2[.]3[.]4"


def test_el_bundle_stix_de_la_mision_es_valido():
    from misp_stix_connector import validate_bundle

    m = build_mission([indicador("1.2.3.4", SourceName.THREATFOX)])
    bundle = {
        "type": "bundle",
        "id": "bundle--" + "0" * 8 + "-0000-4000-a000-000000000000",
        "objects": m["objects"],
    }
    errores = [e for e in validate_bundle(bundle) if "referencia colgada" not in e]
    assert errores == [], errores


def test_la_mezcla_de_misiones_es_balanceada():
    """Ni todo KEV ni todo ambiguo: un turno de cada categoría.

    Ordenar sólo por solidez hacía que el KEV —todo malicioso— ocupara todos
    los lugares, y "decir siempre malicioso" ganaba siempre.
    """
    misiones = missions_from(
        [
            indicador("1.1.1.1", SourceName.OTX, confianza=40),
            indicador("2.2.2.2", SourceName.CISA_KEV, kind=IndicatorKind.CVE, kev=True),
            indicador("3.3.3.3", SourceName.OTX),
            indicador("3.3.3.3", SourceName.THREATFOX),
        ]
    )
    assert misiones[0]["kev_listed"] is True
    assert misiones[1]["independent_sources"] == 2


def test_una_fuente_caida_no_tumba_la_corrida(monkeypatch):
    """Una plataforma de inteligencia sin feed porque una API dio 500 no sirve."""
    import run

    class Rota(CisaKevConnector):
        def fetch(self, limit):
            raise RuntimeError("la fuente explotó")

    class Sana(ThreatFoxConnector):
        def fetch(self, limit):
            return [indicador("1.2.3.4", SourceName.THREATFOX)]

    monkeypatch.setattr(run, "ALL_CONNECTORS", (Rota, Sana))
    indicadores, estado = run.recolectar(limite_por_fuente=5)

    assert len(indicadores) == 1, "la fuente sana igual tiene que aportar"
    assert any("✗" in v for v in estado.values())
    assert any("✓" in v for v in estado.values())


# ══════════════════════════════════════════════════════════════════════
#  5. El ciclo completo contra PostgreSQL
# ══════════════════════════════════════════════════════════════════════


def _correr(coro_factory):
    """Ejecuta contra una conexión propia (ver tests/test_persistence.py)."""
    import asyncio

    async def runner():
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
        from sqlalchemy.pool import NullPool

        from config import get_settings

        engine = create_async_engine(
            get_settings().async_database_url, poolclass=NullPool
        )
        try:
            async with async_sessionmaker(engine, expire_on_commit=False)() as s:
                resultado = await coro_factory(s)
                await s.commit()
                return resultado
        finally:
            await engine.dispose()

    return asyncio.run(runner())


def _ingerir(grupo: list[RawIndicator]):
    """Persiste una misión con sus avistamientos, como lo hace run.py."""
    import run
    from ingestion_repository import IngestionRepository

    mision = build_mission(grupo)

    async def hacer(session):
        repo = IngestionRepository(session)
        estado = await repo.upsert_mission(mision, run.avistamientos_de(grupo))
        return mision, estado

    return _correr(hacer)


def test_la_corroboracion_se_acumula_entre_corridas(migrated_database):
    """Cada fuente nueva suma; la misma fuente repetida no.

    Es la diferencia entre contar corroboración y contar repeticiones. Un
    conector corriendo cada quince minutos inflaría el conteo con sus
    propias vueltas si esto no estuviera.
    """
    ip = "45.77.10.201"  # ruteable: no cae en rango reservado

    mision, estado = _ingerir([indicador(ip, SourceName.OTX, confianza=55)])
    assert estado == "creada"
    assert mision["ground_truth"] == "UNKNOWN"

    # La MISMA fuente otra vez: no es corroboración.
    _, estado = _ingerir([indicador(ip, SourceName.OTX, confianza=55)])
    assert estado == "sin-cambios"

    # Otra API del MISMO operador que ThreatFox tampoco suma dos.
    _, estado = _ingerir([indicador(ip, SourceName.THREATFOX)])
    assert estado == "corroborada"
    _, estado = _ingerir([indicador(ip, SourceName.URLHAUS)])

    async def contar(session):
        from ingestion_repository import IngestionRepository

        return await IngestionRepository(session)._independent_families(
            mission_id_for(f"ipv4-addr:{ip}")
        )

    # OTX + (ThreatFox y URLhaus, que son abuse.ch) = 2 operadores, no 3.
    assert _correr(contar) == 2
    # Y con el umbral en 2, eso ya es corroboración.


def test_la_ventana_vencida_resuelve_a_favor_si_hubo_corroboracion(migrated_database):
    ip = "45.77.10.202"
    _ingerir([indicador(ip, SourceName.OTX)])
    _ingerir([indicador(ip, SourceName.THREATFOX)])
    _ingerir([indicador(ip, SourceName.CISA_KEV)])

    mission_id = mission_id_for(f"ipv4-addr:{ip}")

    async def vencer_y_resolver(session):
        from ingestion_repository import IngestionRepository
        from models import MissionRecord

        m = await session.get(MissionRecord, mission_id)
        m.resolves_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        await session.flush()

        repo = IngestionRepository(session)
        pendientes = await repo.due_for_resolution()
        assert any(x.mission_id == mission_id for x in pendientes)
        return await repo.verdict_for(m)

    verdad, fuente, motivo = _correr(vencer_y_resolver)
    assert verdad.value == "MALICIOUS"
    assert fuente.value == "MULTI_SOURCE"
    assert "3 operadores" in motivo


def test_sin_corroboracion_y_baja_confianza_se_resuelve_BENIGNO(migrated_database):
    """Estas son las misiones que enseñan a NO bloquear.

    Una fuente sola, de baja confianza, sin muestra, y 72 h sin que nadie
    más lo viera: el peso de la evidencia dice que fue ruido.
    """
    ip = "45.77.10.203"
    _ingerir([indicador(ip, SourceName.OTX, confianza=45)])
    mission_id = mission_id_for(f"ipv4-addr:{ip}")

    async def vencer_y_resolver(session):
        from ingestion_repository import IngestionRepository
        from models import MissionRecord

        m = await session.get(MissionRecord, mission_id)
        m.resolves_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        await session.flush()
        return await IngestionRepository(session).verdict_for(m)

    verdad, fuente, motivo = _correr(vencer_y_resolver)
    assert verdad.value == "BENIGN"
    assert fuente.value == "CORROBORATION"
    assert "ninguna corroboración" in motivo


def test_evidencia_a_mitad_de_camino_NO_se_inventa_una_verdad(migrated_database):
    """Un solo operador, con confianza alta: queda sin resolver.

    No alcanza para corroborar (hace falta otro operador) y tampoco para
    darlo por ruido (la fuente está segura). Inventar una verdad para poder
    puntuar le enseñaría al analista una lección falsa: expira sin calificar.
    """
    ip = "45.77.10.204"
    _ingerir([indicador(ip, SourceName.OTX, confianza=85)])
    mission_id = mission_id_for(f"ipv4-addr:{ip}")

    async def vencer_y_resolver(session):
        from ingestion_repository import IngestionRepository
        from models import MissionRecord

        m = await session.get(MissionRecord, mission_id)
        m.resolves_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        await session.flush()
        return await IngestionRepository(session).verdict_for(m)

    verdad, fuente, _ = _correr(vencer_y_resolver)
    assert verdad.value == "UNKNOWN"
    assert fuente is None


def test_una_verdad_ya_fijada_no_se_toca(migrated_database):
    """Cambiar la verdad después de que la gente apostó es mover el arco."""
    cve = "CVE-2026-99999"
    mision, _ = _ingerir(
        [indicador(cve, SourceName.CISA_KEV, kind=IndicatorKind.CVE, kev=True)]
    )
    assert mision["ground_truth"] == "MALICIOUS"

    _ingerir([indicador(cve, SourceName.OTX, kind=IndicatorKind.CVE, confianza=30)])

    async def leer(session):
        from models import MissionRecord

        return await session.get(
            MissionRecord, mission_id_for(f"vulnerability:{cve.lower()}")
        )

    m = _correr(leer)
    assert m.ground_truth == "MALICIOUS"
    assert m.resolved_at is not None


def test_la_misma_ip_con_varios_puertos_es_un_solo_avistamiento(migrated_database):
    """Regresión encontrada contra datos reales de ThreatFox.

    La misma IP aparece con puertos distintos; al sacar el puerto quedan
    varias filas de la misma fuente. Eso es un operador repitiéndose, no tres
    corroboraciones — y persistirlo tal cual chocaba contra el índice único.
    """
    import run

    ip = "45.77.10.210"
    grupo = [
        indicador(ip, SourceName.THREATFOX, confianza=50),
        indicador(ip, SourceName.THREATFOX, confianza=90, muestra=True),
        indicador(ip, SourceName.THREATFOX, confianza=75),
    ]
    filas = run.avistamientos_de(grupo)
    assert len(filas) == 1
    assert filas[0]["source_confidence"] == 90
    assert filas[0]["sample_available"] is True

    mision, estado = _ingerir(grupo)  # antes: IntegrityError
    assert estado == "creada"
    assert mision["independent_sources"] == 1
