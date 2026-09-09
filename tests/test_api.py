"""ATALAYA // Tests de la API: feed, progresión y contrato STIX."""

import pytest


# ── Salud ─────────────────────────────────────────────────────────────
def test_health_responde_ok(client, token_for):
    res = client.get("/health")
    assert res.status_code == 200
    body = res.json()
    assert body["service"] == "atalaya-api"
    assert body["stix_spec"] == "2.1"
    assert body["uptime_seconds"] >= 0


# ── Feed ──────────────────────────────────────────────────────────────
def test_feed_devuelve_misiones_y_bundle(client, token_for):
    res = client.get("/api/v1/feed?limit=3")
    assert res.status_code == 200
    body = res.json()

    assert len(body["missions"]) == 3
    assert body["bundle"]["type"] == "bundle"
    assert body["bundle"]["id"].startswith("bundle--")
    assert body["next_cursor"]


def test_feed_el_bundle_es_stix_21_coherente(client, token_for):
    """Todo objeto del bundle debe declarar spec_version 2.1 y un ID válido."""
    res = client.get("/api/v1/feed?limit=6")
    objects = res.json()["bundle"]["objects"]

    assert len(objects) > 6, "el bundle debe traer los objetos relacionados"

    for obj in objects:
        assert obj["id"].startswith(f"{obj['type']}--")
        assert obj["spec_version"] == "2.1"

    tipos = {o["type"] for o in objects}
    # El grafo mínimo que exige el proyecto.
    assert {"indicator", "malware", "attack-pattern", "relationship"} <= tipos


def test_feed_relaciones_resuelven_dentro_del_bundle(client, token_for):
    res = client.get("/api/v1/feed?limit=6")
    objects = res.json()["bundle"]["objects"]
    ids = {o["id"] for o in objects}

    for rel in (o for o in objects if o["type"] == "relationship"):
        assert rel["source_ref"] in ids
        assert rel["target_ref"] in ids
        assert rel["relationship_type"] in {"indicates", "uses", "targets"}


def test_feed_pagina_con_cursor(client, token_for):
    primera = client.get("/api/v1/feed?limit=2").json()
    segunda = client.get(f"/api/v1/feed?limit=2&cursor={primera['next_cursor']}").json()

    assert primera["missions"][0]["mission_id"] != segunda["missions"][0]["mission_id"]


def test_feed_cursor_invalido_no_rompe(client, token_for):
    """Un cursor manipulado devuelve la primera página, no un 500."""
    res = client.get("/api/v1/feed?limit=2&cursor=basura-no-base64")
    assert res.status_code == 200
    assert len(res.json()["missions"]) == 2


def test_feed_filtra_por_severidad(client, token_for):
    res = client.get("/api/v1/feed?severity=critical&limit=5")
    assert res.status_code == 200
    assert all(m["severity"] == "critical" for m in res.json()["missions"])


def test_feed_rechaza_severidad_desconocida(client, token_for):
    assert client.get("/api/v1/feed?severity=apocaliptica").status_code == 400


def test_feed_los_iocs_van_neutralizados(client, token_for):
    """Ningún indicador puede llegar al frontend en forma clickeable."""
    for mission in client.get("/api/v1/feed?limit=6").json()["missions"]:
        assert "http://" not in mission["ioc_defanged"]
        assert "https://" not in mission["ioc_defanged"]


def test_mision_inexistente_devuelve_404(client, token_for):
    res = client.get("/api/v1/feed/MSN-NOEXISTE")
    assert res.status_code == 404
    assert res.json()["error"] == "http_404"


def test_mision_expone_su_bundle_stix(client, token_for):
    mission_id = client.get("/api/v1/feed?limit=1").json()["missions"][0]["mission_id"]
    res = client.get(f"/api/v1/feed/{mission_id}/stix")
    assert res.status_code == 200
    assert res.json()["type"] == "bundle"


# ── Progresión ────────────────────────────────────────────────────────
def test_level_up_otorga_xp(client, token_for):
    res = client.post(
        "/api/v1/level-up",
        json={"event": "ioc_verified", "severity": "high"},
        headers=token_for("test-xp"),
    )
    assert res.status_code == 200
    body = res.json()
    # 60 base x 1.6 (severidad alta) = 96
    assert body["xp_delta"] == 96
    assert body["rank"] == "NOVATO"
    assert 0 <= body["progress"] <= 1


def test_level_up_asciende_al_cruzar_el_umbral(client, token_for):
    callsign = "test-ascenso"
    promovido = False
    for _ in range(6):
        body = client.post(
            "/api/v1/level-up",
            json={"event": "campaign_attributed", "severity": "low"},
            headers=token_for(callsign),
        ).json()
        if body["promoted"]:
            promovido = True
            assert body["rank"] == "ANALISTA_JUNIOR"
            assert "ioc:enrich" in body["unlocked"]
            break
    assert promovido, "300 XP por evento deberían cruzar el umbral de 250"


def test_penalizacion_resta_y_no_se_multiplica(client, token_for):
    """La severidad crítica no amplifica el castigo.

    Se acumula saldo suficiente primero (120 XP) para que el piso en cero no
    interfiera: lo que se mide acá es el multiplicador, no el piso.
    """
    callsign = "test-penalizacion"
    for _ in range(2):
        client.post(
            "/api/v1/level-up",
            json={"event": "ioc_verified", "severity": "low"},
            headers=token_for(callsign),
        )
    body = client.post(
        "/api/v1/level-up",
        json={"event": "false_positive_published", "severity": "critical"},
        headers=token_for(callsign),
    ).json()
    # -75 exacto: sin ×2 por severidad crítica.
    assert body["xp_delta"] == -75
    assert body["xp_total"] == 45  # 60 + 60 - 75


def test_la_penalizacion_se_recorta_al_saldo_disponible(client, token_for):
    """Con saldo menor a la multa, se descuenta sólo lo que hay.

    El evento registra el delta REALMENTE aplicado, no el nominal. Si guardara
    el nominal, `SUM(xp_delta_applied)` daría negativo — un saldo imposible —
    y la auditoría afirmaría un descuento que nunca ocurrió.
    """
    callsign = "test-recorte"
    client.post(
        "/api/v1/level-up",
        json={"event": "mission_triage", "severity": "low"},
        headers=token_for(callsign),
    )  # +10
    body = client.post(
        "/api/v1/level-up",
        json={"event": "false_positive_published"},
        headers=token_for(callsign),
    ).json()
    assert body["xp_delta"] == -10, "sólo puede descontar los 10 que había"
    assert body["xp_total"] == 0


def test_la_xp_nunca_baja_de_cero(client, token_for):
    callsign = "test-piso"
    for _ in range(3):
        client.post(
            "/api/v1/level-up",
            json={"event": "false_positive_published"},
            headers=token_for(callsign),
        )
    assert client.get(f"/api/v1/analysts/{callsign}").json()["xp"] == 0


def test_evento_desconocido_es_rechazado(client, token_for):
    res = client.post(
        "/api/v1/level-up",
        json={"event": "hackear_la_nasa"},
        headers=token_for("test-x"),
    )
    assert res.status_code == 422


def test_callsign_se_sanitiza(client):
    """El callsign se normaliza en el ALTA, que es donde se declara."""
    res = client.post(
        "/api/v1/auth/register",
        json={
            "callsign": "  GON<script>  ",
            "password": "frase-larga-de-prueba-atalaya-2026",
        },
    )
    client.cookies.clear()
    assert res.status_code == 201
    assert res.json()["callsign"] == "gonscript"


def test_callsign_demasiado_corto_es_rechazado(client):
    res = client.post(
        "/api/v1/auth/register",
        json={"callsign": "!", "password": "frase-larga-de-prueba-atalaya-2026"},
    )
    assert res.status_code == 422


def test_escalera_de_rangos_completa(client, token_for):
    ranks = client.get("/api/v1/ranks").json()
    assert [r["rank"] for r in ranks] == [
        "NOVATO",
        "ANALISTA_JUNIOR",
        "ANALISTA_SENIOR",
        "CAZADOR_DE_AMENAZAS",
    ]
    # Los umbrales tienen que ser estrictamente crecientes.
    umbrales = [r["xp_required"] for r in ranks]
    assert umbrales == sorted(umbrales) and len(set(umbrales)) == 4


def test_misiones_bloqueadas_segun_rango(client, token_for):
    """Un novato ve las misiones de rango superior, pero marcadas."""
    body = client.get("/api/v1/feed?limit=6", headers=token_for("test-novato")).json()
    assert any(m["locked"] for m in body["missions"])
    assert body["viewer_rank"] == "NOVATO"


# ── Motor de progresión, sin HTTP ─────────────────────────────────────
def test_escalera_invalida_es_rechazada():
    from gamification import build_ladder

    with pytest.raises(ValueError):
        build_ladder(0, 500, 100, 4000)  # desordenada


def test_progreso_llega_a_uno_en_el_rango_maximo(fresh_engine):
    assert fresh_engine.progress_to_next(999_999) == 1.0


def test_rango_por_xp(fresh_engine):
    assert fresh_engine.rank_for_xp(0).rank.value == "NOVATO"
    assert fresh_engine.rank_for_xp(249).rank.value == "NOVATO"
    assert fresh_engine.rank_for_xp(250).rank.value == "ANALISTA_JUNIOR"
    assert fresh_engine.rank_for_xp(1_200).rank.value == "ANALISTA_SENIOR"
    assert fresh_engine.rank_for_xp(10_000).rank.value == "CAZADOR_DE_AMENAZAS"


# ── Endurecimiento ────────────────────────────────────────────────────
def test_cabeceras_de_seguridad_presentes(client, token_for):
    res = client.get("/health")
    assert res.headers["X-Content-Type-Options"] == "nosniff"
    assert res.headers["X-Frame-Options"] == "DENY"
    assert "X-Trace-Id" in res.headers
