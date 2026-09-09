"""
ATALAYA // Tests del bucle de verificación.

Lo que se prueba acá es la tesis del producto (docs/VERIFICACION.md):

  1. Cubrirse al 50% no paga. Nunca.
  2. Equivocarse con certeza cuesta más que acertar con certeza.
  3. Un veredicto se emite una vez y no se puede reescribir.
  4. Lo emitido a ciegas se califica cuando la verdad se resuelve.
"""

import pytest

from scoring import (
    BRIER_SLOPE,
    Call,
    GroundTruth,
    brier_score,
    calibration_score,
    grade_verdict,
    overconfidence,
    probability_malicious,
    xp_from_brier,
)

# ══════════════════════════════════════════════════════════════════════
#  Motor de puntuación (puro, sin base)
# ══════════════════════════════════════════════════════════════════════


def test_cubrirse_al_50_no_paga_en_ninguna_direccion():
    """La propiedad más importante del sistema.

    Si declarar 50% pagara algo, la estrategia óptima sería hedgear en todo
    y farmear XP sin analizar nada.
    """
    for call in (Call.MALICIOUS, Call.BENIGN):
        for truth in (GroundTruth.MALICIOUS, GroundTruth.BENIGN):
            assert grade_verdict(call, 50, truth, 100).xp == 0


def test_equivocarse_con_certeza_cuesta_mas_que_acertar_con_certeza():
    """La asimetría es la tesis: un falso negativo confiado es lo más caro."""
    acierto = grade_verdict(Call.MALICIOUS, 100, GroundTruth.MALICIOUS, 100)
    error = grade_verdict(Call.MALICIOUS, 100, GroundTruth.BENIGN, 100)
    assert acierto.xp == 100
    assert error.xp == -300
    assert abs(error.xp) == 3 * acierto.xp


def test_la_duda_declarada_amortigua_el_error():
    """Equivocarse dudando debe costar menos que equivocarse con certeza."""
    dudando = grade_verdict(Call.MALICIOUS, 60, GroundTruth.BENIGN, 100)
    seguro = grade_verdict(Call.MALICIOUS, 95, GroundTruth.BENIGN, 100)
    assert dudando.xp > seguro.xp


def test_ambos_lados_se_califican_con_la_misma_regla():
    """Decir BENIGNO al 90% equivale a 10% de probabilidad de malicioso."""
    assert probability_malicious(Call.BENIGN, 90) == pytest.approx(0.1)
    assert probability_malicious(Call.MALICIOUS, 90) == pytest.approx(0.9)

    a = grade_verdict(Call.BENIGN, 90, GroundTruth.BENIGN, 100)
    b = grade_verdict(Call.MALICIOUS, 90, GroundTruth.MALICIOUS, 100)
    assert a.xp == b.xp


def test_inconclusive_no_puntua_ni_penaliza():
    for truth in (GroundTruth.MALICIOUS, GroundTruth.BENIGN):
        r = grade_verdict(Call.INCONCLUSIVE, 50, truth, 100)
        assert r.graded is True and r.xp == 0 and r.was_correct is None


def test_no_se_puede_calificar_contra_verdad_desconocida():
    r = grade_verdict(Call.MALICIOUS, 90, GroundTruth.UNKNOWN, 100)
    assert r.graded is False and r.xp == 0
    with pytest.raises(ValueError):
        brier_score(Call.MALICIOUS, 90, GroundTruth.UNKNOWN)


def test_brier_es_regla_propia_declarar_la_creencia_real_es_optimo():
    """La verificación de que el sistema no se puede jugar.

    Para una creencia real p se calcula el valor esperado de declarar cada
    confianza posible. Si el máximo no cayera en p, mentir pagaría — y la
    defensa anti-farmeo sería una política y no una propiedad matemática.

    Se mide sobre la fórmula continua: `xp_from_brier` redondea a enteros y
    ese redondeo corre el óptimo uno o dos puntos, lo cual se verifica aparte.
    """

    def xp_continuo(brier: float) -> float:
        return 100 * (1 - BRIER_SLOPE * brier)

    for p in (0.55, 0.6, 0.75, 0.9, 1.0):
        esperado = {
            c: p * xp_continuo(brier_score(Call.MALICIOUS, c, GroundTruth.MALICIOUS))
            + (1 - p) * xp_continuo(brier_score(Call.MALICIOUS, c, GroundTruth.BENIGN))
            for c in range(50, 101)
        }
        optimo = max(esperado, key=esperado.get)
        assert optimo == round(p * 100), (
            f"con creencia {p:.0%} conviene declarar {optimo}%: "
            "la regla dejó de ser propia"
        )


def test_el_redondeo_a_xp_entera_no_hace_rentable_mentir():
    """El redondeo introduce ruido, pero no una estrategia.

    Declarar la creencia real tiene que quedar a lo sumo 1 XP del máximo
    alcanzable. Un margen mayor sería una ventaja explotable.
    """
    for p in (0.55, 0.6, 0.75, 0.9):
        esperado = {
            c: p
            * xp_from_brier(brier_score(Call.MALICIOUS, c, GroundTruth.MALICIOUS), 100)
            + (1 - p)
            * xp_from_brier(brier_score(Call.MALICIOUS, c, GroundTruth.BENIGN), 100)
            for c in range(50, 101)
        }
        ventaja = max(esperado.values()) - esperado[round(p * 100)]
        assert (
            ventaja <= 1
        ), f"con creencia {p:.0%}, mentir rinde {ventaja:.2f} XP extra"


def test_calibracion_y_sobreconfianza():
    assert calibration_score([0.0, 0.0]) == 1.0
    assert calibration_score([]) is None
    # Declara 90% de confianza pero acierta la mitad: cree saber más.
    assert overconfidence([90, 90], [True, False]) == pytest.approx(0.4)
    # Declara 60% y acierta el 60%: bien calibrado.
    assert overconfidence([60] * 10, [True] * 6 + [False] * 4) == pytest.approx(0.0)


# ══════════════════════════════════════════════════════════════════════
#  Flujo completo por HTTP
# ══════════════════════════════════════════════════════════════════════


def _mision_con(client, ground_truth: str) -> str:
    """Busca en el catálogo una misión con la verdad de referencia pedida."""
    from stix_feed import full_catalog

    return next(
        m["mission_id"] for m in full_catalog() if m["ground_truth"] == ground_truth
    )


def test_veredicto_correcto_con_certeza_otorga_el_maximo(client, token_for):
    mid = _mision_con(client, "MALICIOUS")
    r = client.post(
        f"/api/v1/missions/{mid}/verdict",
        json={
            "call": "MALICIOUS",
            "confidence": 100,
            "rationale": "Corroborado por múltiples fuentes independientes.",
        },
        headers=token_for("test-ver-acierto"),
    )
    assert r.status_code == 200
    body = r.json()
    assert body["graded"] is True
    assert body["was_correct"] is True
    assert body["brier_score"] == 0.0
    assert body["xp_awarded"] > 0


def test_veredicto_equivocado_con_certeza_resta(client, token_for):
    """El caso que el sistema existe para castigar."""
    callsign = "test-ver-error"
    mid = _mision_con(client, "BENIGN")
    # Primero acumula saldo, para que el piso en cero no oculte el descuento.
    client.post(
        "/api/v1/level-up",
        json={"event": "campaign_attributed", "severity": "critical"},
        headers=token_for(callsign),
    )
    antes = client.get(f"/api/v1/analysts/{callsign}").json()["xp"]

    body = client.post(
        f"/api/v1/missions/{mid}/verdict",
        json={
            "call": "MALICIOUS",
            "confidence": 100,
            "rationale": "Estoy segurísimo, el patrón de balizas es de C2.",
        },
        headers=token_for(callsign),
    ).json()

    assert body["was_correct"] is False
    assert body["xp_awarded"] < 0
    assert client.get(f"/api/v1/analysts/{callsign}").json()["xp"] < antes


def test_no_se_puede_reescribir_un_veredicto(client, token_for):
    """Corregir después de ver el resultado no es análisis."""
    mid = _mision_con(client, "MALICIOUS")
    cabeceras = token_for("test-ver-unico")
    payload = {"call": "BENIGN", "confidence": 70}
    assert (
        client.post(
            f"/api/v1/missions/{mid}/verdict", json=payload, headers=cabeceras
        ).status_code
        == 200
    )

    segundo = client.post(
        f"/api/v1/missions/{mid}/verdict",
        json={
            **payload,
            "call": "MALICIOUS",
            "confidence": 100,
            "rationale": "me arrepentí",
        },
        headers=cabeceras,
    )
    assert segundo.status_code == 409


def test_certeza_alta_exige_fundamento(client, token_for):
    mid = _mision_con(client, "MALICIOUS")
    r = client.post(
        f"/api/v1/missions/{mid}/verdict",
        json={"call": "MALICIOUS", "confidence": 95},
        headers=token_for("test-ver-sinfund"),
    )
    assert r.status_code == 422
    assert "fundamento" in r.json()["detail"]


def test_confianza_fuera_de_rango_es_rechazada(client, token_for):
    """Por debajo de 50 el veredicto se contradice a sí mismo."""
    mid = _mision_con(client, "MALICIOUS")
    for conf in (30, 49, 101):
        r = client.post(
            f"/api/v1/missions/{mid}/verdict",
            json={"call": "MALICIOUS", "confidence": conf},
            headers=token_for("test-ver-rango"),
        )
        assert r.status_code == 422


def test_mision_inexistente(client, token_for):
    r = client.post(
        "/api/v1/missions/MSN-NOEXISTE/verdict",
        json={"call": "BENIGN", "confidence": 60},
        headers=token_for("test-ver-404"),
    )
    assert r.status_code == 404


# ══════════════════════════════════════════════════════════════════════
#  Corroboración diferida
# ══════════════════════════════════════════════════════════════════════


def test_apuesta_a_ciegas_y_calificacion_diferida(client, token_for, instructor_token):
    """El corazón pedagógico: decidir sin saber, y que el tiempo te juzgue."""
    mid = _mision_con(client, "UNKNOWN")
    callsign = "test-ver-diferido"

    sellado = client.post(
        f"/api/v1/missions/{mid}/verdict",
        json={
            "call": "MALICIOUS",
            "confidence": 70,
            "rationale": "Dominio nuevo y ASN con antecedentes.",
        },
        headers=token_for(callsign),
    ).json()

    assert sellado["graded"] is False
    assert sellado["xp_awarded"] == 0
    assert sellado["ground_truth"] is None

    cal = client.get(f"/api/v1/analysts/{callsign}/calibration").json()
    assert cal["verdicts_pending"] == 1
    assert cal["verdicts_graded"] == 0

    # Pasadas las 72 h, la corroboración cierra.
    resuelta = client.post(
        f"/api/v1/missions/{mid}/resolve",
        json={"ground_truth": "MALICIOUS", "truth_source": "CORROBORATION"},
        headers=instructor_token,
    ).json()
    assert resuelta["verdicts_graded"] >= 1

    cal = client.get(f"/api/v1/analysts/{callsign}/calibration").json()
    assert cal["verdicts_graded"] == 1
    assert cal["verdicts_pending"] == 0
    assert cal["accuracy"] == 1.0
    assert client.get(f"/api/v1/analysts/{callsign}").json()["xp"] > 0


def test_veredicto_tardio_no_puntua(client, token_for, instructor_token):
    """Esperar a que la verdad sea pública no mide criterio."""
    mid = _mision_con(client, "UNKNOWN")
    # La misión ya fue resuelta por el test anterior o se resuelve acá.
    client.post(
        f"/api/v1/missions/{mid}/resolve",
        json={"ground_truth": "MALICIOUS", "truth_source": "CORROBORATION"},
        headers=instructor_token,
    )
    body = client.post(
        f"/api/v1/missions/{mid}/verdict",
        json={"call": "MALICIOUS", "confidence": 100, "rationale": "Leí la respuesta."},
        headers=token_for("test-ver-tardio"),
    ).json()
    assert body["graded"] is False
    assert body["xp_awarded"] == 0
    assert "TÉRMINO" in body["message"]


def test_no_se_puede_cambiar_una_verdad_ya_fijada(client, token_for, instructor_token):
    """Cambiar las reglas después de que la gente apostó."""
    mid = _mision_con(client, "MALICIOUS")
    r = client.post(
        f"/api/v1/missions/{mid}/resolve",
        json={"ground_truth": "BENIGN", "truth_source": "CURATED"},
        headers=instructor_token,
    )
    assert r.status_code == 409


# ══════════════════════════════════════════════════════════════════════
#  Catálogo
# ══════════════════════════════════════════════════════════════════════


def test_el_catalogo_tiene_verdades_de_ambos_signos():
    """Sin misiones BENIGN, "decir siempre MALICIOSO" sería estrategia ganadora.

    Este test protege la propiedad que hace que el sistema mida criterio y no
    obediencia.
    """
    from stix_feed import full_catalog

    verdades = {m["ground_truth"] for m in full_catalog()}
    assert "MALICIOUS" in verdades
    assert "BENIGN" in verdades, "sin verdad benigna el sistema es trivial de ganar"
    assert "UNKNOWN" in verdades, "sin ambigüedad no hay corroboración diferida"


def test_toda_mision_declara_las_señales_de_ingesta():
    """Contrato para los conectores de la Etapa 4."""
    from stix_feed import full_catalog

    for m in full_catalog():
        assert m["independent_sources"] >= 1
        assert 0 <= m["source_confidence"] <= 100
        assert isinstance(m["kev_listed"], bool)
