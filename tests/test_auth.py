"""
ATALAYA // Tests de identidad.

El test que justifica toda la etapa es `test_no_puedo_otorgarme_xp_como_otro`:
mientras el callsign viajaba en el cuerpo de la petición, cualquiera podía
ascenderse solo —o vaciarle la XP a otro— con un `curl`. Todo lo demás de
este archivo protege esa corrección.
"""

import pytest

from auth import (
    MIN_PASSWORD_LENGTH,
    AuthError,
    Role,
    decode_access_token,
    hash_password,
    issue_access_token,
    validate_password,
    verify_password,
)

CLAVE = "frase-larga-de-prueba-atalaya-2026"
SECRETO = "s" * 64


# ══════════════════════════════════════════════════════════════════════
#  Criptografía (pura)
# ══════════════════════════════════════════════════════════════════════


def test_argon2id_y_no_bcrypt():
    """bcrypt trunca en 72 bytes sin avisar. Argon2id no."""
    h = hash_password(CLAVE)
    assert h.startswith("$argon2id$")
    assert verify_password(CLAVE, h)
    assert not verify_password(CLAVE + "x", h)


def test_dos_hashes_de_la_misma_clave_difieren():
    """Salt por hash: dos cuentas con la misma contraseña no se delatan."""
    assert hash_password(CLAVE) != hash_password(CLAVE)


def test_verificar_contra_cuenta_inexistente_no_explota():
    """El señuelo hace que el login tarde lo mismo exista o no la cuenta."""
    assert verify_password(CLAVE, None) is False


def test_politica_de_contrasena():
    with pytest.raises(AuthError):
        validate_password("corta", "gon")
    with pytest.raises(AuthError):
        validate_password("gon-" + "x" * 20, "gon")  # contiene el callsign
    validate_password("a" * MIN_PASSWORD_LENGTH, "gon")


def test_token_firmado_con_otra_clave_es_rechazado():
    import uuid

    token, _ = issue_access_token(SECRETO, uuid.uuid4(), "gon", Role.ANALYST)
    assert decode_access_token(SECRETO, token).callsign == "gon"
    with pytest.raises(AuthError):
        decode_access_token("o" * 64, token)


def test_token_manipulado_es_rechazado():
    """Cambiar el rol en el payload invalida la firma."""
    import base64
    import json
    import uuid

    token, _ = issue_access_token(SECRETO, uuid.uuid4(), "gon", Role.ANALYST)
    cabecera, carga, firma = token.split(".")
    datos = json.loads(base64.urlsafe_b64decode(carga + "=="))
    datos["role"] = "ADMIN"
    falsa = base64.urlsafe_b64encode(json.dumps(datos).encode()).decode().rstrip("=")
    with pytest.raises(AuthError):
        decode_access_token(SECRETO, f"{cabecera}.{falsa}.{firma}")


# ══════════════════════════════════════════════════════════════════════
#  EL test de la etapa
# ══════════════════════════════════════════════════════════════════════


def test_no_puedo_otorgarme_xp_como_otro(client, token_for):
    """La vulnerabilidad que esta etapa vino a cerrar.

    Antes bastaba con poner el callsign ajeno en el cuerpo. Ahora la
    identidad sale del token, así que mandar un callsign es, literalmente,
    mandar un campo que nadie lee.
    """
    victima, atacante = "test-auth-victima", "test-auth-atacante"
    token_for(victima)

    antes = client.get(f"/api/v1/analysts/{victima}").json()["xp"]

    respuesta = client.post(
        "/api/v1/level-up",
        json={
            "callsign": victima,  # ← ignorado por completo
            "event": "campaign_attributed",
            "severity": "critical",
        },
        headers=token_for(atacante),
    ).json()

    assert respuesta["callsign"] == atacante, "la XP fue a parar al atacante"
    assert client.get(f"/api/v1/analysts/{victima}").json()["xp"] == antes


def test_no_puedo_restarle_xp_a_otro(client, token_for):
    """La cara inversa: tampoco se puede sabotear a un tercero."""
    victima, atacante = "test-auth-victima2", "test-auth-atacante2"
    client.post(
        "/api/v1/level-up",
        json={"event": "campaign_attributed", "severity": "critical"},
        headers=token_for(victima),
    )
    antes = client.get(f"/api/v1/analysts/{victima}").json()["xp"]
    assert antes > 0

    for _ in range(3):
        client.post(
            "/api/v1/level-up",
            json={"callsign": victima, "event": "false_positive_published"},
            headers=token_for(atacante),
        )
    assert client.get(f"/api/v1/analysts/{victima}").json()["xp"] == antes


@pytest.mark.parametrize(
    "metodo,ruta,cuerpo",
    [
        ("post", "/api/v1/level-up", {"event": "mission_triage"}),
        (
            "post",
            "/api/v1/missions/MSN-E869F7A7/verdict",
            {"call": "BENIGN", "confidence": 60},
        ),
        (
            "post",
            "/api/v1/missions/MSN-E869F7A7/resolve",
            {"ground_truth": "BENIGN", "truth_source": "CURATED"},
        ),
        ("get", "/api/v1/auth/me", None),
        ("post", "/api/v1/auth/logout", None),
    ],
)
def test_sin_token_no_se_pasa(client, metodo, ruta, cuerpo):
    """Todo lo que muta estado exige sesión."""
    res = getattr(client, metodo)(ruta, **({"json": cuerpo} if cuerpo else {}))
    assert res.status_code == 401, f"{ruta} respondió {res.status_code}"


def test_el_feed_sigue_siendo_publico(client):
    """Mirar no requiere cuenta. Operar, sí."""
    res = client.get("/api/v1/feed?limit=3")
    assert res.status_code == 200
    assert res.json()["viewer_rank"] == "NOVATO"


# ══════════════════════════════════════════════════════════════════════
#  Roles
# ══════════════════════════════════════════════════════════════════════


def test_un_analista_no_puede_fijar_la_verdad(client, token_for):
    """Quien fija la verdad decide quién gana XP. No es para cualquiera."""
    res = client.post(
        "/api/v1/missions/MSN-D46B6B85/resolve",
        json={"ground_truth": "BENIGN", "truth_source": "CURATED"},
        headers=token_for("test-auth-simple"),
    )
    assert res.status_code == 403
    assert "INSTRUCTOR" in res.json()["detail"]


def test_el_rol_no_se_puede_declarar_en_el_alta(client):
    """Registrarse pidiendo ser ADMIN no debe conceder nada."""
    res = client.post(
        "/api/v1/auth/register",
        json={
            "callsign": "test-auth-ambicioso",
            "password": CLAVE,
            "role": "ADMIN",
            "is_active": True,
        },
    )
    client.cookies.clear()
    assert res.status_code == 201
    assert res.json()["role"] == "ANALYST"


# ══════════════════════════════════════════════════════════════════════
#  Ciclo de vida de la sesión
# ══════════════════════════════════════════════════════════════════════


def test_alta_login_y_me(client):
    payload = {"callsign": "test-auth-ciclo", "password": CLAVE}
    alta = client.post("/api/v1/auth/register", json=payload)
    client.cookies.clear()
    assert alta.status_code == 201

    login = client.post("/api/v1/auth/login", json=payload)
    assert login.status_code == 200
    token = {"Authorization": f"Bearer {login.json()['access_token']}"}
    client.cookies.clear()

    yo = client.get("/api/v1/auth/me", headers=token).json()
    assert yo["callsign"] == "test-auth-ciclo"
    assert yo["role"] == "ANALYST"
    assert yo["active_sessions"] >= 1


def test_las_cookies_de_sesion_son_httponly_y_samesite(client):
    """Un token accesible desde JavaScript es un token que un XSS se lleva."""
    client.cookies.clear()
    res = client.post(
        "/api/v1/auth/register",
        json={"callsign": "test-auth-cookies", "password": CLAVE},
    )
    # get_list y no items(): httpx colapsa las cabeceras repetidas en una
    # sola cadena separada por comas, y ahí se pierde cuál es cuál.
    cookies = res.headers.get_list("set-cookie")
    client.cookies.clear()

    acceso = next(c for c in cookies if c.startswith("atalaya_access"))
    refresco = next(c for c in cookies if c.startswith("atalaya_refresh"))

    for cookie in (acceso, refresco):
        assert "HttpOnly" in cookie
        assert "SameSite=strict" in cookie.replace("samesite", "SameSite")

    # El refresh sólo viaja al endpoint que lo necesita.
    assert "Path=/api/v1/auth" in refresco


def test_callsign_o_clave_incorrectos_dan_el_mismo_mensaje(client):
    """Distinguirlos sería un oráculo para enumerar cuentas."""
    client.post(
        "/api/v1/auth/register",
        json={"callsign": "test-auth-oraculo", "password": CLAVE},
    )
    client.cookies.clear()

    inexistente = client.post(
        "/api/v1/auth/login", json={"callsign": "no-existe-jamas", "password": CLAVE}
    )
    mala_clave = client.post(
        "/api/v1/auth/login",
        json={"callsign": "test-auth-oraculo", "password": "otra-cosa-larguisima"},
    )
    assert inexistente.status_code == mala_clave.status_code == 401
    assert inexistente.json()["detail"] == mala_clave.json()["detail"]


def test_callsign_tomado(client):
    payload = {"callsign": "test-auth-repetido", "password": CLAVE}
    assert client.post("/api/v1/auth/register", json=payload).status_code == 201
    client.cookies.clear()
    assert client.post("/api/v1/auth/register", json=payload).status_code == 409
    client.cookies.clear()


def test_bloqueo_por_intentos_fallidos(client):
    """Cinco intentos y la cuenta queda bloqueada un rato."""
    client.cookies.clear()
    payload = {"callsign": "test-auth-bloqueo", "password": CLAVE}
    client.post("/api/v1/auth/register", json=payload)
    client.cookies.clear()

    for _ in range(5):
        client.post(
            "/api/v1/auth/login",
            json={"callsign": payload["callsign"], "password": "clave-equivocada-x"},
        )

    # Ahora ni siquiera la contraseña correcta entra.
    res = client.post("/api/v1/auth/login", json=payload)
    assert res.status_code == 401
    assert "bloqueada" in res.json()["detail"].lower()


def test_rotacion_de_refresh_y_deteccion_de_reuso(client):
    """Reusar un refresh ya rotado revoca la familia entera.

    Si un token rotado vuelve a aparecer, o alguien clonó la sesión o el
    cliente falló. Ante la duda se cierra todo: molestar con un login nuevo
    es barato; dejar viva una sesión robada, no se arregla después.
    """
    client.cookies.clear()
    payload = {"callsign": "test-auth-rotacion", "password": CLAVE}
    alta = client.post("/api/v1/auth/register", json=payload)
    primero = alta.cookies["atalaya_refresh"]

    # Se manda la cookie explícita en cada petición en vez de confiar en el
    # frasco del cliente: al rotar quedan varias con el mismo nombre y httpx
    # no sabe cuál mandar.
    client.cookies.clear()
    client.cookies.set("atalaya_refresh", primero)
    renovado = client.post("/api/v1/auth/refresh")
    assert renovado.status_code == 200
    segundo = renovado.cookies["atalaya_refresh"]
    assert segundo != primero, "el refresh tiene que rotar en cada uso"

    # Reutilizar el viejo: debe cerrar todo.
    client.cookies.clear()
    client.cookies.set("atalaya_refresh", primero)
    reuso = client.post("/api/v1/auth/refresh")
    assert reuso.status_code == 401
    assert "seguridad" in reuso.json()["detail"].lower()

    # Y el nuevo tampoco sirve ya: la familia entera quedó revocada.
    client.cookies.clear()
    client.cookies.set("atalaya_refresh", segundo)
    assert client.post("/api/v1/auth/refresh").status_code == 401
    client.cookies.clear()


def test_logout_revoca_del_lado_del_servidor(client):
    """Borrar la cookie no alcanza: el token tiene que quedar inservible."""
    client.cookies.clear()
    payload = {"callsign": "test-auth-logout", "password": CLAVE}
    alta = client.post("/api/v1/auth/register", json=payload)
    token = {"Authorization": f"Bearer {alta.json()['access_token']}"}
    refresh = alta.cookies["atalaya_refresh"]

    client.cookies.clear()
    client.cookies.set("atalaya_refresh", refresh)
    assert client.post("/api/v1/auth/logout", headers=token).status_code == 200

    client.cookies.clear()
    client.cookies.set("atalaya_refresh", refresh)
    assert client.post("/api/v1/auth/refresh").status_code == 401
    client.cookies.clear()


def test_leer_un_analista_inexistente_no_lo_crea(client):
    """Antes, un GET daba de alta. Era una forma barata de llenar la tabla."""
    assert client.get("/api/v1/analysts/fantasma-que-no-existe").status_code == 404
    assert (
        client.get("/api/v1/analysts/fantasma-que-no-existe/calibration").status_code
        == 404
    )
