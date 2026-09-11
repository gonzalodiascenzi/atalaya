"""
ATALAYA // Limitador de tasa por IP.

El techo se baja a 3 pedidos sólo dentro de cada test (el resto de la suite
corre con el límite alto de conftest) y los cubos arrancan vacíos.
"""

from collections import defaultdict, deque

import pytest

CABECERA = "x-atalaya-ip"


@pytest.fixture
def limitador(client, monkeypatch):
    """Devuelve una función para fijar la cabecera de IP confiable.

    `main` se importa acá adentro y no arriba de todo: importarlo durante la
    colección cachea la configuración ANTES de que conftest apunte la API a
    la base de pruebas, y toda la suite termina hablándole a otra base.
    """
    import main

    monkeypatch.setattr(main, "_RATE_LIMIT", 3)
    monkeypatch.setattr(main, "_RATE_BUCKETS", defaultdict(deque))
    monkeypatch.setattr(main, "_CLIENT_IP_HEADER", "")
    return lambda cabecera: monkeypatch.setattr(main, "_CLIENT_IP_HEADER", cabecera)


def _pedidos(client, n, headers_de=lambda i: {}):
    return [client.get("/health", headers=headers_de(i)).status_code for i in range(n)]


def test_el_cuarto_pedido_se_corta_con_429(client, limitador):
    assert _pedidos(client, 4) == [200, 200, 200, 429]
    r = client.get("/health")
    assert r.json()["error"] == "rate_limited"
    assert r.headers["Retry-After"] == "60"


def test_rotar_x_forwarded_for_no_saltea_el_limite(client, limitador):
    """El ataque real contra la Function URL: una IP inventada por pedido.

    Lambda deja en X-Forwarded-For sólo el valor que escribe el cliente. Si el
    limitador lo usara, cada pedido caería en un cubo nuevo y nunca cortaría.
    """
    limitador(CABECERA)

    def falsos(i):
        return {CABECERA: "198.51.100.7", "X-Forwarded-For": f"203.0.113.{i}"}

    assert _pedidos(client, 4, falsos) == [200, 200, 200, 429]


def test_cada_ip_real_tiene_su_propio_cubo(client, limitador):
    limitador(CABECERA)
    assert _pedidos(client, 3, lambda i: {CABECERA: "198.51.100.7"}) == [200] * 3
    assert client.get("/health", headers={CABECERA: "198.51.100.8"}).status_code == 200


def test_sin_la_cabecera_se_limita_mas_no_menos(client, limitador):
    """Si falta la IP confiable, todos esos pedidos comparten UN cubo."""
    limitador(CABECERA)
    assert _pedidos(client, 4) == [200, 200, 200, 429]
