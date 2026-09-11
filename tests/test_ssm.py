"""
ATALAYA // Secretos desde SSM Parameter Store.

En Lambda, las variables de entorno sólo traen el NOMBRE del parámetro; el
valor se lee al arrancar. Estos tests usan un cliente falso: sin red y sin
boto3 real. Los valores son inventados y no tienen forma de credencial.
"""

import os

import pytest

from config import load_ssm_secrets


class SSMFalso:
    def __init__(self, valores, invalidos=()):
        self.valores = valores
        self.invalidos = list(invalidos)
        self.pedidos = []

    def get_parameters(self, Names, WithDecryption):
        self.pedidos.append((list(Names), WithDecryption))
        return {
            "Parameters": [
                {"Name": n, "Value": self.valores[n]}
                for n in Names
                if n in self.valores
            ],
            "InvalidParameters": self.invalidos,
        }


@pytest.fixture
def entorno_limpio(monkeypatch):
    for var in ("DATABASE_URL_SSM", "API_SECRET_KEY_SSM"):
        monkeypatch.delenv(var, raising=False)
    # Se restauran solas al terminar el test: monkeypatch las recuerda.
    monkeypatch.setenv("DATABASE_URL", "valor-local")
    monkeypatch.setenv("API_SECRET_KEY", "valor-local")
    return monkeypatch


def test_sin_variables_ssm_no_hace_nada(entorno_limpio):
    """Localmente no se toca el entorno ni se importa boto3."""
    cliente = SSMFalso({})
    assert load_ssm_secrets(cliente) == []
    assert cliente.pedidos == []
    assert os.environ["DATABASE_URL"] == "valor-local"


def test_completa_el_entorno_con_lo_que_lee(entorno_limpio):
    entorno_limpio.setenv("DATABASE_URL_SSM", "/atalaya/prod/database-url")
    entorno_limpio.setenv("API_SECRET_KEY_SSM", "/atalaya/prod/api-secret-key")
    cliente = SSMFalso(
        {
            "/atalaya/prod/database-url": "valor-de-la-base",
            "/atalaya/prod/api-secret-key": "valor-de-la-clave",
        }
    )

    completadas = load_ssm_secrets(cliente)

    assert sorted(completadas) == ["API_SECRET_KEY", "DATABASE_URL"]
    assert os.environ["DATABASE_URL"] == "valor-de-la-base"
    assert os.environ["API_SECRET_KEY"] == "valor-de-la-clave"


def test_pide_todo_en_una_sola_llamada_y_descifrado(entorno_limpio):
    """Una llamada, no dos: el arranque en frío de Lambda se paga por cada ida y vuelta."""
    entorno_limpio.setenv("DATABASE_URL_SSM", "/a")
    entorno_limpio.setenv("API_SECRET_KEY_SSM", "/b")
    cliente = SSMFalso({"/a": "x", "/b": "y"})

    load_ssm_secrets(cliente)

    assert len(cliente.pedidos) == 1
    nombres, descifrar = cliente.pedidos[0]
    assert sorted(nombres) == ["/a", "/b"]
    assert descifrar is True  # SecureString sin descifrar = texto cifrado como clave


def test_un_parametro_que_falta_impide_arrancar(entorno_limpio):
    """Arrancar sin la clave de firma, o con la de desarrollo, es peor que no arrancar."""
    entorno_limpio.setenv("API_SECRET_KEY_SSM", "/no-existe")
    cliente = SSMFalso({}, invalidos=["/no-existe"])

    with pytest.raises(RuntimeError, match="/no-existe"):
        load_ssm_secrets(cliente)
    assert os.environ["API_SECRET_KEY"] == "valor-local"


def test_solo_pide_los_declarados(entorno_limpio):
    entorno_limpio.setenv("DATABASE_URL_SSM", "/solo-la-base")
    cliente = SSMFalso({"/solo-la-base": "z"})

    assert load_ssm_secrets(cliente) == ["DATABASE_URL"]
    assert cliente.pedidos[0][0] == ["/solo-la-base"]
    assert os.environ["API_SECRET_KEY"] == "valor-local"
