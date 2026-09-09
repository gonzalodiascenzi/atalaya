"""ATALAYA // Tests del conector de ingesta MISP → STIX 2.1."""

from misp_stix_connector import build_ransomware_bundle, defang, validate_bundle


def test_el_bundle_de_referencia_es_valido():
    errores = validate_bundle(build_ransomware_bundle())
    assert errores == [], f"El bundle canónico dejó de ser válido: {errores}"


def test_contiene_el_grafo_pedido():
    """Attack Pattern ← Malware ← Indicator de IP: el requisito del proyecto."""
    bundle = build_ransomware_bundle()
    por_tipo = {o["type"]: o for o in bundle["objects"]}

    assert (
        por_tipo["attack-pattern"]["external_references"][0]["external_id"] == "T1486"
    )
    assert por_tipo["malware"]["is_family"] is True
    assert "ransomware" in por_tipo["malware"]["malware_types"]
    assert por_tipo["indicator"]["pattern"].startswith("[ipv4-addr:value =")

    rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
    tipos = {r["relationship_type"] for r in rels}
    assert {"indicates", "uses"} <= tipos


def test_ids_deterministas():
    """Dos corridas deben producir los mismos IDs: ingesta idempotente."""
    a = build_ransomware_bundle()
    b = build_ransomware_bundle()

    ids_a = {o["id"] for o in a["objects"] if o["type"] != "bundle"}
    ids_b = {o["id"] for o in b["objects"] if o["type"] != "bundle"}
    assert ids_a == ids_b
    # El ID del bundle sí cambia: cada envío es un envío distinto.
    assert a["id"] != b["id"]


def test_ningun_objeto_lleva_propiedades_nulas():
    for obj in build_ransomware_bundle()["objects"]:
        assert all(v is not None for v in obj.values()), obj["id"]


def test_el_validador_detecta_un_bundle_roto():
    bundle = build_ransomware_bundle()
    # Rompemos una referencia a propósito.
    for obj in bundle["objects"]:
        if obj["type"] == "relationship":
            obj["target_ref"] = "malware--00000000-0000-4000-a000-000000000000"
            break
    errores = validate_bundle(bundle)
    assert any("colgada" in e for e in errores)


def test_defang_neutraliza():
    assert defang("http://malo.com") == "hxxp://malo[.]com"
    assert defang("198.51.100.42") == "198[.]51[.]100[.]42"
