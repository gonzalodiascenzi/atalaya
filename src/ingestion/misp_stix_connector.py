#!/usr/bin/env python3
"""
ATALAYA // Conector de referencia MISP → STIX 2.1
=================================================

Genera un **bundle STIX 2.1 puro** (JSON, sin dependencias externas) que
modela un caso real de ransomware, con el grafo mínimo que cualquier
plataforma de CTI seria espera recibir:

    Indicator (IP del C2)  ──indicates──▶  Malware (Akira, ransomware)
                                                │
                                                └──uses──▶  Attack Pattern
                                                            (T1486 · Data
                                                             Encrypted for Impact)

Y alrededor, lo que separa un JSON de juguete de inteligencia utilizable:

    * `Identity`  — quién produjo esto (procedencia).
    * `object_marking_refs` — bajo qué TLP se puede compartir.
    * `Infrastructure` — el activo del adversario, no sólo el observable.
    * `Observed-data` + SCO `ipv4-addr` — el hecho crudo detrás del indicador.
    * IDs deterministas (UUIDv5) — reingerir dos veces no duplica el grafo.

Por qué está escrito sólo con la librería estándar
--------------------------------------------------
Este archivo es el **contrato canónico** del proyecto: cualquiera tiene que
poder ejecutarlo en un contenedor pelado, sin `pip install`, y ver exactamente
la forma de los datos que viajan por el sistema. Los conectores que hablan con
las APIs reales (OTX, ThreatFox, CISA KEV, MISP) sí usan `pymisp`/`pycti`, y
todos emiten con esta misma estructura.

Uso
---
    python3 misp_stix_connector.py                 # bundle compacto a stdout
    python3 misp_stix_connector.py --pretty        # legible por humanos
    python3 misp_stix_connector.py --validate      # valida y reporta
    python3 misp_stix_connector.py -o caso.json    # escribe a archivo
    python3 misp_stix_connector.py --push          # empuja a OpenCTI (necesita pycti)

Referencias
-----------
    STIX 2.1 (OASIS): https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
    MITRE ATT&CK T1486: https://attack.mitre.org/techniques/T1486/
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

# ══════════════════════════════════════════════════════════════════════
#  1. CONSTANTES DEL PRODUCTOR
# ══════════════════════════════════════════════════════════════════════

#: Namespace propio para derivar UUIDv5. La spec sugiere UUIDv4 para SDOs,
#: pero un conector que genera IDs aleatorios crea un objeto nuevo en cada
#: corrida y termina inflando el grafo con duplicados. UUIDv5 sobre una clave
#: estable (el patrón del indicador, el nombre de la familia) hace la ingesta
#: idempotente, que es lo que realmente querés en producción.
ATALAYA_NAMESPACE = uuid.UUID("6ba7b812-9dad-11d1-80b4-00c04fd430c8")

#: IDs canónicos de las marcas TLP, definidos por la propia spec STIX 2.1.
#: Se referencian por ID: toda plataforma (OpenCTI, MISP, Anomali) ya los tiene
#: precargados, así que no hace falta embeberlos en el bundle.
#: Nota histórica: la spec sigue llamándolo "TLP:WHITE"; TLP 2.0 lo renombró
#: a TLP:CLEAR, pero el objeto de marcado es el mismo.
#: Semilla de la identidad que firma lo que publicamos. Se exporta para que
#: los conectores reales usen exactamente el mismo `created_by_ref` y no
#: aparezcan tres autores distintos para la misma organización.
ATALAYA_IDENTITY_SEED = "atalaya-cti-ops"

TLP_CLEAR = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
TLP_GREEN = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
TLP_AMBER = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
TLP_RED = "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"

#: Tipos STIX que este conector sabe emitir (usado por el validador).
KNOWN_SDO_TYPES = {
    "attack-pattern",
    "identity",
    "indicator",
    "infrastructure",
    "malware",
    "observed-data",
    "relationship",
    "ipv4-addr",
}

#: Propiedades obligatorias por tipo, según STIX 2.1.
REQUIRED_PROPS: dict[str, set[str]] = {
    "indicator": {"pattern", "pattern_type", "valid_from", "spec_version", "created"},
    "malware": {"is_family", "spec_version", "created"},
    "attack-pattern": {"name", "spec_version", "created"},
    "identity": {"name", "spec_version", "created"},
    "infrastructure": {"name", "spec_version", "created"},
    "observed-data": {
        "first_observed",
        "last_observed",
        "number_observed",
        "spec_version",
    },
    "relationship": {"relationship_type", "source_ref", "target_ref", "spec_version"},
}

#: El caso que modelamos. Los IoCs son sintéticos a propósito: la IP pertenece
#: a 198.51.100.0/24 (TEST-NET-2, reservada por RFC 5737) y el dominio a
#: `.example` (RFC 2606). Si alguien copia esto a un firewall no bloquea
#: infraestructura de un tercero real. La familia de malware y la técnica
#: ATT&CK, en cambio, son reales: ahí está el valor didáctico.
CASE = {
    "name": "Akira",
    "aliases": ["Akira Ransomware", "Megazord"],
    "c2_ip": "198.51.100.42",
    "c2_port": 443,
    "attack_id": "T1486",
    "attack_name": "Data Encrypted for Impact",
    "tactic": "impact",
    "tlp": TLP_AMBER,
    "misp_event_id": "1478",
    "misp_event_uuid": "5f8a1c3e-0e2d-4c8a-9a1e-7b3d2f0c9e14",
}


# ══════════════════════════════════════════════════════════════════════
#  2. UTILIDADES
# ══════════════════════════════════════════════════════════════════════


def stix_id(stix_type: str, seed: str) -> str:
    """Construye un ID STIX determinista.

    El mismo `seed` produce siempre el mismo ID, de modo que reingerir el
    mismo indicador actualiza el objeto existente en lugar de crear otro.
    """
    return f"{stix_type}--{uuid.uuid5(ATALAYA_NAMESPACE, f'{stix_type}:{seed}')}"


def ts(offset_minutes: int = 0) -> str:
    """Timestamp en el formato exacto que pide STIX: UTC, sufijo Z, milisegundos.

    Ojo con `datetime.isoformat()`: produce `+00:00` y microsegundos, y hay
    validadores estrictos que lo rechazan.
    """
    moment = datetime.now(timezone.utc) + timedelta(minutes=offset_minutes)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def defang(value: str) -> str:
    """Neutraliza un observable para mostrarlo sin riesgo de click accidental."""
    return value.replace("http", "hxxp").replace(".", "[.]")


# ══════════════════════════════════════════════════════════════════════
#  3. CONSTRUCCIÓN DEL BUNDLE
# ══════════════════════════════════════════════════════════════════════


def build_ransomware_bundle(case: dict[str, Any] | None = None) -> dict[str, Any]:
    """Arma el bundle STIX 2.1 completo del caso de ransomware.

    Devuelve un dict serializable directamente con `json.dumps`. Cada bloque
    va comentado con el porqué de las propiedades no obvias.
    """
    case = case or CASE
    created = ts()
    tlp = case["tlp"]

    # ── 3.1 Identity: quién firma esta inteligencia ───────────────────
    # Sin procedencia, un IoC es un rumor. `created_by_ref` apunta acá desde
    # todos los objetos del bundle.
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": stix_id("identity", ATALAYA_IDENTITY_SEED),
        "created": created,
        "modified": created,
        "name": "ATALAYA CTI Ops",
        "description": "Torre de vigilancia y academia táctica de Threat Intelligence.",
        "identity_class": "organization",
        "sectors": ["technology"],
        "contact_information": "cti@atalaya.localhost",
    }
    author = identity["id"]

    # Propiedades que repiten todos los SDO. Se factorizan para que el bundle
    # sea consistente y no se escape ningún objeto sin marcado TLP.
    common = {
        "spec_version": "2.1",
        "created": created,
        "modified": created,
        "created_by_ref": author,
        "object_marking_refs": [tlp],
    }

    # ── 3.2 Attack Pattern: el CÓMO (MITRE ATT&CK) ────────────────────
    # `external_references` con source_name "mitre-attack" es lo que permite
    # que OpenCTI deduplique contra su base de ATT&CK en vez de crear una
    # técnica huérfana.
    attack_pattern = {
        "type": "attack-pattern",
        "id": stix_id("attack-pattern", case["attack_id"]),
        **common,
        "name": case["attack_name"],
        "description": (
            "El adversario cifra datos en los sistemas objetivo para "
            "interrumpir la disponibilidad. En operaciones de ransomware "
            "moderno se combina con exfiltración previa (doble extorsión) "
            "para sostener la presión aun cuando existan backups."
        ),
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": case["attack_id"],
                "url": f"https://attack.mitre.org/techniques/{case['attack_id']}/",
            }
        ],
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack", "phase_name": case["tactic"]}
        ],
        "x_mitre_platforms": ["Windows", "Linux", "ESXi"],
    }

    # ── 3.3 Malware: el QUÉ ───────────────────────────────────────────
    # `is_family` es OBLIGATORIO en STIX 2.1 (fue el cambio más ruidoso
    # respecto de 2.0). True = familia; False = una muestra concreta.
    malware = {
        "type": "malware",
        "id": stix_id("malware", case["name"]),
        **common,
        "name": case["name"],
        "description": (
            "Ransomware de doble extorsión operado bajo modelo RaaS. "
            "Accede por VPN sin MFA o credenciales válidas, exfiltra a "
            "servicios de almacenamiento, borra shadow copies y detona el "
            "cifrado. Cuenta con variante para hipervisores ESXi."
        ),
        "is_family": True,
        "malware_types": ["ransomware"],
        "aliases": case["aliases"],
        "is_family_ref": None,  # se elimina abajo; ver nota
        "capabilities": [
            "anti-vm",
            "compromises-data-availability",
            "exfiltrates-data",
        ],
        "implementation_languages": ["c++", "rust"],
        "first_seen": ts(-60 * 24 * 400),
    }
    # STIX 2.1 no admite propiedades nulas: una propiedad que no aplica se
    # OMITE, no se manda en None. Los validadores estrictos fallan por esto.
    malware = {k: v for k, v in malware.items() if v is not None}

    # ── 3.4 Indicator: el DÓNDE MIRAR ─────────────────────────────────
    # El patrón usa STIX Patterning, que no es una query de SIEM: es un
    # lenguaje propio. La comparación va entre corchetes y con comillas
    # simples en el literal.
    pattern = f"[ipv4-addr:value = '{case['c2_ip']}']"
    indicator = {
        "type": "indicator",
        "id": stix_id("indicator", pattern),
        **common,
        "name": f"C2 {case['name']} — {case['c2_ip']}",
        "description": (
            f"Servidor de mando y control asociado a {case['name']}. "
            f"Observado recibiendo balizas TLS en el puerto {case['c2_port']} "
            "desde hosts cifrados minutos antes de la detonación."
        ),
        "indicator_types": ["malicious-activity"],
        "pattern": pattern,
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": created,
        # Un IoC sin fecha de vencimiento es deuda técnica: las IPs rotan y
        # bloquear para siempre genera falsos positivos meses después.
        "valid_until": ts(60 * 24 * 30),
        "confidence": 85,  # escala 0-100 de STIX 2.1
        "labels": ["ransomware", "c2", "akira"],
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack", "phase_name": "command-and-control"}
        ],
        "external_references": [
            {
                "source_name": "MISP",
                "description": "Evento MISP de origen",
                "external_id": case["misp_event_id"],
            }
        ],
        # Propiedades custom: la spec exige prefijo `x_` para no colisionar
        # con futuras versiones del estándar. `x_opencti_score` lo entiende
        # OpenCTI nativamente y alimenta su motor de decaimiento.
        "x_atalaya_defanged": defang(case["c2_ip"]),
        "x_atalaya_source": "MISP",
        "x_opencti_score": 90,
        "x_opencti_detection": True,
    }

    # ── 3.5 Infrastructure: el activo del adversario ──────────────────
    # Distinguir "el indicador" de "la infraestructura" permite razonar sobre
    # el hosting, el ASN y la reutilización entre campañas.
    infrastructure = {
        "type": "infrastructure",
        "id": stix_id("infrastructure", f"{case['name']}-c2"),
        **common,
        "name": f"Infraestructura C2 de {case['name']}",
        "description": "Nodo de mando y control con TLS sobre 443.",
        "infrastructure_types": ["command-and-control"],
        "first_seen": ts(-60 * 24 * 9),
    }

    # ── 3.6 SCO + Observed Data: el hecho crudo ───────────────────────
    # Los SCO (Cyber-observable Objects) en STIX 2.1 son objetos de primer
    # nivel y su ID es UUIDv5 sobre sus propiedades ID-contributing —
    # justamente para que el mismo observable tenga el mismo ID en todas
    # las plataformas del mundo.
    ipv4_sco = {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": stix_id("ipv4-addr", case["c2_ip"]),
        "value": case["c2_ip"],
    }
    observed_data = {
        "type": "observed-data",
        "id": stix_id("observed-data", f"{case['c2_ip']}-sighting"),
        **common,
        "first_observed": ts(-180),
        "last_observed": ts(-12),
        "number_observed": 47,
        "object_refs": [ipv4_sco["id"]],
    }

    # ── 3.7 Relaciones: acá la lista de IPs se vuelve inteligencia ─────
    # `indicates` y `uses` son términos del vocabulario STIX; inventar
    # relationship_types rompe la interoperabilidad con otras plataformas.
    relationships = [
        {
            "type": "relationship",
            "id": stix_id(
                "relationship", f"{case['name']}:indicator-indicates-malware"
            ),
            **common,
            "relationship_type": "indicates",
            "source_ref": indicator["id"],
            "target_ref": malware["id"],
            "description": (
                "El tráfico hacia esta IP evidencia una infección activa de "
                f"{case['name']}."
            ),
            "confidence": 85,
            "start_time": ts(-180),
        },
        {
            "type": "relationship",
            "id": stix_id("relationship", f"{case['name']}:malware-uses-technique"),
            **common,
            "relationship_type": "uses",
            "source_ref": malware["id"],
            "target_ref": attack_pattern["id"],
            "description": (
                f"{case['name']} implementa {case['attack_id']} para cifrar los "
                "datos de la víctima."
            ),
            "confidence": 95,
        },
        {
            "type": "relationship",
            "id": stix_id("relationship", f"{case['name']}:indicator-indicates-infra"),
            **common,
            "relationship_type": "indicates",
            "source_ref": indicator["id"],
            "target_ref": infrastructure["id"],
            "description": "El indicador identifica este nodo de C2.",
            "confidence": 90,
        },
        {
            "type": "relationship",
            "id": stix_id("relationship", f"{case['name']}:malware-uses-infra"),
            **common,
            "relationship_type": "uses",
            "source_ref": malware["id"],
            "target_ref": infrastructure["id"],
            "description": "La familia se comunica con esta infraestructura.",
            "confidence": 80,
        },
    ]

    # ── 3.8 Bundle ────────────────────────────────────────────────────
    # El Bundle NO es un contenedor con semántica: es sólo transporte. Por eso
    # su ID sí es UUIDv4 (cada envío es un envío distinto) y no lleva
    # `created_by_ref` ni marcados.
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [
            identity,
            attack_pattern,
            malware,
            infrastructure,
            ipv4_sco,
            observed_data,
            indicator,
            *relationships,
        ],
    }


# ══════════════════════════════════════════════════════════════════════
#  4. VALIDACIÓN ESTRUCTURAL
# ══════════════════════════════════════════════════════════════════════

_ID_RE = re.compile(
    r"^[a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$")


def _check_identity(obj: dict[str, Any], label: str, seen: set[str]) -> list[str]:
    """ID bien formado, prefijo coherente con el type y sin duplicados."""
    errors: list[str] = []
    otype = obj.get("type", "<sin type>")
    oid = str(obj.get("id", ""))

    if not _ID_RE.match(oid):
        errors.append(f"{label}: ID mal formado -> {oid!r}")
    elif not oid.startswith(f"{otype}--"):
        errors.append(f"{label}: el prefijo del ID no coincide con el type.")
    if oid in seen:
        errors.append(f"{label}: ID duplicado dentro del bundle -> {oid}")
    if otype not in KNOWN_SDO_TYPES:
        errors.append(f"{label}: tipo no contemplado por este conector.")
    return errors


def _check_required(obj: dict[str, Any], label: str) -> list[str]:
    """Propiedades obligatorias según el tipo, y ausencia de nulos.

    STIX 2.1 no admite propiedades en null: la que no aplica se OMITE.
    """
    errors = [
        f"{label}: falta la propiedad obligatoria '{prop}'."
        for prop in REQUIRED_PROPS.get(obj.get("type", ""), set())
        if prop not in obj
    ]
    errors += [
        f"{label}: la propiedad '{key}' es null (debe omitirse)."
        for key, value in obj.items()
        if value is None
    ]
    return errors


def _check_timestamps(obj: dict[str, Any], label: str) -> list[str]:
    """Formato de timestamp exigido por la spec (UTC, sufijo Z)."""
    campos = (
        "created",
        "modified",
        "valid_from",
        "valid_until",
        "first_seen",
        "first_observed",
        "last_observed",
    )
    return [
        f"{label}: timestamp inválido en '{prop}' -> {obj[prop]}"
        for prop in campos
        if prop in obj and not _TS_RE.match(str(obj[prop]))
    ]


def _check_type_rules(obj: dict[str, Any], label: str) -> list[str]:
    """Reglas propias de cada tipo de objeto."""
    errors: list[str] = []
    otype = obj.get("type")

    if otype == "indicator":
        pattern = str(obj.get("pattern", ""))
        if not (pattern.startswith("[") and pattern.endswith("]")):
            errors.append(f"{label}: el patrón STIX debe ir entre corchetes.")
        if obj.get("pattern_type") != "stix":
            errors.append(f"{label}: pattern_type esperado 'stix'.")
        confidence = obj.get("confidence")
        if confidence is not None and not 0 <= confidence <= 100:
            errors.append(f"{label}: confidence fuera del rango 0-100.")

    if otype == "malware" and not isinstance(obj.get("is_family"), bool):
        errors.append(f"{label}: 'is_family' debe ser booleano.")

    return errors


def _check_references(objects: list[dict[str, Any]], ids: set[str]) -> list[str]:
    """Integridad referencial.

    Toda referencia `*_ref` / `*_refs` debe resolver dentro del bundle, salvo
    los marcados TLP, que son objetos predefinidos por la propia spec.
    """
    predefined = {TLP_CLEAR, TLP_GREEN, TLP_AMBER, TLP_RED}
    errors: list[str] = []

    for i, obj in enumerate(objects):
        refs: list[str] = []
        for key, value in obj.items():
            if key.endswith("_ref") and isinstance(value, str):
                refs.append(value)
            elif key.endswith("_refs") and isinstance(value, list):
                refs.extend(v for v in value if isinstance(v, str))

        errors += [
            f"objects[{i}] ({obj.get('type')}): referencia colgada -> {ref}"
            for ref in refs
            if ref not in ids and ref not in predefined
        ]

    return errors


def validate_bundle(bundle: dict[str, Any]) -> list[str]:
    """Valida el bundle contra las reglas duras de STIX 2.1.

    No reemplaza a `stix2-validator` (que además chequea vocabularios y
    convenciones), pero atrapa lo que rompe una ingesta en producción:
    IDs mal formados, propiedades obligatorias faltantes, referencias
    colgadas y timestamps con formato inválido.

    Devuelve la lista de errores; vacía significa que pasó.
    """
    errors: list[str] = []

    if bundle.get("type") != "bundle":
        errors.append("El objeto raíz debe tener type='bundle'.")
    if not str(bundle.get("id", "")).startswith("bundle--"):
        errors.append("El ID del bundle debe empezar con 'bundle--'.")

    objects: list[dict[str, Any]] = bundle.get("objects", [])
    if not objects:
        errors.append("El bundle está vacío.")
        return errors

    ids: set[str] = set()
    for i, obj in enumerate(objects):
        label = f"objects[{i}] ({obj.get('type', '<sin type>')})"
        errors += _check_identity(obj, label, ids)
        errors += _check_required(obj, label)
        errors += _check_timestamps(obj, label)
        errors += _check_type_rules(obj, label)
        ids.add(str(obj.get("id", "")))

    errors += _check_references(objects, ids)
    return errors


# ══════════════════════════════════════════════════════════════════════
#  5. PUBLICACIÓN (opcional)
# ══════════════════════════════════════════════════════════════════════


def push_to_opencti(bundle: dict[str, Any]) -> int:
    """Empuja el bundle a OpenCTI.

    Requiere `pycti` (ver requirements.txt) y las variables OPENCTI_URL /
    OPENCTI_ADMIN_TOKEN. Si no están, el fallback correcto es escribir el
    bundle a disco e importarlo desde la UI (Data → Import).

    Devuelve un código de salida estilo shell.
    """
    url = os.getenv("OPENCTI_URL", "http://localhost:8080")
    token = os.getenv("OPENCTI_ADMIN_TOKEN", "")

    if not token or token.startswith("0000"):
        print(
            "[!] OPENCTI_ADMIN_TOKEN no configurado (o sigue en el valor de "
            "ejemplo). Generá uno con `uuidgen` y cargalo en .env.",
            file=sys.stderr,
        )
        return 2

    try:
        from pycti import OpenCTIApiClient  # noqa: PLC0415 - import opcional
    except ImportError:
        print(
            "[!] pycti no está instalado. Ejecutá:\n"
            "      pip install -r src/ingestion/requirements.txt\n"
            "    o importá el bundle manualmente desde la UI de OpenCTI.",
            file=sys.stderr,
        )
        return 3

    try:
        client = OpenCTIApiClient(url, token, log_level="error")
        client.stix2.import_bundle_from_json(json.dumps(bundle), update=True)
    except Exception as exc:  # noqa: BLE001 - queremos reportar cualquier fallo
        print(f"[!] Falló la publicación en OpenCTI: {exc}", file=sys.stderr)
        return 4

    print(f"[+] Bundle publicado en {url} ({len(bundle['objects'])} objetos).")
    return 0


# ══════════════════════════════════════════════════════════════════════
#  6. CLI
# ══════════════════════════════════════════════════════════════════════


def summarize(bundle: dict[str, Any]) -> str:
    """Resumen legible del grafo generado, para el log de la corrida."""
    counts: dict[str, int] = {}
    for obj in bundle["objects"]:
        counts[obj["type"]] = counts.get(obj["type"], 0) + 1
    lines = [f"    {t:<18} x{n}" for t, n in sorted(counts.items())]
    rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
    lines.append("")
    lines.append("    Grafo:")
    by_id = {o["id"]: o for o in bundle["objects"]}
    for rel in rels:
        src = by_id.get(rel["source_ref"], {})
        dst = by_id.get(rel["target_ref"], {})
        lines.append(
            f"      {src.get('name', src.get('value', '?')):<28}"
            f" --{rel['relationship_type']}-> "
            f"{dst.get('name', dst.get('value', '?'))}"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="misp_stix_connector",
        description="ATALAYA · Genera un bundle STIX 2.1 de un caso de ransomware.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  %(prog)s --pretty\n"
            "  %(prog)s --validate\n"
            "  %(prog)s -o caso_akira.stix.json --pretty\n"
        ),
    )
    parser.add_argument("--pretty", action="store_true", help="JSON indentado.")
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Valida el bundle e imprime el reporte en vez del JSON.",
    )
    parser.add_argument(
        "-o", "--out", metavar="ARCHIVO", help="Escribe el JSON a disco."
    )
    parser.add_argument(
        "--push", action="store_true", help="Publica el bundle en OpenCTI."
    )
    args = parser.parse_args(argv)

    bundle = build_ransomware_bundle()

    if args.validate:
        errors = validate_bundle(bundle)
        print("╔══════════════════════════════════════════════════════════╗")
        print("║  ATALAYA · Validación STIX 2.1                           ║")
        print("╚══════════════════════════════════════════════════════════╝")
        print(f"  Bundle: {bundle['id']}")
        print(f"  Objetos: {len(bundle['objects'])}")
        print(summarize(bundle))
        print()
        if errors:
            print(f"  [✗] {len(errors)} problema(s):")
            for err in errors:
                print(f"      - {err}")
            return 1
        print("  [✓] Bundle STIX 2.1 estructuralmente válido.")
        return 0

    payload = json.dumps(
        bundle, indent=2 if args.pretty else None, ensure_ascii=False, sort_keys=False
    )

    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(payload + "\n")
        print(f"[+] Bundle escrito en {args.out} ({len(bundle['objects'])} objetos).")
    else:
        print(payload)

    if args.push:
        return push_to_opencti(bundle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
