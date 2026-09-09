"""
ATALAYA // Generador del Feed de Misiones (STIX 2.1).

Cada "misión" que ve el analista es, por debajo, un micro-bundle STIX 2.1
coherente: un Indicator que apunta a un Malware, que a su vez usa un
Attack Pattern de MITRE ATT&CK. Es el mismo modelo de datos que va a llegar
desde OpenCTI/MISP en producción, así que el frontend no cambia una línea
cuando se conecta la ingesta real.

IMPORTANTE — sobre los IoCs de este catálogo:
    Son sintéticos a propósito. Usan rangos reservados por RFC 5737
    (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) y dominios RFC 2606
    (.example / .invalid). Si alguien copia y pega esto a un firewall, no
    bloquea infraestructura de un tercero real. Las familias de malware y
    las técnicas ATT&CK SÍ son reales: el valor didáctico está ahí.
"""

from __future__ import annotations

import base64
import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

# Namespace propio de ATALAYA para IDs deterministas (UUIDv5).
# La spec sugiere UUIDv4 para SDOs, pero los conectores serios usan v5:
# reingerir el mismo IoC dos veces debe producir el mismo ID, o el grafo
# de OpenCTI se llena de duplicados.
ATALAYA_NAMESPACE = uuid.UUID("6ba7b812-9dad-11d1-80b4-00c04fd430c8")

# Identidad que firma lo que publicamos.
ATALAYA_IDENTITY_ID = "identity--" + str(
    uuid.uuid5(ATALAYA_NAMESPACE, "identity:atalaya-cti-ops")
)

# IDs canónicos de marcado TLP definidos por la spec STIX 2.1.
# Nota: la spec conserva el nombre "TLP:WHITE"; TLP 2.0 lo renombró a
# TLP:CLEAR pero el objeto de marcado sigue siendo el mismo.
TLP_MARKINGS = {
    "TLP:CLEAR": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "TLP:WHITE": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "TLP:GREEN": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "TLP:AMBER": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "TLP:RED": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}


def stix_id(stix_type: str, seed: str) -> str:
    """ID STIX determinista: mismo seed -> mismo ID, siempre."""
    return f"{stix_type}--{uuid.uuid5(ATALAYA_NAMESPACE, f'{stix_type}:{seed}')}"


def now_iso(offset_minutes: int = 0) -> str:
    """Timestamp STIX (UTC, sufijo Z, milisegundos)."""
    ts = datetime.now(timezone.utc) + timedelta(minutes=offset_minutes)
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


def defang(value: str) -> str:
    """Neutraliza un IoC para mostrarlo en pantalla sin riesgo de click.

    Un feed de amenazas que renderiza URLs clickeables es un incidente
    esperando a pasar. Defang por diseño, no por disciplina del usuario.
    """
    return (
        value.replace("http://", "hxxp://")
        .replace("https://", "hxxps://")
        .replace(".", "[.]")
        .replace("@", "[at]")
    )


# ──────────────────────────────────────────────────────────────────────
#  Catálogo de escenarios
#  Cada entrada produce una misión completa y auto-consistente.
# ──────────────────────────────────────────────────────────────────────
THREAT_CATALOG: list[dict[str, Any]] = [
    {
        "key": "akira-ransomware-c2",
        "ground_truth": "MALICIOUS",
        "truth_source": "MULTI_SOURCE",
        "source_confidence": 95,
        "independent_sources": 4,
        "kev_listed": False,
        "title": "Cifrado masivo en curso — familia Akira",
        "briefing": (
            "Un endpoint del segmento corporativo abrió una sesión saliente "
            "sostenida hacia un host no catalogado, minutos antes de que "
            "empezaran a aparecer archivos con extensión .akira. Confirmá si "
            "la IP es infraestructura de mando y control o un falso positivo "
            "de un servicio legítimo."
        ),
        "severity": "critical",
        "malware": {
            "name": "Akira",
            "types": ["ransomware"],
            "description": (
                "Ransomware de doble extorsión activo desde 2023. Cifra y "
                "exfiltra antes de detonar; opera bajo modelo RaaS."
            ),
            "is_family": True,
            "aliases": ["Akira Ransomware", "Megazord"],
        },
        "attack_pattern": {
            "name": "Data Encrypted for Impact",
            "attack_id": "T1486",
            "tactic": "impact",
        },
        "indicator": {
            "pattern": "[ipv4-addr:value = '198.51.100.42']",
            "raw": "198.51.100.42",
            "types": ["malicious-activity"],
            "name": "C2 Akira — 198.51.100.42",
        },
        "objectives": [
            "Pivotear la IP en OpenCTI y listar observables relacionados",
            "Contrastar contra ThreatFox y el catálogo KEV de CISA",
            "Determinar si hubo exfiltración previa al cifrado",
            "Emitir veredicto: TRUE POSITIVE / FALSE POSITIVE con evidencia",
        ],
        "source": "abuse.ch/ThreatFox",
        "tlp": "TLP:AMBER",
        "required_rank": "NOVATO",
        "difficulty": 4,
    },
    {
        "key": "lumma-stealer-panel",
        "ground_truth": "UNKNOWN",
        "truth_source": None,
        "source_confidence": 50,
        "independent_sources": 1,
        "kev_listed": False,
        "title": "Robo de credenciales — panel de Lumma Stealer",
        "briefing": (
            "Telemetría de navegador muestra lecturas anómalas del almacén de "
            "credenciales seguidas de un POST a un dominio registrado hace 6 "
            "días. Perfil clásico de infostealer. Caracterizá la campaña."
        ),
        "severity": "high",
        "malware": {
            "name": "Lumma Stealer",
            "types": ["trojan", "spyware"],
            "description": (
                "Infostealer como servicio (MaaS). Extrae credenciales de "
                "navegadores, wallets de criptomonedas y sesiones 2FA."
            ),
            "is_family": True,
            "aliases": ["LummaC2"],
        },
        "attack_pattern": {
            "name": "Credentials from Web Browsers",
            "attack_id": "T1555.003",
            "tactic": "credential-access",
        },
        "indicator": {
            "pattern": "[domain-name:value = 'panel-update.example']",
            "raw": "panel-update.example",
            "types": ["malicious-activity"],
            "name": "Panel C2 Lumma — panel-update.example",
        },
        "objectives": [
            "Resolver el dominio y mapear la infraestructura asociada",
            "Buscar reutilización de certificado TLS entre dominios hermanos",
            "Estimar alcance: ¿cuántos hosts internos consultaron el dominio?",
            "Proponer regla de detección (Sigma o YARA)",
        ],
        "source": "AlienVault OTX",
        "tlp": "TLP:GREEN",
        "required_rank": "NOVATO",
        "difficulty": 3,
    },
    {
        "key": "edge-appliance-kev",
        "ground_truth": "MALICIOUS",
        "truth_source": "KEV",
        "source_confidence": 100,
        "independent_sources": 2,
        "kev_listed": True,
        "title": "Explotación activa de appliance perimetral (CISA KEV)",
        "briefing": (
            "CISA sumó al catálogo KEV una vulnerabilidad de ejecución remota "
            "en un appliance de acceso remoto. Tenemos dos de esos en el "
            "perímetro. Hay escaneo entrante desde una IP no vista antes."
        ),
        "severity": "critical",
        "malware": {
            "name": "Generic Webshell Implant",
            "types": ["webshell", "backdoor"],
            "description": (
                "Implante post-explotación desplegado sobre appliances "
                "perimetrales comprometidos para persistencia."
            ),
            "is_family": False,
            "aliases": [],
        },
        "attack_pattern": {
            "name": "Exploit Public-Facing Application",
            "attack_id": "T1190",
            "tactic": "initial-access",
        },
        "indicator": {
            "pattern": "[ipv4-addr:value = '203.0.113.77']",
            "raw": "203.0.113.77",
            "types": ["attribution", "malicious-activity"],
            "name": "Escáner de explotación — 203.0.113.77",
        },
        "vulnerability": {
            "name": "CVE-2024-00000",
            "description": (
                "RCE sin autenticar en appliance de acceso remoto. Ejemplo "
                "didáctico: el conector real toma el CVE del feed KEV."
            ),
            "cvss": 9.8,
        },
        "objectives": [
            "Confirmar exposición: ¿alguno de nuestros activos es vulnerable?",
            "Revisar logs del appliance buscando indicios post-explotación",
            "Verificar la fecha límite de remediación que fija CISA",
            "Escalar a respuesta a incidentes si hay evidencia de acceso",
        ],
        "source": "CISA KEV",
        "tlp": "TLP:CLEAR",
        "required_rank": "ANALISTA_JUNIOR",
        "difficulty": 5,
    },
    {
        "key": "cobalt-strike-beacon",
        "ground_truth": "MALICIOUS",
        "truth_source": "CURATED",
        "source_confidence": 90,
        "independent_sources": 3,
        "kev_listed": False,
        "title": "Beacon de Cobalt Strike en movimiento lateral",
        "briefing": (
            "Un binario sin firmar se ejecutó desde un directorio temporal en "
            "tres estaciones distintas dentro de la misma hora. El patrón de "
            "tráfico saliente tiene jitter regular. Olor a beacon."
        ),
        "severity": "high",
        "malware": {
            "name": "Cobalt Strike",
            "types": ["remote-access-trojan", "backdoor"],
            "description": (
                "Framework comercial de post-explotación, ampliamente abusado "
                "por actores criminales y estatales. Su beacon soporta "
                "comunicación C2 sobre HTTP/S, DNS y SMB."
            ),
            "is_family": True,
            "aliases": ["CobaltStrike", "Beacon"],
        },
        "attack_pattern": {
            "name": "Application Layer Protocol: Web Protocols",
            "attack_id": "T1071.001",
            "tactic": "command-and-control",
        },
        "indicator": {
            "pattern": (
                "[file:hashes.'SHA-256' = "
                "'a1b2c3d4e5f60718293a4b5c6d7e8f90"
                "1a2b3c4d5e6f708192a3b4c5d6e7f801']"
            ),
            "raw": "a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f708192a3b4c5d6e7f801",
            "types": ["malicious-activity"],
            "name": "Beacon CS — SHA-256 sintético",
        },
        "objectives": [
            "Extraer la configuración del beacon (watermark, sleep, jitter)",
            "Correlacionar el watermark con campañas conocidas",
            "Reconstruir la cadena de ejecución hasta el acceso inicial",
            "Documentar el TTP en formato ATT&CK Navigator",
        ],
        "source": "MISP / evento interno",
        "tlp": "TLP:AMBER",
        "required_rank": "ANALISTA_SENIOR",
        "difficulty": 5,
    },
    {
        "key": "phishing-kit-mfa-relay",
        "ground_truth": "MALICIOUS",
        "truth_source": "CURATED",
        "source_confidence": 85,
        "independent_sources": 2,
        "kev_listed": False,
        "title": "Kit de phishing con relay de MFA",
        "briefing": (
            "Tres empleados reportaron un correo de 'revalidación de acceso'. "
            "El link intermedia la sesión real y roba la cookie post-MFA. "
            "AiTM en libro. Medí el daño."
        ),
        "severity": "medium",
        "malware": {
            "name": "AiTM Phishing Kit",
            "types": ["credential-exploitation"],
            "description": (
                "Kit adversary-in-the-middle que proxea el login legítimo y "
                "captura la cookie de sesión, evadiendo MFA por SMS y TOTP."
            ),
            "is_family": False,
            "aliases": ["Evilginx-like"],
        },
        "attack_pattern": {
            "name": "Phishing: Spearphishing Link",
            "attack_id": "T1566.002",
            "tactic": "initial-access",
        },
        "indicator": {
            "pattern": "[url:value = 'https://sso-revalidacion.example/login']",
            "raw": "https://sso-revalidacion.example/login",
            "types": ["malicious-activity"],
            "name": "Landing AiTM — sso-revalidacion.example",
        },
        "objectives": [
            "Identificar cuántos usuarios cargaron credenciales",
            "Invalidar sesiones activas de los afectados",
            "Determinar si el kit tiene panel expuesto (OSINT con SpiderFoot)",
            "Publicar el IoC en MISP con el TLP correcto",
        ],
        "source": "SpiderFoot / reporte interno",
        "tlp": "TLP:GREEN",
        "required_rank": "NOVATO",
        "difficulty": 2,
    },
    {
        "key": "asyncrat-loader",
        "ground_truth": "UNKNOWN",
        "truth_source": None,
        "source_confidence": 55,
        "independent_sources": 1,
        "kev_listed": False,
        "title": "Loader multi-etapa desplegando AsyncRAT",
        "briefing": (
            "Un archivo .lnk dentro de un ZIP disparó PowerShell ofuscado que "
            "descargó una segunda etapa. La persistencia quedó en una tarea "
            "programada con nombre plausible. Desarmá la cadena."
        ),
        "severity": "medium",
        "malware": {
            "name": "AsyncRAT",
            "types": ["remote-access-trojan"],
            "description": (
                "RAT de código abierto en .NET con captura de pantalla, "
                "keylogging y ejecución remota. Muy usado por commodity crime."
            ),
            "is_family": True,
            "aliases": ["Async RAT"],
        },
        "attack_pattern": {
            "name": "Command and Scripting Interpreter: PowerShell",
            "attack_id": "T1059.001",
            "tactic": "execution",
        },
        "indicator": {
            "pattern": "[ipv4-addr:value = '192.0.2.155']",
            "raw": "192.0.2.155",
            "types": ["malicious-activity"],
            "name": "C2 AsyncRAT — 192.0.2.155",
        },
        "objectives": [
            "Desofuscar el script de PowerShell de la primera etapa",
            "Identificar el mecanismo de persistencia exacto",
            "Extraer configuración del RAT (puerto, mutex, clave)",
            "Escribir una regla YARA para la segunda etapa",
        ],
        "source": "MalwareBazaar",
        "tlp": "TLP:GREEN",
        "required_rank": "ANALISTA_JUNIOR",
        "difficulty": 3,
    },
    {
        "key": "cdn-falso-positivo",
        "ground_truth": "BENIGN",
        "truth_source": "CURATED",
        "source_confidence": 35,
        "independent_sources": 1,
        "kev_listed": False,
        "title": "Balizas periódicas hacia un rango no catalogado",
        "briefing": (
            "Un agregador de baja confianza marcó esta IP como C2 por su "
            "patrón de conexiones regulares. Doscientos endpoints la "
            "consultan cada quince minutos, de forma idéntica. Antes de "
            "bloquear medio parque: ¿es infraestructura del adversario o "
            "estás por romper algo que funciona?"
        ),
        "severity": "medium",
        "malware": {
            "name": "Sin atribución",
            "types": ["unknown"],
            "description": (
                "Actividad reportada por una única fuente de baja confianza, "
                "sin muestra asociada ni corroboración independiente."
            ),
            "is_family": False,
            "aliases": [],
        },
        "attack_pattern": {
            "name": "Application Layer Protocol: Web Protocols",
            "attack_id": "T1071.001",
            "tactic": "command-and-control",
        },
        "indicator": {
            "pattern": "[ipv4-addr:value = '192.0.2.8']",
            "raw": "192.0.2.8",
            "types": ["anomalous-activity"],
            "name": "Balizas regulares — 192.0.2.8",
        },
        "objectives": [
            "Identificar a quién pertenece el rango y para qué se usa",
            "Contrastar el patrón con el de una actualización programada",
            "Buscar corroboración en fuentes independientes",
            "Estimar el impacto de bloquear antes de bloquear",
        ],
        "source": "Agregador de baja confianza",
        "tlp": "TLP:CLEAR",
        "required_rank": "NOVATO",
        "difficulty": 3,
    },
    {
        "key": "pentest-interno",
        "ground_truth": "BENIGN",
        "truth_source": "CURATED",
        "source_confidence": 40,
        "independent_sources": 1,
        "kev_listed": False,
        "title": "Barrido de puertos desde la red interna",
        "briefing": (
            "Un host interno escaneó 1.400 puertos de tres segmentos en "
            "cuarenta minutos. Ruidoso, metódico y en horario laboral. "
            "Un atacante que ya está adentro no suele hacer tanto ruido a "
            "las once de la mañana."
        ),
        "severity": "high",
        "malware": {
            "name": "Sin atribución",
            "types": ["unknown"],
            "description": "Actividad de reconocimiento sin binario asociado.",
            "is_family": False,
            "aliases": [],
        },
        "attack_pattern": {
            "name": "Network Service Discovery",
            "attack_id": "T1046",
            "tactic": "discovery",
        },
        "indicator": {
            "pattern": "[ipv4-addr:value = '203.0.113.201']",
            "raw": "203.0.113.201",
            "types": ["anomalous-activity"],
            "name": "Barrido interno — 203.0.113.201",
        },
        "objectives": [
            "Identificar el activo de origen y su dueño",
            "Revisar si hay una autorización de prueba vigente",
            "Comparar la firma del barrido con herramientas conocidas",
            "Decidir si escalar a respuesta a incidentes o cerrar",
        ],
        "source": "Telemetría interna",
        "tlp": "TLP:AMBER",
        "required_rank": "ANALISTA_JUNIOR",
        "difficulty": 2,
    },
]


def _external_refs_attack(ap: dict[str, Any]) -> list[dict[str, str]]:
    """Referencia a MITRE ATT&CK como manda la spec."""
    return [
        {
            "source_name": "mitre-attack",
            "external_id": ap["attack_id"],
            "url": (
                "https://attack.mitre.org/techniques/"
                + ap["attack_id"].replace(".", "/")
            ),
        }
    ]


def build_mission(entry: dict[str, Any], age_minutes: int = 0) -> dict[str, Any]:
    """Construye una misión completa: metadatos + objetos STIX 2.1 + relaciones."""
    key = entry["key"]
    created = now_iso(-age_minutes)
    tlp_ref = TLP_MARKINGS.get(entry.get("tlp", "TLP:CLEAR"), TLP_MARKINGS["TLP:CLEAR"])
    common = {
        "spec_version": "2.1",
        "created": created,
        "modified": created,
        "created_by_ref": ATALAYA_IDENTITY_ID,
        "object_marking_refs": [tlp_ref],
    }

    ap = entry["attack_pattern"]
    attack_pattern = {
        "type": "attack-pattern",
        "id": stix_id("attack-pattern", ap["attack_id"]),
        **common,
        "name": ap["name"],
        "external_references": _external_refs_attack(ap),
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack", "phase_name": ap["tactic"]}
        ],
    }

    mw = entry["malware"]
    malware = {
        "type": "malware",
        "id": stix_id("malware", mw["name"]),
        **common,
        "name": mw["name"],
        "description": mw["description"],
        # is_family es obligatorio en STIX 2.1 para el SDO malware.
        "is_family": mw["is_family"],
        "malware_types": mw["types"],
        **({"aliases": mw["aliases"]} if mw.get("aliases") else {}),
    }

    ind = entry["indicator"]
    indicator = {
        "type": "indicator",
        "id": stix_id("indicator", ind["pattern"]),
        **common,
        "name": ind["name"],
        "description": entry["briefing"],
        "indicator_types": ind["types"],
        "pattern": ind["pattern"],
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": created,
        "valid_until": now_iso(-age_minutes + 60 * 24 * 30),
        "confidence": {"low": 40, "medium": 65, "high": 80, "critical": 95}[
            entry["severity"]
        ],
        "labels": [entry["source"].lower().replace(" ", "-")],
        # Propiedades custom: la spec exige prefijo x_ para no colisionar.
        "x_atalaya_defanged": defang(ind["raw"]),
        "x_atalaya_severity": entry["severity"],
        "x_opencti_score": {"low": 30, "medium": 55, "high": 75, "critical": 92}[
            entry["severity"]
        ],
    }

    objects: list[dict[str, Any]] = [attack_pattern, malware, indicator]

    # Relaciones — el grafo es donde la CTI deja de ser una lista de IPs.
    relationships = [
        {
            "type": "relationship",
            "id": stix_id("relationship", f"{key}:indicates"),
            **common,
            "relationship_type": "indicates",
            "source_ref": indicator["id"],
            "target_ref": malware["id"],
            "description": "El indicador evidencia actividad de esta familia.",
        },
        {
            "type": "relationship",
            "id": stix_id("relationship", f"{key}:uses"),
            **common,
            "relationship_type": "uses",
            "source_ref": malware["id"],
            "target_ref": attack_pattern["id"],
            "description": "La familia implementa esta técnica de ATT&CK.",
        },
    ]

    # Escenarios con CVE suman un SDO vulnerability y su relación.
    if "vulnerability" in entry:
        vuln_data = entry["vulnerability"]
        vulnerability = {
            "type": "vulnerability",
            "id": stix_id("vulnerability", vuln_data["name"]),
            **common,
            "name": vuln_data["name"],
            "description": vuln_data["description"],
            "external_references": [
                {"source_name": "cve", "external_id": vuln_data["name"]}
            ],
            "x_atalaya_cvss_v3": vuln_data["cvss"],
            "x_atalaya_kev": True,
        }
        objects.append(vulnerability)
        relationships.append(
            {
                "type": "relationship",
                "id": stix_id("relationship", f"{key}:targets"),
                **common,
                "relationship_type": "targets",
                "source_ref": malware["id"],
                "target_ref": vulnerability["id"],
                "description": "La amenaza explota esta vulnerabilidad.",
            }
        )

    objects.extend(relationships)

    xp_base = {"low": 40, "medium": 80, "high": 160, "critical": 300}[entry["severity"]]

    return {
        "mission_id": "MSN-" + hashlib.sha256(key.encode()).hexdigest()[:8].upper(),
        "title": entry["title"],
        "briefing": entry["briefing"],
        "severity": entry["severity"],
        "difficulty": entry["difficulty"],
        "xp_reward": xp_base,
        "required_rank": entry["required_rank"],
        "source": entry["source"],
        "tlp": entry.get("tlp", "TLP:CLEAR"),
        "attack_technique": ap["attack_id"],
        "attack_tactic": ap["tactic"],
        "malware_family": mw["name"],
        "ioc_defanged": defang(ind["raw"]),
        "ioc_pattern": ind["pattern"],
        "objectives": entry["objectives"],
        "detected_at": created,
        "expires_in_minutes": max(15, 240 - age_minutes),
        "status": "OPEN",
        # ── Señales del bucle de verificación (docs/VERIFICACION.md) ──
        # Sin estos campos no hay nada que calificar: son el contrato mínimo
        # que todo conector de ingesta tiene que poder alimentar.
        "ground_truth": entry.get("ground_truth", "UNKNOWN"),
        "truth_source": entry.get("truth_source"),
        "source_confidence": entry.get("source_confidence", 50),
        "independent_sources": entry.get("independent_sources", 1),
        "kev_listed": entry.get("kev_listed", False),
        "object_refs": [o["id"] for o in objects],
        "objects": objects,
    }


def full_catalog() -> list[dict[str, Any]]:
    """Catálogo completo, ordenado del hallazgo más reciente al más viejo."""
    return [
        build_mission(entry, age_minutes=idx * 17)
        for idx, entry in enumerate(THREAT_CATALOG)
    ]


def encode_cursor(offset: int) -> str:
    """Cursor opaco para scroll infinito. Opaco = el cliente no lo manipula."""
    return base64.urlsafe_b64encode(f"offset:{offset}".encode()).decode().rstrip("=")


def decode_cursor(cursor: str | None) -> int:
    """Decodifica el cursor. Entrada inválida -> arrancamos de cero, sin 500."""
    if not cursor:
        return 0
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(padded.encode()).decode()
        if not raw.startswith("offset:"):
            return 0
        return max(0, int(raw.split(":", 1)[1]))
    except (ValueError, UnicodeDecodeError):
        return 0


def as_bundle(missions: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Empaqueta las misiones en un STIX Bundle válido, deduplicando objetos.

    El bundle incluye la Identity que firma; sin ella los `created_by_ref`
    quedan colgando y OpenCTI se queja al importar.
    """
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": ATALAYA_IDENTITY_ID,
        "created": "2026-01-01T00:00:00.000Z",
        "modified": "2026-01-01T00:00:00.000Z",
        "name": "ATALAYA CTI Ops",
        "identity_class": "organization",
        "sectors": ["technology"],
        "description": "Torre de vigilancia y academia táctica de CTI.",
    }

    seen: set[str] = {identity["id"]}
    objects: list[dict[str, Any]] = [identity]
    for mission in missions:
        for obj in mission["objects"]:
            if obj["id"] not in seen:
                seen.add(obj["id"])
                objects.append(obj)

    return {
        "type": "bundle",
        "id": "bundle--" + str(uuid.uuid4()),
        "objects": objects,
    }
