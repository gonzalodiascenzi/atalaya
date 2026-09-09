/**
 * ATALAYA // Datos de siembra (modo autónomo).
 *
 * Réplica reducida del catálogo de `src/api/stix_feed.py`. Permite que la
 * consola arranque y se pueda demostrar sin backend levantado. Los IoCs son
 * sintéticos (RFC 5737 / RFC 2606) — no bloquean infraestructura real.
 */

import type { Mission, RankInfo, RankId } from './types';

export const SEED_RANKS: RankInfo[] = [
  {
    rank: 'NOVATO',
    level: 1,
    label: 'Novato',
    xp_required: 0,
    clearance: 'OBSERVADOR',
    unlocks: ['feed:read', 'mission:triage'],
    color: 'neon-green',
  },
  {
    rank: 'ANALISTA_JUNIOR',
    level: 2,
    label: 'Analista Junior',
    xp_required: 250,
    clearance: 'CONTRIBUYENTE',
    unlocks: ['ioc:enrich', 'mission:report', 'sandbox:submit'],
    color: 'neon-cyan',
  },
  {
    rank: 'ANALISTA_SENIOR',
    level: 3,
    label: 'Analista Senior',
    xp_required: 1200,
    clearance: 'VERIFICADOR',
    unlocks: ['ioc:verify', 'campaign:correlate', 'peer:review', 'graph:pivot'],
    color: 'neon-magenta',
  },
  {
    rank: 'CAZADOR_DE_AMENAZAS',
    level: 4,
    label: 'Cazador de Amenazas',
    xp_required: 4000,
    clearance: 'OPERADOR',
    unlocks: ['misp:publish', 'mission:author', 'yara:deploy', 'attribution:propose'],
    color: 'neon-amber',
  },
];

export const RANK_LEVEL: Record<RankId, number> = {
  NOVATO: 1,
  ANALISTA_JUNIOR: 2,
  ANALISTA_SENIOR: 3,
  CAZADOR_DE_AMENAZAS: 4,
};

const iso = (minutesAgo: number) =>
  new Date(Date.now() - minutesAgo * 60_000).toISOString();

export const SEED_MISSIONS: Mission[] = [
  {
    mission_id: 'MSN-AK1RA001',
    title: 'Cifrado masivo en curso — familia Akira',
    briefing:
      'Un endpoint del segmento corporativo abrió una sesión saliente sostenida hacia un host no catalogado, minutos antes de que empezaran a aparecer archivos con extensión .akira. Confirmá si la IP es infraestructura de mando y control o un falso positivo de un servicio legítimo.',
    severity: 'critical',
    difficulty: 4,
    xp_reward: 300,
    required_rank: 'NOVATO',
    source: 'abuse.ch/ThreatFox',
    tlp: 'TLP:AMBER',
    attack_technique: 'T1486',
    attack_tactic: 'impact',
    malware_family: 'Akira',
    ioc_defanged: '198[.]51[.]100[.]42',
    ioc_pattern: "[ipv4-addr:value = '198.51.100.42']",
    objectives: [
      'Pivotear la IP en OpenCTI y listar observables relacionados',
      'Contrastar contra ThreatFox y el catálogo KEV de CISA',
      'Determinar si hubo exfiltración previa al cifrado',
      'Emitir veredicto: TRUE POSITIVE / FALSE POSITIVE con evidencia',
    ],
    detected_at: iso(4),
    expires_in_minutes: 236,
    status: 'OPEN',
    object_refs: [],
    locked: false,
  },
  {
    mission_id: 'MSN-LUMM4002',
    title: 'Robo de credenciales — panel de Lumma Stealer',
    briefing:
      'Telemetría de navegador muestra lecturas anómalas del almacén de credenciales seguidas de un POST a un dominio registrado hace 6 días. Perfil clásico de infostealer. Caracterizá la campaña.',
    severity: 'high',
    difficulty: 3,
    xp_reward: 160,
    required_rank: 'NOVATO',
    source: 'AlienVault OTX',
    tlp: 'TLP:GREEN',
    attack_technique: 'T1555.003',
    attack_tactic: 'credential-access',
    malware_family: 'Lumma Stealer',
    ioc_defanged: 'panel-update[.]example',
    ioc_pattern: "[domain-name:value = 'panel-update.example']",
    objectives: [
      'Resolver el dominio y mapear la infraestructura asociada',
      'Buscar reutilización de certificado TLS entre dominios hermanos',
      'Estimar alcance: ¿cuántos hosts internos consultaron el dominio?',
      'Proponer regla de detección (Sigma o YARA)',
    ],
    detected_at: iso(21),
    expires_in_minutes: 219,
    status: 'OPEN',
    object_refs: [],
    locked: false,
  },
  {
    mission_id: 'MSN-KEV00003',
    title: 'Explotación activa de appliance perimetral (CISA KEV)',
    briefing:
      'CISA sumó al catálogo KEV una vulnerabilidad de ejecución remota en un appliance de acceso remoto. Tenemos dos de esos en el perímetro. Hay escaneo entrante desde una IP no vista antes.',
    severity: 'critical',
    difficulty: 5,
    xp_reward: 300,
    required_rank: 'ANALISTA_JUNIOR',
    source: 'CISA KEV',
    tlp: 'TLP:CLEAR',
    attack_technique: 'T1190',
    attack_tactic: 'initial-access',
    malware_family: 'Generic Webshell Implant',
    ioc_defanged: '203[.]0[.]113[.]77',
    ioc_pattern: "[ipv4-addr:value = '203.0.113.77']",
    objectives: [
      'Confirmar exposición: ¿alguno de nuestros activos es vulnerable?',
      'Revisar logs del appliance buscando indicios post-explotación',
      'Verificar la fecha límite de remediación que fija CISA',
      'Escalar a respuesta a incidentes si hay evidencia de acceso',
    ],
    detected_at: iso(38),
    expires_in_minutes: 202,
    status: 'OPEN',
    object_refs: [],
    locked: true,
  },
  {
    mission_id: 'MSN-CSB34C0N',
    title: 'Beacon de Cobalt Strike en movimiento lateral',
    briefing:
      'Un binario sin firmar se ejecutó desde un directorio temporal en tres estaciones distintas dentro de la misma hora. El patrón de tráfico saliente tiene jitter regular. Olor a beacon.',
    severity: 'high',
    difficulty: 5,
    xp_reward: 160,
    required_rank: 'ANALISTA_SENIOR',
    source: 'MISP / evento interno',
    tlp: 'TLP:AMBER',
    attack_technique: 'T1071.001',
    attack_tactic: 'command-and-control',
    malware_family: 'Cobalt Strike',
    ioc_defanged: 'a1b2c3d4e5f6…d6e7f801 (SHA-256)',
    ioc_pattern: "[file:hashes.'SHA-256' = 'a1b2…f801']",
    objectives: [
      'Extraer la configuración del beacon (watermark, sleep, jitter)',
      'Correlacionar el watermark con campañas conocidas',
      'Reconstruir la cadena de ejecución hasta el acceso inicial',
      'Documentar el TTP en formato ATT&CK Navigator',
    ],
    detected_at: iso(55),
    expires_in_minutes: 185,
    status: 'OPEN',
    object_refs: [],
    locked: true,
  },
  {
    mission_id: 'MSN-A1TM0005',
    title: 'Kit de phishing con relay de MFA',
    briefing:
      'Tres empleados reportaron un correo de "revalidación de acceso". El link intermedia la sesión real y roba la cookie post-MFA. AiTM en libro. Medí el daño.',
    severity: 'medium',
    difficulty: 2,
    xp_reward: 80,
    required_rank: 'NOVATO',
    source: 'SpiderFoot / reporte interno',
    tlp: 'TLP:GREEN',
    attack_technique: 'T1566.002',
    attack_tactic: 'initial-access',
    malware_family: 'AiTM Phishing Kit',
    ioc_defanged: 'hxxps://sso-revalidacion[.]example/login',
    ioc_pattern: "[url:value = 'https://sso-revalidacion.example/login']",
    objectives: [
      'Identificar cuántos usuarios cargaron credenciales',
      'Invalidar sesiones activas de los afectados',
      'Determinar si el kit tiene panel expuesto (OSINT con SpiderFoot)',
      'Publicar el IoC en MISP con el TLP correcto',
    ],
    detected_at: iso(72),
    expires_in_minutes: 168,
    status: 'OPEN',
    object_refs: [],
    locked: false,
  },
  {
    mission_id: 'MSN-4SYNC006',
    title: 'Loader multi-etapa desplegando AsyncRAT',
    briefing:
      'Un archivo .lnk dentro de un ZIP disparó PowerShell ofuscado que descargó una segunda etapa. La persistencia quedó en una tarea programada con nombre plausible. Desarmá la cadena.',
    severity: 'medium',
    difficulty: 3,
    xp_reward: 80,
    required_rank: 'ANALISTA_JUNIOR',
    source: 'MalwareBazaar',
    tlp: 'TLP:GREEN',
    attack_technique: 'T1059.001',
    attack_tactic: 'execution',
    malware_family: 'AsyncRAT',
    ioc_defanged: '192[.]0[.]2[.]155',
    ioc_pattern: "[ipv4-addr:value = '192.0.2.155']",
    objectives: [
      'Desofuscar el script de PowerShell de la primera etapa',
      'Identificar el mecanismo de persistencia exacto',
      'Extraer configuración del RAT (puerto, mutex, clave)',
      'Escribir una regla YARA para la segunda etapa',
    ],
    detected_at: iso(89),
    expires_in_minutes: 151,
    status: 'OPEN',
    object_refs: [],
    locked: true,
  },
];

/** Tabla de XP local: espeja `XP_TABLE` del backend para el modo autónomo. */
export const SEED_XP_TABLE: Record<string, number> = {
  mission_triage: 10,
  ioc_enriched: 25,
  ioc_verified: 60,
  correlation_confirmed: 120,
  campaign_attributed: 300,
  yara_rule_accepted: 200,
  peer_review: 40,
  first_blood: 150,
  false_positive_published: -75,
  mission_expired: -15,
};

export const SEED_SEVERITY_MULTIPLIER: Record<string, number> = {
  low: 1.0,
  medium: 1.25,
  high: 1.6,
  critical: 2.0,
};

/** Devuelve el rango correspondiente a una cantidad de XP. */
export function rankForXP(xp: number): RankInfo {
  let earned = SEED_RANKS[0];
  for (const spec of SEED_RANKS) {
    if (xp >= spec.xp_required) earned = spec;
    else break;
  }
  return earned;
}
