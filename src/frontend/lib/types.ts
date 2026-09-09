/**
 * ATALAYA // Contratos compartidos con la API.
 * Espejo de `src/api/schemas.py`. Si cambia allá, cambia acá.
 */

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export type RankId =
  | 'NOVATO'
  | 'ANALISTA_JUNIOR'
  | 'ANALISTA_SENIOR'
  | 'CAZADOR_DE_AMENAZAS';

export interface Mission {
  mission_id: string;
  title: string;
  briefing: string;
  severity: Severity;
  difficulty: number;
  xp_reward: number;
  required_rank: RankId;
  source: string;
  tlp: string;
  attack_technique: string;
  attack_tactic: string;
  malware_family: string;
  ioc_defanged: string;
  ioc_pattern: string;
  objectives: string[];
  detected_at: string;
  expires_in_minutes: number;
  status: string;
  object_refs: string[];
  locked: boolean;
}

export interface FeedResponse {
  missions: Mission[];
  bundle: Record<string, unknown>;
  next_cursor: string | null;
  has_more: boolean;
  total: number;
  generated_at: string;
  viewer_rank: RankId;
}

export interface RankInfo {
  rank: RankId;
  level: number;
  label: string;
  xp_required: number;
  clearance: string;
  unlocks: string[];
  color: string;
}

export interface AnalystState {
  callsign: string;
  xp: number;
  rank: RankId;
  rank_label: string;
  level: number;
  clearance: string;
  unlocks: string[];
  next_rank: RankId | null;
  xp_to_next: number;
  progress: number;
  missions_completed: number;
  iocs_verified: number;
  streak: number;
  joined_at: string;
  last_event_at: string | null;
  recent_events: Array<Record<string, unknown>>;
}

export interface LevelUpResponse {
  callsign: string;
  event: string;
  xp_delta: number;
  xp_total: number;
  rank: RankId;
  rank_label: string;
  level: number;
  clearance: string;
  promoted: boolean;
  previous_rank: RankId;
  unlocked: string[];
  next_rank: RankId | null;
  xp_to_next: number;
  progress: number;
  streak: number;
  message: string;
}

export type XPEventId =
  | 'mission_triage'
  | 'ioc_enriched'
  | 'ioc_verified'
  | 'correlation_confirmed'
  | 'campaign_attributed'
  | 'yara_rule_accepted'
  | 'peer_review'
  | 'first_blood'
  | 'false_positive_published'
  | 'mission_expired';

/** Tokens de color por severidad. Centralizado para no repetir clases sueltas. */
export const SEVERITY_STYLE: Record<
  Severity,
  { text: string; border: string; bg: string; glow: string; label: string }
> = {
  low: {
    text: 'text-severity-low',
    border: 'border-severity-low/45',
    bg: 'bg-severity-low/10',
    glow: '',
    label: 'BAJA',
  },
  medium: {
    text: 'text-severity-medium',
    border: 'border-severity-medium/45',
    bg: 'bg-severity-medium/10',
    glow: '',
    label: 'MEDIA',
  },
  high: {
    text: 'text-severity-high',
    border: 'border-severity-high/55',
    bg: 'bg-severity-high/10',
    glow: 'shadow-glow-amber',
    label: 'ALTA',
  },
  critical: {
    text: 'text-severity-critical',
    border: 'border-severity-critical/70',
    bg: 'bg-severity-critical/10',
    glow: 'shadow-glow-critical',
    label: 'CRÍTICA',
  },
};

export const RANK_STYLE: Record<RankId, { text: string; border: string; shadow: string }> = {
  NOVATO: {
    text: 'text-neon-green',
    border: 'border-neon-green/50',
    shadow: 'shadow-glow-green',
  },
  ANALISTA_JUNIOR: {
    text: 'text-neon-cyan',
    border: 'border-neon-cyan/50',
    shadow: 'shadow-glow-cyan',
  },
  ANALISTA_SENIOR: {
    text: 'text-neon-magenta',
    border: 'border-neon-magenta/50',
    shadow: 'shadow-glow-magenta',
  },
  CAZADOR_DE_AMENAZAS: {
    text: 'text-neon-amber',
    border: 'border-neon-amber/50',
    shadow: 'shadow-glow-amber',
  },
};

// ══════════════════════════════════════════════════════════════════
//  Identidad
// ══════════════════════════════════════════════════════════════════

export type RoleId = 'ANALYST' | 'INSTRUCTOR' | 'ADMIN';

export interface Session {
  callsign: string;
  role: RoleId;
  email: string | null;
  joined_at: string;
  last_login_at: string | null;
  active_sessions: number;
}
