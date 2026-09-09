/**
 * ATALAYA // Cliente de la API.
 *
 * Principio de diseño: la consola NUNCA se queda en blanco. Si la API no
 * responde, se degrada a los datos de siembra locales y se avisa en la barra
 * de estado. Un analista mirando un spinner infinito no está entrenando.
 */

import type {
  AnalystState,
  FeedResponse,
  LevelUpResponse,
  RankInfo,
  Session,
  XPEventId,
  Severity,
} from './types';

export const API_BASE =
  process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, '') ?? 'http://localhost:8000';

/** Timeout duro: sin esto, un backend colgado congela la UI. */
const TIMEOUT_MS = 6000;

export class ApiUnavailableError extends Error {
  constructor(cause?: unknown) {
    super('La API de ATALAYA no responde.');
    this.name = 'ApiUnavailableError';
    this.cause = cause;
  }
}

/** La sesión venció o no hay. El llamador decide si renovar o pedir acceso. */
export class UnauthorizedError extends Error {
  constructor(public readonly detail: string) {
    super(detail);
    this.name = 'UnauthorizedError';
  }
}

async function raw<T>(path: string, init?: RequestInit): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(`${API_BASE}${path}`, {
      ...init,
      signal: controller.signal,
      headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
      cache: 'no-store',
      // Las cookies de sesión son httpOnly: JavaScript no las ve ni las puede
      // adjuntar a mano. `credentials: include` es lo que hace que el
      // navegador las mande igual. Sin esto, no hay sesión.
      credentials: 'include',
    });
    if (res.status === 401) {
      const cuerpo = await res.json().catch(() => ({ detail: 'Sesión requerida.' }));
      throw new UnauthorizedError(cuerpo.detail ?? 'Sesión requerida.');
    }
    if (!res.ok) {
      const detail = await res.text().catch(() => '');
      throw new Error(`HTTP ${res.status} en ${path} :: ${detail.slice(0, 200)}`);
    }
    return (await res.json()) as T;
  } catch (err) {
    if (err instanceof Error && (err.name === 'AbortError' || err.name === 'TypeError')) {
      throw new ApiUnavailableError(err);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

/** Evita que N peticiones simultáneas disparen N renovaciones. */
let renovacionEnCurso: Promise<boolean> | null = null;

async function renovarSesion(): Promise<boolean> {
  renovacionEnCurso ??= raw<unknown>('/api/v1/auth/refresh', { method: 'POST' })
    .then(() => true)
    .catch(() => false)
    .finally(() => {
      renovacionEnCurso = null;
    });
  return renovacionEnCurso;
}

/**
 * Petición con renovación automática.
 *
 * El access token dura 15 minutos. Cuando vence, se intenta rotar el refresh
 * una sola vez y se reintenta; si eso también falla, la sesión terminó de
 * verdad y el llamador muestra la pantalla de acceso.
 */
async function request<T>(path: string, init?: RequestInit): Promise<T> {
  try {
    return await raw<T>(path, init);
  } catch (err) {
    if (!(err instanceof UnauthorizedError)) throw err;
    if (path.startsWith('/api/v1/auth/')) throw err;
    if (!(await renovarSesion())) throw err;
    return raw<T>(path, init);
  }
}

export function fetchFeed(params: {
  cursor?: string | null;
  limit?: number;
  severity?: Severity | null;
}): Promise<FeedResponse> {
  const qs = new URLSearchParams();
  if (params.cursor) qs.set('cursor', params.cursor);
  if (params.limit) qs.set('limit', String(params.limit));
  if (params.severity) qs.set('severity', params.severity);
  const query = qs.toString();
  // El feed es público. Si hay sesión, la cookie viaja igual y la API marca
  // las misiones fuera de rango; el callsign ya NO se manda por query.
  return request<FeedResponse>(`/api/v1/feed${query ? `?${query}` : ''}`);
}

export function fetchAnalyst(callsign: string): Promise<AnalystState> {
  return request<AnalystState>(`/api/v1/analysts/${encodeURIComponent(callsign)}`);
}

export function fetchRanks(): Promise<RankInfo[]> {
  return request<RankInfo[]>('/api/v1/ranks');
}

export function submitXPEvent(payload: {
  event: XPEventId;
  mission_id?: string;
  severity?: Severity;
}): Promise<LevelUpResponse> {
  // Sin `callsign`: la identidad sale del token del lado del servidor.
  return request<LevelUpResponse>('/api/v1/level-up', {
    method: 'POST',
    body: JSON.stringify({ severity: 'medium', ...payload }),
  });
}

// ══════════════════════════════════════════════════════════════════
//  Identidad
// ══════════════════════════════════════════════════════════════════

export function login(callsign: string, password: string) {
  return raw<{ callsign: string; role: string }>('/api/v1/auth/login', {
    method: 'POST',
    body: JSON.stringify({ callsign, password }),
  });
}

export function register(callsign: string, password: string) {
  return raw<{ callsign: string; role: string }>('/api/v1/auth/register', {
    method: 'POST',
    body: JSON.stringify({ callsign, password }),
  });
}

export function whoami(): Promise<Session> {
  return request<Session>('/api/v1/auth/me');
}

export function logout() {
  return raw<unknown>('/api/v1/auth/logout', { method: 'POST' });
}
