/**
 * ATALAYA // Cliente de la API.
 *
 * Principio de diseño: la consola NUNCA se queda en blanco. Si la API no
 * responde, se degrada a los datos de siembra locales y se avisa en la barra
 * de estado. Un analista mirando un spinner infinito no está entrenando.
 */

import type {
  AnalystState,
  Calibration,
  FeedResponse,
  RankInfo,
  Session,
  VerdictResult,
  Severity,
} from './types';
import type { Call } from './scoring';

export const API_BASE =
    process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, '') ?? '';

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

/**
 * SHA-256 del cuerpo, en hexadecimal.
 *
 * En AWS la API sólo acepta pedidos firmados por CloudFront (OAC). CloudFront
 * firma, pero no calcula el hash del cuerpo: lo tiene que mandar el cliente
 * en `x-amz-content-sha256`. Sin él, todo POST muere con 403.
 */
export async function hashCuerpo(cuerpo: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(cuerpo));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

async function raw<T>(path: string, init?: RequestInit): Promise<T> {
  const metodo = (init?.method ?? 'GET').toUpperCase();
  const firma: Record<string, string> = {};
  if (metodo !== 'GET' && metodo !== 'HEAD') {
    // También sin cuerpo (renovar sesión, salir): se firma el hash del vacío.
    const cuerpo = typeof init?.body === 'string' ? init.body : '';
    firma['x-amz-content-sha256'] = await hashCuerpo(cuerpo);
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(`${API_BASE}${path}`, {
      ...init,
      signal: controller.signal,
      headers: { 'Content-Type': 'application/json', ...firma, ...(init?.headers ?? {}) },
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

// ══════════════════════════════════════════════════════════════════
//  Bucle de verificación
// ══════════════════════════════════════════════════════════════════

/** Error de negocio con el mensaje del servidor (ej: veredicto repetido). */
export class ApiRejection extends Error {
  constructor(public readonly status: number, public readonly detail: string) {
    super(detail);
    this.name = 'ApiRejection';
  }
}

export async function submitVerdict(
  missionId: string,
  payload: { call: Call; confidence: number; rationale?: string },
): Promise<VerdictResult> {
  try {
    return await request<VerdictResult>(
      `/api/v1/missions/${encodeURIComponent(missionId)}/verdict`,
      { method: 'POST', body: JSON.stringify(payload) },
    );
  } catch (err) {
    // 409 (ya emitido) y 422 (falta fundamento) traen un mensaje que el
    // analista tiene que leer tal cual: se rescata del cuerpo del error.
    if (err instanceof Error && !(err instanceof UnauthorizedError)) {
      const m = /HTTP (\d{3}) en [^:]+ :: (.*)$/s.exec(err.message);
      if (m) {
        let detalle = m[2];
        try {
          detalle = JSON.parse(detalle).detail ?? detalle;
        } catch {
          /* el cuerpo no era JSON */
        }
        throw new ApiRejection(Number(m[1]), String(detalle));
      }
    }
    throw err;
  }
}

export function fetchCalibration(callsign: string): Promise<Calibration> {
  return request<Calibration>(
    `/api/v1/analysts/${encodeURIComponent(callsign)}/calibration`,
  );
}
