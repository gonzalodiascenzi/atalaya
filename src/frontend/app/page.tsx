'use client';

/**
 * ATALAYA // Consola de operaciones
 * ═══════════════════════════════════════════════════════════════════════
 * Pantalla principal: panel del analista a la izquierda, Feed de Misiones al
 * centro con scroll infinito.
 *
 * Decisión de diseño clave — DEGRADACIÓN AUTÓNOMA:
 * si la API no responde, la consola no muestra un error y se muere: cambia a
 * "modo autónomo", sirve el catálogo local de siembra y calcula la progresión
 * del lado del cliente. Un entorno de entrenamiento que se cae cuando se cae
 * el backend no entrena a nadie.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import AccessGate from '@/components/AccessGate';
import AnalystPanel from '@/components/AnalystPanel';
import MissionCard from '@/components/MissionCard';
import StatusBar from '@/components/StatusBar';
import {
  fetchAnalyst,
  fetchFeed,
  fetchRanks,
  logout,
  submitXPEvent,
  UnauthorizedError,
  whoami,
} from '@/lib/api';
import {
  RANK_LEVEL,
  SEED_MISSIONS,
  SEED_RANKS,
  SEED_SEVERITY_MULTIPLIER,
  SEED_XP_TABLE,
  rankForXP,
} from '@/lib/seed';
import type {
  AnalystState,
  Mission,
  RankInfo,
  Session,
  Severity,
  XPEventId,
} from '@/lib/types';

const PAGE_SIZE = 6;

/** Tres estados posibles de la consola, y sólo tres. */
type Acceso =
  | 'verificando' // arranque: ¿hay sesión válida?
  | 'sin-sesion' // hay que identificarse
  | 'autenticado' // se puede operar
  | 'invitado'; // sin cuenta: se lee el feed, no se opera

const SEVERITIES: Array<{ id: Severity | 'all'; label: string; cls: string }> = [
  { id: 'all', label: 'todas', cls: 'border-void-600 text-phosphor-dim' },
  { id: 'critical', label: 'crítica', cls: 'border-severity-critical/60 text-severity-critical' },
  { id: 'high', label: 'alta', cls: 'border-severity-high/60 text-severity-high' },
  { id: 'medium', label: 'media', cls: 'border-severity-medium/60 text-severity-medium' },
  { id: 'low', label: 'baja', cls: 'border-severity-low/60 text-severity-low' },
];

/** Estado inicial del analista antes de que responda la API. */
function emptyAnalyst(callsign = 'invitado'): AnalystState {
  const rank = SEED_RANKS[0];
  return {
    callsign,
    xp: 0,
    rank: rank.rank,
    rank_label: rank.label,
    level: rank.level,
    clearance: rank.clearance,
    unlocks: rank.unlocks,
    next_rank: SEED_RANKS[1].rank,
    xp_to_next: SEED_RANKS[1].xp_required,
    progress: 0,
    missions_completed: 0,
    iocs_verified: 0,
    streak: 0,
    joined_at: new Date().toISOString(),
    last_event_at: null,
    recent_events: [],
  };
}

/**
 * Progresión local para el modo autónomo.
 * Espeja la lógica de `gamification.py`: las penalizaciones no se multiplican
 * por severidad y la XP nunca baja de cero.
 */
function applyLocalXP(
  analyst: AnalystState,
  event: XPEventId,
  severity: Severity,
): { next: AnalystState; promoted: boolean; delta: number } {
  const base = SEED_XP_TABLE[event] ?? 0;
  const delta =
    base < 0 ? base : Math.round(base * (SEED_SEVERITY_MULTIPLIER[severity] ?? 1));

  const beforeLevel = analyst.level;
  const xp = Math.max(0, analyst.xp + delta);
  const spec = rankForXP(xp);
  const nextSpec = SEED_RANKS.find((r) => r.level === spec.level + 1) ?? null;
  const span = nextSpec ? nextSpec.xp_required - spec.xp_required : 1;

  return {
    delta,
    promoted: spec.level > beforeLevel,
    next: {
      ...analyst,
      xp,
      rank: spec.rank,
      rank_label: spec.label,
      level: spec.level,
      clearance: spec.clearance,
      unlocks: spec.unlocks,
      next_rank: nextSpec?.rank ?? null,
      xp_to_next: nextSpec ? Math.max(0, nextSpec.xp_required - xp) : 0,
      progress: nextSpec ? Math.min(1, (xp - spec.xp_required) / span) : 1,
      missions_completed:
        analyst.missions_completed + (event === 'mission_triage' ? 1 : 0),
      iocs_verified:
        analyst.iocs_verified +
        (event === 'ioc_verified' || event === 'correlation_confirmed' ? 1 : 0),
      streak: delta > 0 ? analyst.streak + 1 : 0,
      last_event_at: new Date().toISOString(),
      recent_events: [
        { event, xp_delta: delta, xp_total: xp, at: new Date().toISOString() },
        ...analyst.recent_events,
      ].slice(0, 10),
    },
  };
}

export default function ConsolePage() {
  const [acceso, setAcceso] = useState<Acceso>('verificando');
  const [sesion, setSesion] = useState<Session | null>(null);
  const [analyst, setAnalyst] = useState<AnalystState>(() => emptyAnalyst());
  const [ranks, setRanks] = useState<RankInfo[]>(SEED_RANKS);
  const [missions, setMissions] = useState<Mission[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [online, setOnline] = useState(true);
  const [booted, setBooted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState<Severity | 'all'>('all');
  const [toast, setToast] = useState<{ text: string; tone: 'ok' | 'warn' | 'up' } | null>(
    null,
  );
  const [busy, setBusy] = useState(false);

  const sentinelRef = useRef<HTMLDivElement | null>(null);
  const loadingRef = useRef(false);
  const seedPage = useRef(0);

  const flash = useCallback((text: string, tone: 'ok' | 'warn' | 'up' = 'ok') => {
    setToast({ text, tone });
    setTimeout(() => setToast(null), tone === 'up' ? 5200 : 3200);
  }, []);

  /** Genera la siguiente página en modo autónomo, ciclando el catálogo. */
  const seedSlice = useCallback((): Mission[] => {
    const pool =
      filter === 'all' ? SEED_MISSIONS : SEED_MISSIONS.filter((m) => m.severity === filter);
    if (pool.length === 0) return [];
    const start = seedPage.current * PAGE_SIZE;
    seedPage.current += 1;
    return Array.from({ length: PAGE_SIZE }, (_, i) => {
      const base = pool[(start + i) % pool.length];
      const cycle = Math.floor((start + i) / pool.length);
      // Cada ciclo produce IDs únicos: React necesita keys estables y únicas.
      return cycle === 0
        ? base
        : { ...base, mission_id: `${base.mission_id}-R${cycle}` };
    });
  }, [filter]);

  const loadPage = useCallback(
    async (reset = false) => {
      if (loadingRef.current) return;
      loadingRef.current = true;
      setLoading(true);
      try {
        const page = await fetchFeed({
          cursor: reset ? null : cursor,
          limit: PAGE_SIZE,
          severity: filter === 'all' ? null : filter,
        });
        setOnline(true);
        setCursor(page.next_cursor);
        setMissions((prev) => {
          const incoming = reset ? page.missions : [...prev, ...page.missions];
          // El feed cicla el catálogo a propósito (flujo continuo), así que
          // el mismo mission_id puede volver a aparecer. Se le agrega un
          // sufijo de repetición para que las keys de React sigan siendo
          // únicas sin perder la trazabilidad al ID original.
          const seen = new Map<string, number>();
          return incoming.map((m) => {
            const times = seen.get(m.mission_id) ?? 0;
            seen.set(m.mission_id, times + 1);
            return times === 0 ? m : { ...m, mission_id: `${m.mission_id}-R${times}` };
          });
        });
      } catch {
        // ── Degradación a modo autónomo ──────────────────────────
        setOnline(false);
        if (reset) seedPage.current = 0;
        const slice = seedSlice();
        setMissions((prev) => (reset ? slice : [...prev, ...slice]));
        if (!booted) flash('API fuera de línea · modo autónomo con catálogo local', 'warn');
      } finally {
        setBooted(true);
        setLoading(false);
        loadingRef.current = false;
      }
    },
    [cursor, filter, seedSlice, booted, flash],
  );

  /* ── Arranque: ¿quién sos? ─────────────────────────────────────── */
  const cargarSesion = useCallback(async () => {
    try {
      const [yo, r] = await Promise.all([whoami(), fetchRanks()]);
      setSesion(yo);
      setRanks(r);
      setAcceso('autenticado');
      setAnalyst(await fetchAnalyst(yo.callsign));
      setOnline(true);
    } catch (err) {
      if (err instanceof UnauthorizedError) {
        setAcceso('sin-sesion');
      } else {
        // La API no responde: se puede seguir en modo autónomo, pero sin
        // sesión no hay progresión que registrar.
        setOnline(false);
        setAcceso('sin-sesion');
      }
    }
  }, []);

  useEffect(() => {
    void cargarSesion();
  }, [cargarSesion]);

  const cerrarSesion = useCallback(async () => {
    try {
      await logout();
    } catch {
      /* si la API no responde, igual se limpia el estado local */
    }
    setSesion(null);
    setAnalyst(emptyAnalyst());
    setAcceso('sin-sesion');
  }, []);

  /* ── Recarga al cambiar el filtro ──────────────────────────────── */
  useEffect(() => {
    seedPage.current = 0;
    setCursor(null);
    setMissions([]);
    void loadPage(true);
    // Sólo el filtro dispara una recarga completa del feed.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter]);

  /* ── Scroll infinito ───────────────────────────────────────────── */
  useEffect(() => {
    const node = sentinelRef.current;
    if (!node) return;
    const io = new IntersectionObserver(
      (entries) => {
        if (entries[0]?.isIntersecting && !loadingRef.current && booted) {
          void loadPage(false);
        }
      },
      { rootMargin: '600px 0px' },
    );
    io.observe(node);
    return () => io.disconnect();
  }, [loadPage, booted]);

  /* ── Acciones sobre una misión ─────────────────────────────────── */
  const handleAction = useCallback(
    async (mission: Mission, event: XPEventId) => {
      setBusy(true);
      // Sin sesión no se opera: la progresión necesita saber quién sos, y
      // dejar clickear para después descartar el resultado sería peor que
      // decirlo de frente.
      if (acceso === 'invitado') {
        flash('Necesitás una cuenta para operar misiones.', 'warn');
        setBusy(false);
        return;
      }
      try {
        if (online && acceso === 'autenticado') {
          const res = await submitXPEvent({
            event,
            mission_id: mission.mission_id.split('-R')[0],
            severity: mission.severity,
          });
          const fresh = await fetchAnalyst(res.callsign);
          setAnalyst(fresh);
          flash(res.message, res.promoted ? 'up' : res.xp_delta < 0 ? 'warn' : 'ok');
        } else {
          const { next, promoted, delta } = applyLocalXP(analyst, event, mission.severity);
          setAnalyst(next);
          flash(
            promoted
              ? `>> ASCENSO CONFIRMADO :: ${next.rank_label.toUpperCase()} :: clearance ${next.clearance}`
              : delta < 0
                ? '>> INTELIGENCIA REFUTADA :: -XP aplicada :: revisá tu metodología'
                : `>> +${delta} XP :: registrado en la torre (local)`,
            promoted ? 'up' : delta < 0 ? 'warn' : 'ok',
          );
        }
      } catch (err) {
        if (err instanceof UnauthorizedError) {
          flash('Tu sesión venció. Volvé a identificarte.', 'warn');
          setAcceso('sin-sesion');
        } else {
          flash('No se pudo registrar el evento. Reintentá.', 'warn');
        }
      } finally {
        setBusy(false);
      }
    },
    [analyst, online, acceso, flash],
  );

  /* ── Re-evaluación de bloqueos al ascender ─────────────────────── */
  useEffect(() => {
    setMissions((prev) =>
      prev.map((m) => ({
        ...m,
        locked: RANK_LEVEL[m.required_rank] > analyst.level,
      })),
    );
  }, [analyst.level]);

  const criticals = missions.filter((m) => m.severity === 'critical').length;
  const sources = Array.from(new Set(missions.map((m) => m.source))).slice(0, 6);

  if (acceso === 'verificando') {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <span className="animate-flicker text-2xs uppercase tracking-[0.28em] text-neon-green">
          ▚▚▚ estableciendo enlace con la torre ▚▚▚
        </span>
      </div>
    );
  }

  if (acceso === 'sin-sesion') {
    return (
      <AccessGate
        onAuthenticated={() => {
          setAcceso('verificando');
          void cargarSesion();
        }}
        onOffline={() => setAcceso('invitado')}
      />
    );
  }

  return (
    <div className="min-h-screen">
      <StatusBar
        online={online}
        missionCount={missions.length}
        criticalCount={criticals}
        sources={
          sources.length
            ? sources
            : ['abuse.ch', 'AlienVault OTX', 'CISA KEV', 'MISP', 'SpiderFoot']
        }
        session={sesion}
        onLogout={cerrarSesion}
      />

      {acceso === 'invitado' && (
        <div className="border-b border-neon-amber/40 bg-neon-amber/10 px-4 py-2 text-center text-2xs uppercase tracking-[0.16em] text-neon-amber">
          modo invitado · podés leer el feed, pero no operar ·{' '}
          <button
            onClick={() => setAcceso('sin-sesion')}
            className="underline hover:text-neon-green"
          >
            identificarse
          </button>
        </div>
      )}

      <main className="mx-auto flex max-w-[1600px] flex-col gap-4 px-4 py-5 lg:flex-row">
        <AnalystPanel analyst={analyst} ranks={ranks} online={online} />

        {/* ── Feed de Misiones ──────────────────────────────────── */}
        <section className="min-w-0 flex-1">
          <div className="panel clip-corner mb-4">
            <div className="panel-header justify-between">
              <span>
                <span className="text-neon-green">▸</span> feed de misiones ·
                tiempo real
              </span>
              <span className="text-phosphor-faint">
                {online ? 'origen: opencti/misp' : 'origen: catálogo local'}
              </span>
            </div>
            <div className="flex flex-wrap items-center gap-2 p-3">
              <span className="text-2xs uppercase tracking-[0.16em] text-phosphor-faint">
                filtrar severidad:
              </span>
              {SEVERITIES.map((s) => (
                <button
                  key={s.id}
                  type="button"
                  onClick={() => setFilter(s.id)}
                  className={`btn-console ${s.cls} ${
                    filter === s.id ? 'bg-void-700 shadow-glow-green' : 'hover:bg-void-800'
                  }`}
                >
                  {s.label}
                </button>
              ))}
              <span className="ml-auto text-2xs text-phosphor-faint">
                {missions.length} en cola
              </span>
            </div>
          </div>

          {/* Línea de comando decorativa: marca el tono del entorno */}
          <div className="mb-4 border border-void-600/60 bg-void-900/50 px-3 py-2 text-2xs text-phosphor-faint">
            <span className="text-neon-green">atalaya@torre</span>
            <span className="text-phosphor-dim">:~$</span> watch --interval=15s{' '}
            <span className="text-neon-cyan">ingest --source=all --format=stix2.1</span>
            <span className="animate-caret text-neon-green">█</span>
          </div>

          <div className="space-y-3">
            {missions.map((m, i) => (
              <MissionCard
                key={`${m.mission_id}-${i}`}
                mission={m}
                index={i}
                onAction={handleAction}
                busy={busy}
              />
            ))}
          </div>

          {/* Centinela del scroll infinito */}
          <div ref={sentinelRef} className="py-8 text-center">
            {loading ? (
              <span className="text-2xs uppercase tracking-[0.2em] text-neon-green">
                ▚▚▚ recuperando inteligencia ▚▚▚
              </span>
            ) : (
              <span className="text-2xs uppercase tracking-[0.2em] text-phosphor-faint">
                desplazá para seguir recibiendo
              </span>
            )}
          </div>
        </section>
      </main>

      {/* ── Aviso flotante ──────────────────────────────────────── */}
      {toast && (
        <div
          role="status"
          aria-live="polite"
          className={`fixed bottom-5 left-1/2 z-[60] w-[min(92vw,640px)] -translate-x-1/2 border px-4 py-3 text-[13px] backdrop-blur-md ${
            toast.tone === 'up'
              ? 'animate-glitch-x border-neon-amber bg-void-900/95 text-neon-amber shadow-glow-amber'
              : toast.tone === 'warn'
                ? 'border-severity-critical/70 bg-void-900/95 text-severity-critical'
                : 'border-neon-green/60 bg-void-900/95 text-neon-green shadow-glow-green'
          }`}
        >
          {toast.text}
        </div>
      )}

      <footer className="border-t border-void-600/60 px-4 py-6 text-center text-2xs uppercase tracking-[0.2em] text-phosphor-faint">
        ATALAYA · STIX 2.1 · MITRE ATT&CK · indicadores sintéticos RFC 5737 / RFC 2606
      </footer>
    </div>
  );
}
