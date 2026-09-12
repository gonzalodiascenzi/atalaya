'use client';

/**
 * ATALAYA // Consola de operaciones
 * ═══════════════════════════════════════════════════════════════════════
 * Panel del analista y calibración a la izquierda, Feed de Misiones al centro.
 *
 * La única acción que puntúa es el VEREDICTO: una llamada con su nivel de
 * certeza, calificada contra la verdad de referencia. Los botones de "triar"
 * y "enriquecer" que daban XP por clickear se fueron: eran exactamente el
 * clicker con estética de SOC que este producto viene a no ser.
 *
 * Degradación: si la API no responde, se muestra el catálogo local para que
 * la consola no quede en blanco — pero sin emitir veredictos, porque sin
 * servidor no hay verdad contra la cual calificar.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import AccessGate from '@/components/AccessGate';
import AnalystPanel from '@/components/AnalystPanel';
import CalibrationPanel from '@/components/CalibrationPanel';
import MissionCard from '@/components/MissionCard';
import StatusBar from '@/components/StatusBar';
import {
  fetchAnalyst,
  fetchCalibration,
  fetchFeed,
  fetchRanks,
  logout,
  UnauthorizedError,
  whoami,
} from '@/lib/api';
import { RANK_LEVEL, SEED_MISSIONS, SEED_RANKS } from '@/lib/seed';
import type {
  AnalystState,
  Calibration,
  Mission,
  RankInfo,
  Session,
  Severity,
  VerdictResult,
} from '@/lib/types';

const PAGE_SIZE = 8;

type Acceso =
  | 'verificando' // arranque: ¿hay sesión válida?
  | 'sin-sesion' // hay que identificarse
  | 'autenticado' // se puede operar
  | 'invitado'; // sin cuenta: se lee el feed, no se opera

type Tono = 'ok' | 'warn' | 'up';

const SEVERITIES: Array<{ id: Severity | 'all'; label: string; cls: string }> = [
  { id: 'all', label: 'todas', cls: 'border-void-600 text-phosphor-dim' },
  { id: 'critical', label: 'crítica', cls: 'border-severity-critical/60 text-severity-critical' },
  { id: 'high', label: 'alta', cls: 'border-severity-high/60 text-severity-high' },
  { id: 'medium', label: 'media', cls: 'border-severity-medium/60 text-severity-medium' },
  { id: 'low', label: 'baja', cls: 'border-severity-low/60 text-severity-low' },
];

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

export default function ConsolePage() {
  const [acceso, setAcceso] = useState<Acceso>('verificando');
  const [sesion, setSesion] = useState<Session | null>(null);
  const [analyst, setAnalyst] = useState<AnalystState>(() => emptyAnalyst());
  const [calibracion, setCalibracion] = useState<Calibration | null>(null);
  const [ranks, setRanks] = useState<RankInfo[]>(SEED_RANKS);
  const [missions, setMissions] = useState<Mission[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(true);
  const [total, setTotal] = useState(0);
  const [online, setOnline] = useState(true);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState<Severity | 'all'>('all');
  const [toast, setToast] = useState<{ text: string; tone: Tono } | null>(null);

  const sentinelRef = useRef<HTMLDivElement | null>(null);
  const loadingRef = useRef(false);
  const missionsRef = useRef<Mission[]>([]);
  const [onlyAvailable, setOnlyAvailable] = useState(false);

  const flash = useCallback((text: string, tone: Tono = 'ok') => {
    setToast({ text, tone });
    setTimeout(() => setToast(null), tone === 'up' ? 6000 : 4000);
  }, []);

  /* ── Feed ──────────────────────────────────────────────────────── */
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
        setHasMore(page.has_more);
        setTotal(page.total);
        setMissions((prev) => (reset ? page.missions : [...prev, ...page.missions]));
      } catch {
        // Sin API: el catálogo local, una sola vez. Antes se reciclaba en
        // bucle y la misma misión aparecía cada ocho tarjetas.
        setOnline(false);
        const local =
          filter === 'all' ? SEED_MISSIONS : SEED_MISSIONS.filter((m) => m.severity === filter);
        setMissions(local);
        setHasMore(false);
        setTotal(local.length);
      } finally {
        setLoading(false);
        loadingRef.current = false;
      }
    },
    [cursor, filter],
  );

  useEffect(() => {
    missionsRef.current = missions;
  }, [missions]);

  /* ── Actualización periódica: la torre no se queda vieja ───────── */
  const refreshFeed = useCallback(async () => {
    if (loadingRef.current) return;
    try {
      const limit = Math.min(100, Math.max(missionsRef.current.length, PAGE_SIZE));
      const page = await fetchFeed({
        cursor: null,
        limit,
        severity: filter === 'all' ? null : filter,
      });
      setOnline(true);
      setCursor(page.next_cursor);
      setHasMore(page.has_more);
      setTotal(page.total);
      setMissions(page.missions);
    } catch {
      // Silenciosa: sin servidor, se queda con lo que ya había en pantalla.
    }
  }, [filter]);

  /* ── Sesión ────────────────────────────────────────────────────── */
  const refrescarAnalista = useCallback(async (callsign: string) => {
    const [a, c] = await Promise.allSettled([fetchAnalyst(callsign), fetchCalibration(callsign)]);
    if (a.status === 'fulfilled') setAnalyst(a.value);
    if (c.status === 'fulfilled') setCalibracion(c.value);
  }, []);

  const cargarSesion = useCallback(async () => {
    try {
      const [yo, r] = await Promise.all([whoami(), fetchRanks()]);
      setSesion(yo);
      setRanks(r);
      setAcceso('autenticado');
      setOnline(true);
      await refrescarAnalista(yo.callsign);
    } catch (err) {
      if (!(err instanceof UnauthorizedError)) setOnline(false);
      setAcceso('sin-sesion');
    }
  }, [refrescarAnalista]);

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
    setCalibracion(null);
    setAnalyst(emptyAnalyst());
    setAcceso('sin-sesion');
  }, []);

  const sesionVencida = useCallback(() => {
    flash('Tu sesión venció. Volvé a identificarte.', 'warn');
    setAcceso('sin-sesion');
  }, [flash]);

  /* ── Recarga al cambiar filtro o identidad ─────────────────────── */
  // La identidad también recarga: el feed marca las misiones que ya operaste
  // y las que tu rango todavía no alcanza, y eso depende de quién sos.
  useEffect(() => {
    if (acceso === 'verificando' || acceso === 'sin-sesion') return;
    setCursor(null);
    setHasMore(true);
    setMissions([]);
    void loadPage(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter, acceso]);

  /* ── Refresco automático cada 5 minutos ────────────────────────── */
  useEffect(() => {
    if (acceso === 'verificando' || acceso === 'sin-sesion') return;
    const id = setInterval(() => void refreshFeed(), 5 * 60 * 1000);
    return () => clearInterval(id);
  }, [acceso, refreshFeed]);

  /* ── Scroll infinito, que ahora sí termina ─────────────────────── */
  useEffect(() => {
    const node = sentinelRef.current;
    if (!node || !hasMore) return;
    const io = new IntersectionObserver(
      (entries) => {
        if (entries[0]?.isIntersecting && !loadingRef.current && hasMore) {
          void loadPage(false);
        }
      },
      { rootMargin: '600px 0px' },
    );
    io.observe(node);
    return () => io.disconnect();
  }, [loadPage, hasMore]);

  /* ── Veredicto emitido ─────────────────────────────────────────── */
  const alEmitirVeredicto = useCallback(
    async (mission: Mission, res: VerdictResult) => {
      // La tarjeta pasa a mostrar el veredicto sellado sin esperar al feed.
      setMissions((prev) =>
        prev.map((m) =>
          m.mission_id === mission.mission_id
            ? {
                ...m,
                my_verdict: {
                  call: res.call,
                  confidence: res.confidence,
                  graded: res.graded,
                  xp_awarded: res.xp_awarded,
                  was_correct: res.was_correct,
                  brier_score: res.brier_score,
                },
              }
            : m,
        ),
      );
      const nivelAntes = analyst.level;
      if (sesion) await refrescarAnalista(sesion.callsign);
      flash(
        res.message,
        res.graded && res.was_correct === false ? 'warn' : nivelAntes < analyst.level ? 'up' : 'ok',
      );
    },
    [analyst.level, sesion, refrescarAnalista, flash],
  );

  /* ── Re-evaluación de bloqueos al ascender ─────────────────────── */
  useEffect(() => {
    setMissions((prev) =>
      prev.map((m) => ({ ...m, locked: RANK_LEVEL[m.required_rank] > analyst.level })),
    );
  }, [analyst.level]);

  const puedeOperar = acceso === 'autenticado' && online;
  const criticas = missions.filter((m) => m.severity === 'critical').length;
  const fuentes = Array.from(new Set(missions.map((m) => m.source))).slice(0, 6);
  const pendientes = missions.filter((m) => !m.my_verdict && !m.locked).length;
  const bloqueadas = missions.filter((m) => m.locked).length;
  const visibleMissions = onlyAvailable ? missions.filter((m) => !m.locked) : missions;

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
        missionCount={total}
        criticalCount={criticas}
        sources={fuentes.length ? fuentes : ['CISA KEV', 'abuse.ch', 'AlienVault OTX']}
        session={sesion}
        onLogout={cerrarSesion}
      />

      {acceso === 'invitado' && (
        <div className="border-b border-neon-amber/40 bg-neon-amber/10 px-4 py-2 text-center text-2xs uppercase tracking-[0.16em] text-neon-amber">
          modo invitado · podés leer el feed, pero no emitir veredictos ·{' '}
          <button onClick={() => setAcceso('sin-sesion')} className="underline hover:text-neon-green">
            identificarse
          </button>
        </div>
      )}
      {!online && (
        <div className="border-b border-severity-critical/40 bg-severity-critical/10 px-4 py-2 text-center text-2xs uppercase tracking-[0.16em] text-severity-critical">
          sin conexión con la torre · catálogo local de muestra · los veredictos necesitan servidor
        </div>
      )}

      <main className="mx-auto flex max-w-[1600px] flex-col gap-4 px-4 py-5 lg:flex-row">
        <div className="flex w-full flex-col gap-3 lg:w-[310px] lg:shrink-0">
          <AnalystPanel analyst={analyst} ranks={ranks} online={online} />
          {acceso === 'autenticado' && <CalibrationPanel data={calibracion} />}
        </div>

        <section className="min-w-0 flex-1">
          <div className="panel clip-corner mb-4">
            <div className="panel-header justify-between">
              <span>
                <span className="text-neon-green">▸</span> feed de misiones
              </span>
              <span className="text-phosphor-faint">
                {online
                  ? `${total} en la torre · ${pendientes} sin operar${
                      onlyAvailable && bloqueadas > 0 ? ` · ${bloqueadas} ocultas por rango` : ''
                    }`
                  : 'catálogo local'}
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
              <span className="mx-1 h-4 w-px bg-void-600" aria-hidden />
              <button
                type="button"
                onClick={() => setOnlyAvailable((v) => !v)}
                className={`btn-console border-neon-cyan/60 text-neon-cyan ${
                  onlyAvailable ? 'bg-void-700 shadow-glow-cyan' : 'hover:bg-void-800'
                }`}
              >
                solo mi rango{bloqueadas > 0 ? ` (${bloqueadas} ocultas)` : ''}
              </button>
            </div>
          </div>

          <div className="space-y-3">
            {visibleMissions.length === 0 ? (
              <div className="panel clip-corner p-6 text-center text-2xs uppercase tracking-[0.16em] text-phosphor-faint">
                ▪ ninguna misión operable a tu rango todavía · subí de nivel o desactivá el filtro ▪
              </div>
            ) : (
              visibleMissions.map((m, i) => (
                <MissionCard
                  key={m.mission_id}
                  mission={m}
                  index={i}
                  canOperate={puedeOperar}
                  onVerdict={alEmitirVeredicto}
                  onSessionExpired={sesionVencida}
                />
              ))
            )}
          </div>

          <div ref={sentinelRef} className="py-8 text-center">
            {loading ? (
              <span className="text-2xs uppercase tracking-[0.2em] text-neon-green">
                ▚▚▚ recuperando inteligencia ▚▚▚
              </span>
            ) : hasMore ? (
              <span className="text-2xs uppercase tracking-[0.2em] text-phosphor-faint">
                desplazá para seguir recibiendo
              </span>
            ) : (
              <span className="text-2xs uppercase tracking-[0.2em] text-phosphor-faint" data-testid="fin-del-feed">
                ▪ fin del feed · la torre sigue ingiriendo cada 15 minutos ▪
              </span>
            )}
          </div>
        </section>
      </main>

      {toast && (
        <div
          role="status"
          aria-live="polite"
          className={`fixed bottom-5 left-1/2 z-[60] w-[min(92vw,680px)] -translate-x-1/2 border px-4 py-3 text-[13px] backdrop-blur-md ${
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
        ATALAYA · STIX 2.1 · MITRE ATT&CK · CISA KEV · abuse.ch · AlienVault OTX
      </footer>
    </div>
  );
}
