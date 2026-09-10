'use client';

/**
 * ATALAYA // Panel del analista (columna izquierda).
 *
 * Responde tres preguntas de un vistazo: quién sos, cuánto te falta para el
 * próximo rango, y qué desbloquea ese rango. La barra de XP es el único
 * elemento con animación permanente: es el gancho.
 */

import type { AnalystState, RankInfo, RankId } from '@/lib/types';
import { RANK_STYLE } from '@/lib/types';

interface Props {
  analyst: AnalystState;
  ranks: RankInfo[];
  online: boolean;
}

const RANK_GLYPH: Record<RankId, string> = {
  NOVATO: '◇',
  ANALISTA_JUNIOR: '◈',
  ANALISTA_SENIOR: '◆',
  CAZADOR_DE_AMENAZAS: '✦',
};

function Stat({ label, value, accent }: { label: string; value: string | number; accent: string }) {
  return (
    <div className="border border-void-600/70 bg-void-800/50 px-2.5 py-2">
      <div className={`text-lg font-bold leading-none ${accent}`}>{value}</div>
      <div className="mt-1 text-2xs uppercase tracking-[0.12em] text-phosphor-faint">
        {label}
      </div>
    </div>
  );
}

export default function AnalystPanel({ analyst, ranks, online }: Props) {
  const style = RANK_STYLE[analyst.rank];
  const pct = Math.round(analyst.progress * 100);
  const currentLevel = analyst.level;

  return (
    <aside className="flex w-full flex-col gap-3">
      {/* ── Identidad ─────────────────────────────────────────── */}
      <section className={`panel clip-corner ${style.border}`}>
        <div className="panel-header">
          <span className="text-neon-green">●</span> expediente del analista
        </div>

        <div className="space-y-4 p-4">
          <div className="flex items-center gap-3">
            <div
              className={`flex h-14 w-14 shrink-0 items-center justify-center border text-2xl ${style.border} ${style.text} ${style.shadow}`}
            >
              {RANK_GLYPH[analyst.rank]}
            </div>
            <div className="min-w-0">
              <div className="truncate text-[15px] font-bold uppercase tracking-[0.1em] text-phosphor">
                {analyst.callsign}
                <span className="animate-caret text-neon-green">_</span>
              </div>
              <div className={`truncate text-2xs uppercase tracking-[0.16em] ${style.text}`}>
                {analyst.rank_label}
              </div>
              <div className="mt-0.5 text-2xs text-phosphor-faint">
                NIVEL {analyst.level} · CLEARANCE {analyst.clearance}
              </div>
            </div>
          </div>

          {/* ── Barra de XP ─────────────────────────────────────── */}
          <div>
            <div className="mb-1 flex items-baseline justify-between text-2xs">
              <span className="uppercase tracking-[0.16em] text-phosphor-faint">
                Experiencia
              </span>
              <span className={style.text}>
                {analyst.xp.toLocaleString('es-AR')} XP
              </span>
            </div>
            <div className="relative h-2.5 w-full overflow-hidden border border-void-600 bg-void">
              <div
                className={`animate-xp-fill h-full transition-[width] duration-700 ease-snap ${
                  analyst.rank === 'NOVATO'
                    ? 'bg-neon-green'
                    : analyst.rank === 'ANALISTA_JUNIOR'
                      ? 'bg-neon-cyan'
                      : analyst.rank === 'ANALISTA_SENIOR'
                        ? 'bg-neon-magenta'
                        : 'bg-neon-amber'
                }`}
                style={{ width: `${Math.max(2, pct)}%` }}
              />
              {/* Marcas de la regla */}
              <div className="pointer-events-none absolute inset-0 flex justify-between px-[1px]">
                {Array.from({ length: 20 }).map((_, i) => (
                  <span key={i} className="w-px bg-void/70" />
                ))}
              </div>
            </div>
            <div className="mt-1 flex justify-between text-2xs text-phosphor-faint">
              <span>{pct}%</span>
              <span>
                {analyst.next_rank
                  ? `faltan ${analyst.xp_to_next.toLocaleString('es-AR')} XP`
                  : 'rango máximo alcanzado'}
              </span>
            </div>
          </div>

          {/* ── Métricas ────────────────────────────────────────── */}
          <div className="grid grid-cols-3 gap-2">
            <Stat label="misiones" value={analyst.missions_completed} accent="text-neon-green" />
            <Stat label="IoC verif." value={analyst.iocs_verified} accent="text-neon-cyan" />
            <Stat label="racha" value={`x${analyst.streak}`} accent="text-neon-amber" />
          </div>

          {/* ── Capacidades ─────────────────────────────────────── */}
          <div>
            <p className="mb-1.5 text-2xs uppercase tracking-[0.16em] text-phosphor-faint">
              Capacidades habilitadas
            </p>
            <div className="flex flex-wrap gap-1">
              {analyst.unlocks.map((u) => (
                <span key={u} className={`chip ${style.border} ${style.text} bg-void-800/60`}>
                  {u}
                </span>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ── Escalera de rangos ──────────────────────────────────── */}
      <section className="panel clip-corner">
        <div className="panel-header">
          <span className="text-neon-cyan">▚</span> cadena de mando
        </div>
        <ol className="p-3">
          {ranks.map((r, i) => {
            const reached = currentLevel >= r.level;
            const isCurrent = currentLevel === r.level;
            const rs = RANK_STYLE[r.rank];
            return (
              <li key={r.rank} className="relative flex gap-3 pb-3 last:pb-0">
                {/* Línea vertical del árbol */}
                {i < ranks.length - 1 && (
                  <span
                    className={`absolute left-[7px] top-4 h-full w-px ${
                      reached ? 'bg-neon-green/40' : 'bg-void-600'
                    }`}
                    aria-hidden
                  />
                )}
                <span
                  className={`relative z-10 mt-0.5 h-3.5 w-3.5 shrink-0 border ${
                    isCurrent
                      ? `${rs.border} ${rs.shadow} bg-void`
                      : reached
                        ? 'border-neon-green/50 bg-neon-green/40'
                        : 'border-void-600 bg-void-800'
                  }`}
                  aria-hidden
                />
                <div className="min-w-0 flex-1">
                  <div className="flex items-baseline justify-between gap-2">
                    <span
                      className={`text-[13px] ${
                        isCurrent
                          ? `${rs.text} font-bold`
                          : reached
                            ? 'text-phosphor-dim'
                            : 'text-phosphor-faint'
                      }`}
                    >
                      {r.level}. {r.label}
                    </span>
                    <span className="shrink-0 text-2xs text-phosphor-faint">
                      {r.xp_required.toLocaleString('es-AR')} XP
                    </span>
                  </div>
                  <div className="text-2xs text-phosphor-faint">
                    {isCurrent ? '▸ POSICIÓN ACTUAL' : r.clearance}
                  </div>
                </div>
              </li>
            );
          })}
        </ol>
      </section>

      {/* ── Bitácora ────────────────────────────────────────────── */}
      <section className="panel clip-corner">
        <div className="panel-header justify-between">
          <span>
            <span className="text-neon-magenta">▸</span> bitácora
          </span>
          <span className={online ? 'text-neon-green' : 'text-neon-amber'}>
            {online ? 'sincronizada' : 'local'}
          </span>
        </div>
        <div className="max-h-52 overflow-y-auto p-3 text-2xs leading-relaxed">
          {analyst.recent_events.length === 0 ? (
            <p className="text-phosphor-faint">
              Sin actividad registrada. Operá una misión para abrir la bitácora.
            </p>
          ) : (
            <ul className="space-y-1">
              {analyst.recent_events.map((e, i) => {
                const delta = Number(e.xp_delta ?? 0);
                return (
                  <li key={`${String(e.at)}-${i}`} className="flex gap-2">
                    <span className="text-phosphor-faint">
                      {String(e.at ?? '').slice(11, 19)}
                    </span>
                    <span className="flex-1 truncate text-phosphor-dim">
                      {String(e.event ?? '')}
                    </span>
                    <span className={delta < 0 ? 'text-severity-critical' : 'text-neon-green'}>
                      {delta > 0 ? '+' : ''}
                      {delta}
                    </span>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      </section>
    </aside>
  );
}
