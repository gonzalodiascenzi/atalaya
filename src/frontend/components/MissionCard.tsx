'use client';

/**
 * ATALAYA // Tarjeta de misión.
 *
 * Cada IoC que entra por el feed se presenta como una orden de operación:
 * qué se detectó, bajo qué técnica de ATT&CK, y qué se espera del analista.
 * Los observables se renderizan SIEMPRE defanged y nunca como enlace.
 */

import { useState } from 'react';
import { SEVERITY_STYLE, type Mission, type XPEventId } from '@/lib/types';

interface Props {
  mission: Mission;
  index: number;
  onAction: (mission: Mission, event: XPEventId) => void;
  busy: boolean;
}

const TACTIC_LABEL: Record<string, string> = {
  'initial-access': 'Acceso inicial',
  execution: 'Ejecución',
  persistence: 'Persistencia',
  'privilege-escalation': 'Escalada',
  'defense-evasion': 'Evasión',
  'credential-access': 'Credenciales',
  discovery: 'Descubrimiento',
  'lateral-movement': 'Mov. lateral',
  collection: 'Recolección',
  'command-and-control': 'C2',
  exfiltration: 'Exfiltración',
  impact: 'Impacto',
};

function minutesAgo(iso: string): string {
  const diff = Math.max(0, Date.now() - new Date(iso).getTime());
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return 'AHORA';
  if (mins < 60) return `HACE ${mins}M`;
  return `HACE ${Math.floor(mins / 60)}H`;
}

export default function MissionCard({ mission, index, onAction, busy }: Props) {
  const [open, setOpen] = useState(index < 2);
  const [done, setDone] = useState<Set<number>>(new Set());
  const [copied, setCopied] = useState(false);
  const sev = SEVERITY_STYLE[mission.severity];

  const toggleObjective = (i: number) => {
    setDone((prev) => {
      const next = new Set(prev);
      if (next.has(i)) next.delete(i);
      else next.add(i);
      return next;
    });
  };

  const copyIoC = async () => {
    try {
      await navigator.clipboard.writeText(mission.ioc_pattern);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      // El portapapeles puede estar bloqueado por permisos: no es fatal.
      setCopied(false);
    }
  };

  const allDone = done.size === mission.objectives.length;

  return (
    <article
      className={`panel clip-corner animate-boot-in ${sev.border} ${
        mission.severity === 'critical' ? sev.glow : ''
      } ${mission.locked ? 'opacity-70' : ''}`}
      style={{ animationDelay: `${Math.min(index, 8) * 45}ms` }}
      aria-label={`Misión ${mission.mission_id}`}
    >
      {/* Franja de severidad */}
      <div
        className={`absolute left-0 top-0 h-full w-[3px] ${sev.bg} ${
          mission.severity === 'critical' ? 'animate-pulse-ring' : ''
        }`}
        aria-hidden
      />

      {/* Cabecera */}
      <header className="panel-header justify-between">
        <div className="flex items-center gap-2 truncate">
          <span className={`${sev.text} font-bold`}>◆</span>
          <span className="text-phosphor-dim">{mission.mission_id}</span>
          <span className={`chip ${sev.border} ${sev.text} ${sev.bg}`}>
            {sev.label}
          </span>
          {mission.locked && (
            <span className="chip border-void-600 text-phosphor-faint">
              ⛔ RANGO {mission.required_rank.replace(/_/g, ' ')}
            </span>
          )}
        </div>
        <div className="flex shrink-0 items-center gap-3 text-phosphor-faint">
          <span>{minutesAgo(mission.detected_at)}</span>
          <span className="hidden sm:inline">T-{mission.expires_in_minutes}M</span>
        </div>
      </header>

      <div className="space-y-3 p-4">
        {/* Título */}
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          className="group flex w-full items-start gap-2 text-left"
          aria-expanded={open}
        >
          <span className="mt-0.5 text-neon-green transition-transform duration-200 group-hover:translate-x-0.5">
            {open ? '▾' : '▸'}
          </span>
          <h3 className="flex-1 text-[15px] font-medium leading-snug text-phosphor group-hover:text-neon-green">
            {mission.title}
          </h3>
          <span className="shrink-0 text-2xs text-neon-amber">
            +{mission.xp_reward} XP
          </span>
        </button>

        {/* Metadatos siempre visibles */}
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="chip border-neon-cyan/40 bg-neon-cyan/5 text-neon-cyan">
            {mission.attack_technique}
          </span>
          <span className="chip border-void-600 text-phosphor-dim">
            {TACTIC_LABEL[mission.attack_tactic] ?? mission.attack_tactic}
          </span>
          <span className="chip border-neon-violet/40 bg-neon-violet/5 text-neon-violet">
            {mission.malware_family}
          </span>
          <span className="chip border-void-600 text-phosphor-faint">
            {mission.tlp}
          </span>
          <span className="chip border-void-600 text-phosphor-faint">
            {'▮'.repeat(mission.difficulty)}
            {'▯'.repeat(5 - mission.difficulty)}
          </span>
        </div>

        {open && (
          <div className="space-y-3 border-t border-void-600/60 pt-3">
            <p className="text-[13px] leading-relaxed text-phosphor-dim">
              {mission.briefing}
            </p>

            {/* Observable — defanged, seleccionable, jamás clickeable */}
            <div className="border border-void-600 bg-void/80">
              <div className="flex items-center justify-between border-b border-void-600 px-3 py-1.5">
                <span className="text-2xs uppercase tracking-[0.18em] text-phosphor-faint">
                  Indicador · neutralizado
                </span>
                <button
                  type="button"
                  onClick={copyIoC}
                  className="text-2xs uppercase tracking-[0.14em] text-neon-cyan hover:text-neon-green"
                >
                  {copied ? '✓ copiado' : 'copiar patrón stix'}
                </button>
              </div>
              <code className="block break-all px-3 py-2.5 text-[13px] text-neon-green">
                {mission.ioc_defanged}
              </code>
              <code className="block break-all border-t border-void-600/60 px-3 py-1.5 text-2xs text-phosphor-faint">
                {mission.ioc_pattern}
              </code>
            </div>

            {/* Objetivos */}
            <div>
              <p className="mb-1.5 text-2xs uppercase tracking-[0.18em] text-phosphor-faint">
                Objetivos de la operación · {done.size}/{mission.objectives.length}
              </p>
              <ul className="space-y-1">
                {mission.objectives.map((obj, i) => (
                  <li key={obj}>
                    <button
                      type="button"
                      onClick={() => toggleObjective(i)}
                      className="flex w-full items-start gap-2 text-left text-[13px] leading-relaxed"
                    >
                      <span
                        className={
                          done.has(i) ? 'text-neon-green' : 'text-phosphor-faint'
                        }
                      >
                        [{done.has(i) ? '✓' : ' '}]
                      </span>
                      <span
                        className={
                          done.has(i)
                            ? 'text-phosphor-faint line-through'
                            : 'text-phosphor-dim hover:text-phosphor'
                        }
                      >
                        {obj}
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            </div>

            {/* Acciones */}
            <div className="flex flex-wrap items-center gap-2 border-t border-void-600/60 pt-3">
              <button
                type="button"
                disabled={busy || mission.locked}
                onClick={() => onAction(mission, 'mission_triage')}
                className="btn-console border-neon-green/45 text-neon-green hover:bg-neon-green/10 hover:shadow-glow-green"
              >
                ▸ Triar
              </button>
              <button
                type="button"
                disabled={busy || mission.locked}
                onClick={() => onAction(mission, 'ioc_enriched')}
                className="btn-console border-neon-cyan/45 text-neon-cyan hover:bg-neon-cyan/10 hover:shadow-glow-cyan"
              >
                ▸ Enriquecer
              </button>
              <button
                type="button"
                disabled={busy || mission.locked || !allDone}
                title={
                  allDone
                    ? 'Verificar el indicador'
                    : 'Completá los objetivos antes de emitir veredicto'
                }
                onClick={() => onAction(mission, 'ioc_verified')}
                className="btn-console border-neon-magenta/45 text-neon-magenta hover:bg-neon-magenta/10 hover:shadow-glow-magenta"
              >
                ▸ Verificar
              </button>
              <button
                type="button"
                disabled={busy || mission.locked}
                onClick={() => onAction(mission, 'false_positive_published')}
                className="btn-console ml-auto border-severity-critical/40 text-severity-critical/80 hover:bg-severity-critical/10"
                title="Marcar como falso positivo. Si te equivocás, resta XP."
              >
                ▸ Falso positivo
              </button>
            </div>

            <p className="text-2xs text-phosphor-faint">
              Fuente: {mission.source} · refs STIX: {mission.object_refs.length || '—'}
            </p>
          </div>
        )}
      </div>
    </article>
  );
}
