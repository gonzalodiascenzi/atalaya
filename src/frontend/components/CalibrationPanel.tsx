'use client';

/**
 * ATALAYA // Panel de calibración.
 *
 * La XP dice cuánto trabajaste. Esto dice cuánto vale tu palabra: si cuando
 * decís "estoy seguro" efectivamente acertás. Es la pregunta que un jefe de
 * SOC realmente hace, y el número que ningún producto del rubro muestra.
 */

import { describeOverconfidence } from '@/lib/scoring';
import type { Calibration } from '@/lib/types';

interface Props {
  data: Calibration | null;
}

function pct(v: number | null): string {
  return v === null ? '—' : `${Math.round(v * 100)}%`;
}

export default function CalibrationPanel({ data }: Props) {
  const calificados = data?.verdicts_graded ?? 0;
  const pendientes = data?.verdicts_pending ?? 0;
  const cal = data?.calibration ?? null;
  const oc = data?.overconfidence ?? null;

  const tono =
    cal === null
      ? 'text-phosphor-faint'
      : cal >= 0.75
        ? 'text-neon-green'
        : cal >= 0.6
          ? 'text-neon-amber'
          : 'text-severity-critical';

  return (
    <section className="panel clip-corner" data-testid="panel-calibracion">
      <div className="panel-header justify-between">
        <span>
          <span className="text-neon-cyan">◎</span> calibración
        </span>
        <span className="text-phosphor-faint">{calificados} calificados</span>
      </div>

      <div className="space-y-3 p-4">
        {calificados === 0 ? (
          <p className="text-[13px] leading-relaxed text-phosphor-dim">
            Todavía no hay veredictos calificados.
            {pendientes > 0
              ? ` Tenés ${pendientes} sellado${pendientes > 1 ? 's' : ''} esperando que las fuentes corroboren.`
              : ' Emití tu primero: las misiones con verdad conocida se califican al instante.'}
          </p>
        ) : (
          <>
            <div className="flex items-end justify-between">
              <div>
                <div className={`text-3xl font-bold tabular-nums leading-none ${tono}`}>
                  {cal === null ? '—' : cal.toFixed(2)}
                </div>
                <div className="mt-1 text-2xs uppercase tracking-[0.14em] text-phosphor-faint">
                  índice · arriba de 0.75 es bueno
                </div>
              </div>
              <div className="text-right text-2xs text-phosphor-faint">
                <div>
                  acierto <span className="text-phosphor">{pct(data?.accuracy ?? null)}</span>
                </div>
                <div>
                  certeza media{' '}
                  <span className="text-phosphor">
                    {data?.mean_confidence === null || data?.mean_confidence === undefined
                      ? '—'
                      : `${Math.round(data.mean_confidence)}%`}
                  </span>
                </div>
              </div>
            </div>

            <div className="border-t border-void-600/60 pt-2">
              <div className="flex items-baseline justify-between text-2xs">
                <span className="uppercase tracking-[0.14em] text-phosphor-faint">sobreconfianza</span>
                <span className={`tabular-nums ${oc !== null && oc > 0.05 ? 'text-neon-amber' : 'text-phosphor'}`}>
                  {oc === null ? '—' : `${oc > 0 ? '+' : ''}${Math.round(oc * 100)} pts`}
                </span>
              </div>
              <p className="mt-1 text-[13px] text-phosphor-dim">{describeOverconfidence(oc)}</p>
            </div>

            {pendientes > 0 && (
              <p className="text-2xs text-neon-amber">
                ◷ {pendientes} veredicto{pendientes > 1 ? 's' : ''} sellado{pendientes > 1 ? 's' : ''} esperando corroboración
              </p>
            )}
          </>
        )}
      </div>
    </section>
  );
}
