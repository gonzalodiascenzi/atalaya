'use client';

/**
 * ATALAYA // Panel de veredicto.
 *
 * No es un botón: es una apuesta declarada. El analista elige una llamada y
 * cuánta certeza tiene, y mientras mueve el deslizador ve exactamente cuánto
 * gana si acierta y cuánto pierde si se equivoca.
 *
 * Esa vista previa es la regla del juego explicada sin una sola palabra de
 * teoría: al 50% muestra "+0 / −0" y cualquiera entiende que cubrirse no paga.
 */

import { useMemo, useState } from 'react';
import { ApiRejection, submitVerdict, UnauthorizedError } from '@/lib/api';
import {
  MAX_CONFIDENCE,
  MIN_CONFIDENCE,
  payoff,
  RATIONALE_REQUIRED_AT,
  requiresRationale,
  type Call,
} from '@/lib/scoring';
import type { Mission, MyVerdict, VerdictResult } from '@/lib/types';

interface Props {
  mission: Mission;
  canOperate: boolean;
  onSubmitted: (mission: Mission, result: VerdictResult) => void;
  onSessionExpired: () => void;
}

const LLAMADAS: Array<{ id: Call; label: string; cls: string; activo: string }> = [
  {
    id: 'MALICIOUS',
    label: 'malicioso',
    cls: 'border-severity-critical/50 text-severity-critical',
    activo: 'bg-severity-critical/15 shadow-glow-critical',
  },
  {
    id: 'BENIGN',
    label: 'benigno',
    cls: 'border-neon-green/50 text-neon-green',
    activo: 'bg-neon-green/15 shadow-glow-green',
  },
  {
    id: 'INCONCLUSIVE',
    label: 'no concluyente',
    cls: 'border-void-600 text-phosphor-dim',
    activo: 'bg-void-700',
  },
];

export default function VerdictPanel({
  mission,
  canOperate,
  onSubmitted,
  onSessionExpired,
}: Props) {
  const [call, setCall] = useState<Call | null>(null);
  const [confianza, setConfianza] = useState(70);
  const [fundamento, setFundamento] = useState('');
  const [enviando, setEnviando] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const pago = useMemo(
    () => (call ? payoff(call, confianza, mission.xp_reward) : null),
    [call, confianza, mission.xp_reward],
  );

  if (mission.my_verdict) {
    return <VeredictoEmitido veredicto={mission.my_verdict} mission={mission} />;
  }

  if (!canOperate) {
    return (
      <p className="border border-void-600 bg-void/60 px-3 py-2 text-2xs uppercase tracking-[0.14em] text-phosphor-faint">
        {mission.locked
          ? `⛔ requiere rango ${mission.required_rank.replace(/_/g, ' ')}`
          : 'identificate para emitir veredictos'}
      </p>
    );
  }

  const faltaFundamento =
    call !== null &&
    call !== 'INCONCLUSIVE' &&
    requiresRationale(confianza) &&
    fundamento.trim().length === 0;
  const puedeEnviar = call !== null && !faltaFundamento && !enviando;

  const enviar = async () => {
    if (!call || !puedeEnviar) return;
    setEnviando(true);
    setError(null);
    try {
      const res = await submitVerdict(mission.mission_id.split('-R')[0], {
        call,
        confidence: call === 'INCONCLUSIVE' ? MIN_CONFIDENCE : confianza,
        rationale: fundamento.trim() || undefined,
      });
      onSubmitted(mission, res);
    } catch (err) {
      if (err instanceof UnauthorizedError) onSessionExpired();
      else if (err instanceof ApiRejection) setError(err.detail);
      else setError('No se pudo registrar el veredicto. Reintentá.');
    } finally {
      setEnviando(false);
    }
  };

  return (
    <div className="space-y-3 border border-neon-cyan/25 bg-void/60 p-3">
      <div className="flex items-center justify-between">
        <span className="text-2xs uppercase tracking-[0.18em] text-neon-cyan">
          ▸ tu veredicto
        </span>
        {mission.awaiting_corroboration ? (
          <span
            className="text-2xs uppercase tracking-[0.14em] text-neon-amber"
            title="La verdad se resuelve cuando las fuentes corroboran. Tu apuesta queda sellada hasta entonces."
          >
            ◷ a ciegas · se califica al corroborar
          </span>
        ) : (
          <span className="text-2xs uppercase tracking-[0.14em] text-phosphor-faint">
            se califica al instante
          </span>
        )}
      </div>

      {/* Llamada */}
      <div className="grid grid-cols-3 gap-1.5" role="radiogroup" aria-label="Llamada">
        {LLAMADAS.map((l) => (
          <button
            key={l.id}
            type="button"
            role="radio"
            aria-checked={call === l.id}
            onClick={() => setCall(l.id)}
            className={`btn-console ${l.cls} ${call === l.id ? l.activo : 'hover:bg-void-800'}`}
          >
            {l.label}
          </button>
        ))}
      </div>

      {/* Confianza */}
      {call && call !== 'INCONCLUSIVE' && (
        <div>
          <div className="mb-1 flex items-baseline justify-between text-2xs">
            <label htmlFor={`conf-${mission.mission_id}`} className="uppercase tracking-[0.14em] text-phosphor-faint">
              certeza en tu llamada
            </label>
            <span className="tabular-nums text-[15px] font-bold text-phosphor">{confianza}%</span>
          </div>
          <input
            id={`conf-${mission.mission_id}`}
            type="range"
            min={MIN_CONFIDENCE}
            max={MAX_CONFIDENCE}
            step={5}
            value={confianza}
            onChange={(e) => setConfianza(Number(e.target.value))}
            className="w-full accent-[#22d3ee]"
          />
          <div className="flex justify-between text-2xs text-phosphor-faint">
            <span>50 · moneda al aire</span>
            <span>100 · certeza total</span>
          </div>
        </div>
      )}

      {/* La regla del juego, en números */}
      {pago && call !== 'INCONCLUSIVE' && (
        <div
          className="grid grid-cols-2 gap-1.5 text-center"
          data-testid="vista-previa-pago"
        >
          <div className="border border-neon-green/30 bg-neon-green/5 py-1.5">
            <div className="text-2xs uppercase tracking-[0.12em] text-phosphor-faint">si acertás</div>
            <div className="tabular-nums text-lg font-bold text-neon-green">
              {pago.ifRight > 0 ? '+' : ''}
              {pago.ifRight}
            </div>
          </div>
          <div className="border border-severity-critical/30 bg-severity-critical/5 py-1.5">
            <div className="text-2xs uppercase tracking-[0.12em] text-phosphor-faint">si te equivocás</div>
            <div className="tabular-nums text-lg font-bold text-severity-critical">
              {pago.ifWrong > 0 ? '+' : ''}
              {pago.ifWrong}
            </div>
          </div>
          <p className="col-span-2 text-2xs leading-relaxed text-phosphor-faint">
            {pago.hedging
              ? '50% es una moneda al aire: no pagás ni cobrás. Cubrirse no es una estrategia.'
              : confianza >= 90
                ? 'Certeza alta: equivocarte cuesta el triple de lo que rinde acertar. Decí lo que realmente creés.'
                : 'La estrategia que más rinde a la larga es declarar exactamente lo que creés.'}
          </p>
        </div>
      )}

      {call === 'INCONCLUSIVE' && (
        <p className="text-2xs leading-relaxed text-phosphor-faint">
          No suma ni resta. Reconocer que la evidencia no alcanza es honesto, pero
          no es análisis entregado.
        </p>
      )}

      {/* Fundamento */}
      {call && call !== 'INCONCLUSIVE' && (
        <label className="block">
          <span className="mb-1 block text-2xs uppercase tracking-[0.14em] text-phosphor-faint">
            fundamento
            {requiresRationale(confianza) ? (
              <span className="text-neon-amber"> · obligatorio desde {RATIONALE_REQUIRED_AT}%</span>
            ) : (
              ' · opcional'
            )}
          </span>
          <textarea
            value={fundamento}
            onChange={(e) => setFundamento(e.target.value)}
            maxLength={2000}
            rows={2}
            placeholder="¿Qué evidencia te lleva a esta llamada?"
            className="w-full resize-y border border-void-600 bg-void/80 px-2 py-1.5 text-[13px] text-phosphor outline-none placeholder:text-phosphor-faint focus:border-neon-cyan/60"
          />
        </label>
      )}

      {error && (
        <p role="alert" className="border border-severity-critical/60 bg-severity-critical/10 px-2 py-1.5 text-[13px] text-severity-critical">
          {error}
        </p>
      )}

      <button
        type="button"
        onClick={enviar}
        disabled={!puedeEnviar}
        title={faltaFundamento ? 'Con esta certeza hace falta fundamento escrito' : undefined}
        className="btn-console w-full border-neon-cyan/50 py-2 text-neon-cyan hover:bg-neon-cyan/10 hover:shadow-glow-cyan"
      >
        {enviando ? '▚▚▚ sellando ▚▚▚' : '▸ sellar veredicto · no se puede cambiar'}
      </button>
    </div>
  );
}

function VeredictoEmitido({ veredicto, mission }: { veredicto: MyVerdict; mission: Mission }) {
  const nombre =
    veredicto.call === 'MALICIOUS' ? 'malicioso' : veredicto.call === 'BENIGN' ? 'benigno' : 'no concluyente';

  if (!veredicto.graded) {
    return (
      <div className="border border-neon-amber/40 bg-neon-amber/5 px-3 py-2 text-[13px]" data-testid="veredicto-sellado">
        <span className="text-neon-amber">◷ veredicto sellado:</span>{' '}
        <span className="text-phosphor">{nombre} al {veredicto.confidence}%</span>
        <p className="mt-1 text-2xs text-phosphor-faint">
          Se califica cuando las fuentes corroboren
          {mission.independent_sources > 0 && ` (hoy: ${mission.independent_sources} de 3 operadores)`}.
          El tiempo te va a dar o quitar la razón.
        </p>
      </div>
    );
  }

  const xp = veredicto.xp_awarded ?? 0;
  const acierto = veredicto.was_correct;
  return (
    <div
      className={`border px-3 py-2 text-[13px] ${
        acierto === null
          ? 'border-void-600 bg-void/60'
          : acierto
            ? 'border-neon-green/50 bg-neon-green/5'
            : 'border-severity-critical/50 bg-severity-critical/5'
      }`}
      data-testid="veredicto-calificado"
    >
      <div className="flex items-baseline justify-between gap-2">
        <span>
          <span className={acierto ? 'text-neon-green' : acierto === false ? 'text-severity-critical' : 'text-phosphor-dim'}>
            {acierto === null ? '◇' : acierto ? '✓' : '✗'}
          </span>{' '}
          <span className="text-phosphor">{nombre} al {veredicto.confidence}%</span>
        </span>
        <span className={`tabular-nums font-bold ${xp >= 0 ? 'text-neon-green' : 'text-severity-critical'}`}>
          {xp > 0 ? '+' : ''}
          {xp} XP
        </span>
      </div>
      {veredicto.brier_score !== null && (
        <p className="mt-1 text-2xs text-phosphor-faint">
          brier {veredicto.brier_score.toFixed(3)} ·{' '}
          {acierto && veredicto.brier_score <= 0.04
            ? 'lectura precisa y bien calibrada'
            : acierto
              ? 'acertaste, con menos certeza de la que ameritaba'
              : veredicto.brier_score >= 0.64
                ? 'te equivocaste CON certeza: el error más caro del oficio'
                : 'te equivocaste, pero la duda declarada te protegió'}
        </p>
      )}
    </div>
  );
}
