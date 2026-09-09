'use client';

/**
 * ATALAYA // Barra superior de estado.
 *
 * El reloj se monta recién en el cliente: renderizar la hora en el servidor
 * garantiza un desajuste de hidratación en React.
 */

import { useEffect, useState } from 'react';
import type { Session } from '@/lib/types';

interface Props {
  online: boolean;
  missionCount: number;
  criticalCount: number;
  sources: string[];
  session?: Session | null;
  onLogout?: () => void;
}

export default function StatusBar({
  online,
  missionCount,
  criticalCount,
  sources,
  session,
  onLogout,
}: Props) {
  const [clock, setClock] = useState<string | null>(null);

  useEffect(() => {
    const tick = () =>
      setClock(
        new Date().toISOString().slice(11, 19) + 'Z',
      );
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  return (
    <header className="sticky top-0 z-40 border-b border-void-600/80 bg-void/85 backdrop-blur-md">
      <div className="mx-auto flex max-w-[1600px] flex-wrap items-center gap-x-5 gap-y-2 px-4 py-2.5">
        {/* Marca */}
        <div className="flex items-baseline gap-2">
          <span className="font-display text-lg font-black tracking-[0.22em] text-neon-green glow-text animate-flicker">
            ATALAYA
          </span>
          <span className="hidden text-2xs uppercase tracking-[0.2em] text-phosphor-faint sm:inline">
            {'// cti ops'}
          </span>
        </div>

        <span className="hidden h-4 w-px bg-void-600 md:block" aria-hidden />

        {/* Estado del enlace */}
        <div className="flex items-center gap-1.5 text-2xs uppercase tracking-[0.14em]">
          <span
            className={`h-1.5 w-1.5 rounded-full ${
              online ? 'bg-neon-green shadow-glow-green' : 'bg-neon-amber shadow-glow-amber'
            }`}
            aria-hidden
          />
          <span className={online ? 'text-neon-green' : 'text-neon-amber'}>
            {online ? 'enlace activo' : 'modo autónomo'}
          </span>
        </div>

        {/* Telemetría */}
        <div className="flex items-center gap-4 text-2xs uppercase tracking-[0.14em] text-phosphor-faint">
          <span>
            misiones <span className="text-phosphor">{missionCount}</span>
          </span>
          <span>
            críticas{' '}
            <span className={criticalCount > 0 ? 'text-severity-critical' : 'text-phosphor'}>
              {criticalCount}
            </span>
          </span>
          <span className="hidden lg:inline">
            fuentes <span className="text-phosphor">{sources.length}</span>
          </span>
        </div>

        {/* Reloj y sesión */}
        <div className="ml-auto flex items-center gap-3 text-2xs tracking-[0.14em] text-phosphor-dim">
          <span className="hidden xl:inline text-phosphor-faint">STIX 2.1 · MITRE ATT&CK</span>
          <span className="tabular-nums text-neon-cyan">{clock ?? '--:--:--Z'}</span>
          {session && (
            <>
              <span className="hidden h-4 w-px bg-void-600 sm:block" aria-hidden />
              <span className="uppercase text-phosphor-dim">
                {session.callsign}
                {session.role !== 'ANALYST' && (
                  <span className="ml-1 text-neon-amber">· {session.role}</span>
                )}
              </span>
              <button
                onClick={onLogout}
                className="uppercase tracking-[0.14em] text-phosphor-faint hover:text-severity-critical"
                title="Cerrar sesión en este dispositivo"
              >
                salir
              </button>
            </>
          )}
        </div>
      </div>

      {/* Ticker de fuentes */}
      <div className="overflow-hidden border-t border-void-600/60 bg-void-900/60 py-1">
        <div className="flex w-max animate-ticker gap-8 whitespace-nowrap px-4 text-2xs uppercase tracking-[0.18em] text-phosphor-faint">
          {[0, 1].map((dup) => (
            <span key={dup} className="flex gap-8">
              {sources.map((s) => (
                <span key={`${dup}-${s}`}>
                  <span className="text-neon-green">▸</span> {s}
                </span>
              ))}
              <span>
                <span className="text-neon-magenta">▸</span> el que vigila desde arriba ve
                venir la amenaza primero
              </span>
            </span>
          ))}
        </div>
      </div>
    </header>
  );
}
