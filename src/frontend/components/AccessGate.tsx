'use client';

/**
 * ATALAYA // Puerta de acceso.
 *
 * Terminal de autenticación, no un formulario de SaaS. La sesión viaja en
 * cookies httpOnly que este componente nunca ve — por diseño: un token que
 * JavaScript puede leer es un token que un XSS se lleva.
 */

import { useState } from 'react';
import { login, register, UnauthorizedError } from '@/lib/api';

interface Props {
  onAuthenticated: () => void;
  onOffline: () => void;
}

const MIN_PASSWORD = 12;

export default function AccessGate({ onAuthenticated, onOffline }: Props) {
  const [modo, setModo] = useState<'login' | 'alta'>('login');
  const [callsign, setCallsign] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [ocupado, setOcupado] = useState(false);

  const corta = modo === 'alta' && password.length > 0 && password.length < MIN_PASSWORD;
  const puedeEnviar = callsign.trim().length >= 2 && password.length > 0 && !corta;

  const enviar = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!puedeEnviar || ocupado) return;
    setOcupado(true);
    setError(null);
    try {
      if (modo === 'alta') await register(callsign.trim(), password);
      else await login(callsign.trim(), password);
      setPassword('');
      onAuthenticated();
    } catch (err) {
      if (err instanceof UnauthorizedError) setError(err.detail);
      else if (err instanceof Error && err.name === 'ApiUnavailableError')
        setError('La torre no responde. Podés entrar en modo autónomo.');
      else if (err instanceof Error) {
        const m = /::\s*(.+)$/.exec(err.message);
        let detalle = m?.[1] ?? err.message;
        try {
          detalle = JSON.parse(detalle).detail ?? detalle;
        } catch {
          /* el cuerpo no era JSON; se muestra tal cual */
        }
        setError(String(detalle).slice(0, 220));
      }
    } finally {
      setOcupado(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-md">
        {/* Marca */}
        <div className="mb-6 text-center">
          <h1 className="font-display text-3xl font-black tracking-[0.28em] text-neon-green glow-text animate-flicker">
            ATALAYA
          </h1>
          <p className="mt-2 text-2xs uppercase tracking-[0.24em] text-phosphor-faint">
            el que vigila desde arriba ve venir la amenaza primero
          </p>
        </div>

        <form onSubmit={enviar} className="panel clip-corner">
          <div className="panel-header justify-between">
            <span>
              <span className="text-neon-green">▸</span>{' '}
              {modo === 'login' ? 'identificación' : 'alta de analista'}
            </span>
            <span className="text-phosphor-faint">cifrado extremo a extremo</span>
          </div>

          <div className="space-y-4 p-5">
            <label className="block">
              <span className="mb-1.5 block text-2xs uppercase tracking-[0.18em] text-phosphor-faint">
                Indicativo
              </span>
              <div className="flex items-center border border-void-600 bg-void/80 px-3 focus-within:border-neon-green/60 focus-within:shadow-glow-green">
                <span className="text-neon-green">$</span>
                <input
                  autoFocus
                  value={callsign}
                  onChange={(e) => setCallsign(e.target.value)}
                  autoComplete="username"
                  maxLength={32}
                  className="w-full bg-transparent px-2 py-2.5 text-[15px] text-phosphor outline-none placeholder:text-phosphor-faint"
                  placeholder="tu-callsign"
                />
              </div>
            </label>

            <label className="block">
              <span className="mb-1.5 block text-2xs uppercase tracking-[0.18em] text-phosphor-faint">
                Clave de acceso
              </span>
              <div className="flex items-center border border-void-600 bg-void/80 px-3 focus-within:border-neon-green/60 focus-within:shadow-glow-green">
                <span className="text-neon-green">#</span>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete={modo === 'alta' ? 'new-password' : 'current-password'}
                  maxLength={256}
                  className="w-full bg-transparent px-2 py-2.5 text-[15px] text-phosphor outline-none placeholder:text-phosphor-faint"
                  placeholder="••••••••••••"
                />
              </div>
              {modo === 'alta' && (
                <p
                  className={`mt-1.5 text-2xs ${
                    corta ? 'text-severity-critical' : 'text-phosphor-faint'
                  }`}
                >
                  Mínimo {MIN_PASSWORD} caracteres. Una frase larga rinde más que un
                  revoltijo corto, y se recuerda sin anotarla.
                  {corta && ` Faltan ${MIN_PASSWORD - password.length}.`}
                </p>
              )}
            </label>

            {error && (
              <p
                role="alert"
                className="border border-severity-critical/60 bg-severity-critical/10 px-3 py-2 text-[13px] text-severity-critical"
              >
                {error}
              </p>
            )}

            <button
              type="submit"
              disabled={!puedeEnviar || ocupado}
              className="btn-console w-full border-neon-green/50 py-2.5 text-neon-green hover:bg-neon-green/10 hover:shadow-glow-green"
            >
              {ocupado
                ? '▚▚▚ verificando ▚▚▚'
                : modo === 'login'
                  ? '▸ establecer enlace'
                  : '▸ solicitar alta'}
            </button>

            <div className="flex items-center justify-between border-t border-void-600/60 pt-3 text-2xs">
              <button
                type="button"
                onClick={() => {
                  setModo(modo === 'login' ? 'alta' : 'login');
                  setError(null);
                }}
                className="uppercase tracking-[0.14em] text-neon-cyan hover:text-neon-green"
              >
                {modo === 'login' ? '¿sin credenciales? dar de alta' : '¿ya tenés cuenta? entrar'}
              </button>
              <button
                type="button"
                onClick={onOffline}
                className="uppercase tracking-[0.14em] text-phosphor-faint hover:text-phosphor-dim"
                title="Explorar el feed sin cuenta. No se registra progresión."
              >
                entrar sin cuenta
              </button>
            </div>
          </div>
        </form>

        <p className="mt-4 text-center text-2xs leading-relaxed text-phosphor-faint">
          Sin cuenta podés leer el feed, pero no operar: la progresión y la
          calibración necesitan saber quién sos.
        </p>
      </div>
    </div>
  );
}
