import type { Config } from 'tailwindcss';

/**
 * ATALAYA // Sistema de diseño
 * ═══════════════════════════════════════════════════════════════════
 * Estética: consola de un SOC del futuro. Fósforo sobre vidrio negro.
 *
 * Reglas de la paleta:
 *   · El fondo NUNCA es negro puro (#000): un negro azulado profundo deja
 *     respirar al neón y evita el "agujero" que produce el OLED.
 *   · Un solo acento por estado. Si todo brilla, nada resalta.
 *   · La severidad manda sobre la marca: si una misión es crítica, el rojo
 *     gana aunque rompa la armonía. Es un panel operativo, no un póster.
 */
const config: Config = {
  content: [
    './app/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './lib/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        // ── Sustrato ──────────────────────────────────────────────
        void: {
          DEFAULT: '#05070a', // fondo de la app
          900: '#080b11',     // paneles
          800: '#0d121a',     // tarjetas
          700: '#131a25',     // superficies elevadas
          600: '#1b2534',     // bordes suaves
        },
        // ── Neón ──────────────────────────────────────────────────
        neon: {
          green: '#39ff88',   // marca / terminal / rango 1
          cyan: '#22d3ee',    // datos / enlaces / rango 2
          magenta: '#ff2fb9', // alerta / rango 3
          amber: '#ffb020',   // cazador / rango 4
          violet: '#a855f7',  // secundario
        },
        // ── Semántica de severidad ────────────────────────────────
        severity: {
          low: '#38bdf8',
          medium: '#facc15',
          high: '#fb923c',
          critical: '#ff2d55',
        },
        // ── Texto ─────────────────────────────────────────────────
        phosphor: {
          DEFAULT: '#c8f5dd', // texto principal, verdoso apagado
          dim: '#7d9b8d',     // secundario
          faint: '#48605a',   // terciario / metadatos
        },
      },

      fontFamily: {
        // Stack monoespaciado con degradación limpia si no hay red para
        // bajar la webfont: la consola tiene que verse bien igual.
        mono: [
          'JetBrains Mono',
          'IBM Plex Mono',
          'ui-monospace',
          'SFMono-Regular',
          'Menlo',
          'Consolas',
          'monospace',
        ],
        display: ['Orbitron', 'JetBrains Mono', 'ui-monospace', 'monospace'],
      },

      fontSize: {
        '2xs': ['0.6875rem', { lineHeight: '1rem', letterSpacing: '0.06em' }],
      },

      boxShadow: {
        // Glow en dos capas: halo cercano + difusión lejana. Una sola capa
        // se ve a lámpara barata.
        'glow-green': '0 0 8px rgba(57,255,136,0.45), 0 0 28px rgba(57,255,136,0.14)',
        'glow-cyan': '0 0 8px rgba(34,211,238,0.45), 0 0 28px rgba(34,211,238,0.14)',
        'glow-magenta': '0 0 8px rgba(255,47,185,0.45), 0 0 28px rgba(255,47,185,0.14)',
        'glow-amber': '0 0 8px rgba(255,176,32,0.45), 0 0 28px rgba(255,176,32,0.14)',
        'glow-critical': '0 0 10px rgba(255,45,85,0.55), 0 0 34px rgba(255,45,85,0.2)',
        panel: 'inset 0 1px 0 rgba(255,255,255,0.04), 0 18px 40px -24px rgba(0,0,0,0.9)',
      },

      backgroundImage: {
        // Rejilla del holograma.
        grid: `linear-gradient(rgba(57,255,136,0.045) 1px, transparent 1px),
               linear-gradient(90deg, rgba(57,255,136,0.045) 1px, transparent 1px)`,
        // Líneas de barrido del CRT.
        scanlines: `repeating-linear-gradient(
          180deg,
          rgba(0,0,0,0) 0px,
          rgba(0,0,0,0) 2px,
          rgba(0,0,0,0.28) 3px,
          rgba(0,0,0,0) 4px
        )`,
        'radial-fade':
          'radial-gradient(120% 90% at 50% 0%, rgba(57,255,136,0.10), transparent 62%)',
      },
      backgroundSize: {
        grid: '38px 38px',
      },

      keyframes: {
        flicker: {
          '0%, 19%, 21%, 23%, 25%, 54%, 56%, 100%': { opacity: '1' },
          '20%, 22%, 24%, 55%': { opacity: '0.55' },
        },
        scanline: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
        'pulse-ring': {
          '0%': { boxShadow: '0 0 0 0 rgba(255,45,85,0.5)' },
          '70%': { boxShadow: '0 0 0 12px rgba(255,45,85,0)' },
          '100%': { boxShadow: '0 0 0 0 rgba(255,45,85,0)' },
        },
        'glitch-x': {
          '0%, 100%': { transform: 'translateX(0)' },
          '20%': { transform: 'translateX(-2px)' },
          '40%': { transform: 'translateX(2px)' },
          '60%': { transform: 'translateX(-1px)' },
          '80%': { transform: 'translateX(1px)' },
        },
        'boot-in': {
          '0%': { opacity: '0', transform: 'translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        'type-caret': {
          '0%, 49%': { opacity: '1' },
          '50%, 100%': { opacity: '0' },
        },
        'xp-fill': {
          from: { width: '0%' },
        },
        'ticker': {
          from: { transform: 'translateX(0)' },
          to: { transform: 'translateX(-50%)' },
        },
      },
      animation: {
        flicker: 'flicker 4.5s infinite steps(1)',
        scanline: 'scanline 7s linear infinite',
        'pulse-ring': 'pulse-ring 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glitch-x': 'glitch-x 220ms ease-in-out',
        'boot-in': 'boot-in 420ms cubic-bezier(0.16, 1, 0.3, 1) both',
        caret: 'type-caret 1.05s steps(1) infinite',
        'xp-fill': 'xp-fill 900ms cubic-bezier(0.16, 1, 0.3, 1)',
        ticker: 'ticker 38s linear infinite',
      },

      transitionTimingFunction: {
        snap: 'cubic-bezier(0.16, 1, 0.3, 1)',
      },
    },
  },
  plugins: [],
};

export default config;
