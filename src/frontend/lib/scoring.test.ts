/**
 * La vista previa de pagos no puede mentir.
 *
 * La tabla viene de `src/api/scoring.py`: si alguien cambia la fórmula de un
 * lado y no del otro, este test lo atrapa antes de que el analista vea un
 * número que el servidor no le va a dar.
 */
import { describe, expect, it } from 'vitest';
import tabla from './__fixtures__/payoff_table.json';
import {
  brierScore,
  describeOverconfidence,
  payoff,
  requiresRationale,
  roundHalfEven,
  xpFromBrier,
  type Call,
} from './scoring';

describe('paridad con el motor de Python', () => {
  it.each(tabla.filas)(
    'base $base · $call al $confidence% · verdad $truth → $xp XP',
    ({ base, confidence, call, truth, xp }) => {
      const b = brierScore(call as Call, confidence, truth === 'MALICIOUS');
      expect(xpFromBrier(b, base)).toBe(xp);
    },
  );
});

describe('las propiedades que sostienen el juego', () => {
  it('cubrirse al 50% no paga en ninguna dirección', () => {
    for (const call of ['MALICIOUS', 'BENIGN'] as const) {
      const p = payoff(call, 50, 300);
      expect(p.ifRight).toBe(0);
      expect(p.ifWrong).toBe(0);
      expect(p.hedging).toBe(true);
    }
  });

  it('equivocarse con certeza cuesta el triple de lo que rinde acertar', () => {
    const p = payoff('MALICIOUS', 100, 100);
    expect(p.ifRight).toBe(100);
    expect(p.ifWrong).toBe(-300);
  });

  it('más certeza sube la apuesta en los dos sentidos', () => {
    const tibio = payoff('MALICIOUS', 60, 100);
    const seguro = payoff('MALICIOUS', 95, 100);
    expect(seguro.ifRight).toBeGreaterThan(tibio.ifRight);
    expect(seguro.ifWrong).toBeLessThan(tibio.ifWrong);
  });

  it('no concluyente no suma ni resta', () => {
    expect(payoff('INCONCLUSIVE', 90, 300)).toEqual({ ifRight: 0, ifWrong: 0, hedging: true });
  });
});

describe('redondeo', () => {
  // Python redondea al par en los empates; JavaScript, hacia arriba. Sin esto
  // la vista previa y el servidor divergirían en los .5 exactos.
  it.each([
    [0.5, 0],
    [1.5, 2],
    [2.5, 2],
    // Python devuelve el entero 0, sin signo. Un -0 se vería como "−0 XP".
    [-0.5, 0],
    [-1.5, -2],
    [2.4, 2],
    [2.6, 3],
  ])('roundHalfEven(%f) = %f', (x, esperado) => {
    expect(roundHalfEven(x)).toBe(esperado);
  });
});

describe('reglas de fundamento', () => {
  it('exige fundamento desde el 80%', () => {
    expect(requiresRationale(75)).toBe(false);
    expect(requiresRationale(80)).toBe(true);
    expect(requiresRationale(100)).toBe(true);
  });
});

describe('lectura de la sobreconfianza', () => {
  it.each([
    [null, 'sin veredictos'],
    [0.3, 'creés saber bastante más'],
    [0.0, 'bien calibrado'],
    [-0.3, 'subestimás tu criterio'],
  ])('%s → "%s…"', (oc, fragmento) => {
    expect(describeOverconfidence(oc)).toContain(fragmento);
  });
});
