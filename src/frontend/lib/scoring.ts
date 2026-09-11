/**
 * ATALAYA // Vista previa de la calificación.
 *
 * Espejo EXACTO de `src/api/scoring.py`. Existe para una sola cosa: que el
 * analista vea, mientras mueve el deslizador, cuánto gana si acierta y cuánto
 * pierde si se equivoca. Esa vista previa ES la explicación de la regla — un
 * párrafo sobre "puntuación Brier" no lo lee nadie; ver "+0 / −0" al 50% se
 * entiende en un segundo.
 *
 * Si este archivo y el de Python discrepan, la vista previa miente y el
 * sistema pierde la confianza del analista. Hay un test que los compara
 * contra la misma tabla de valores.
 */

export type Call = 'MALICIOUS' | 'BENIGN' | 'INCONCLUSIVE';

export const MIN_CONFIDENCE = 50;
export const MAX_CONFIDENCE = 100;
export const RATIONALE_REQUIRED_AT = 80;

/**
 * Operadores independientes para dar un indicador por corroborado. Espejo de
 * `CORROBORATION_THRESHOLD` en scoring.py — era 3 y bajó a 2 con datos reales:
 * con fuentes gratuitas, tres operadores coincidiendo casi nunca ocurre. Antes
 * este número estaba escrito a mano en dos componentes; el test de paridad
 * atrapa si vuelven a divergir.
 */
export const CORROBORATION_THRESHOLD = 2;

/**
 * Pendiente de la conversión Brier → XP. El 4 es el único valor que hace que
 * declarar 50% pague exactamente 0: `1 − 4·0.25 = 0`. Ver scoring.py.
 */
export const BRIER_SLOPE = 4;

/** Probabilidad de "es malicioso" implícita en (veredicto, confianza). */
export function probabilityMalicious(call: Call, confidence: number): number {
  const c = Math.max(MIN_CONFIDENCE, Math.min(MAX_CONFIDENCE, confidence)) / 100;
  return call === 'MALICIOUS' ? c : 1 - c;
}

export function brierScore(call: Call, confidence: number, maliciousIsTrue: boolean): number {
  const outcome = maliciousIsTrue ? 1 : 0;
  // Mismo redondeo que Python (`round(x, 6)`), para no divergir en el borde.
  return Math.round((probabilityMalicious(call, confidence) - outcome) ** 2 * 1e6) / 1e6;
}

/**
 * Brier → XP con signo.
 *
 * Python usa `round()`, que redondea al PAR en los empates (banker's
 * rounding). `Math.round` de JavaScript redondea hacia +∞. En un .5 exacto
 * darían resultados distintos y la vista previa mostraría un número que el
 * servidor no otorga. Por eso se implementa el redondeo de Python a mano.
 */
export function xpFromBrier(brier: number, baseXp: number): number {
  return roundHalfEven(baseXp * (1 - BRIER_SLOPE * brier));
}

export function roundHalfEven(x: number): number {
  const piso = Math.floor(x);
  const resto = x - piso;
  const EPS = 1e-9;
  if (resto > 0.5 + EPS) return piso + 1;
  if (resto < 0.5 - EPS) return piso;
  return piso % 2 === 0 ? piso : piso + 1;
}

export interface Payoff {
  /** XP si la llamada resulta correcta. */
  ifRight: number;
  /** XP si la llamada resulta incorrecta (negativa). */
  ifWrong: number;
  /** True cuando declarar esta confianza no paga nada: se está cubriendo. */
  hedging: boolean;
}

/** Lo que el analista ve mientras decide. */
export function payoff(call: Call, confidence: number, baseXp: number): Payoff {
  if (call === 'INCONCLUSIVE') return { ifRight: 0, ifWrong: 0, hedging: true };
  const aciertaSiMalicioso = call === 'MALICIOUS';
  const ifRight = xpFromBrier(brierScore(call, confidence, aciertaSiMalicioso), baseXp);
  const ifWrong = xpFromBrier(brierScore(call, confidence, !aciertaSiMalicioso), baseXp);
  return { ifRight, ifWrong, hedging: ifRight === 0 && ifWrong === 0 };
}

export function requiresRationale(confidence: number): boolean {
  return confidence >= RATIONALE_REQUIRED_AT;
}

/** Lectura humana de la sobreconfianza. */
export function describeOverconfidence(oc: number | null): string {
  if (oc === null) return 'sin veredictos calificados todavía';
  if (oc > 0.15) return 'creés saber bastante más de lo que sabés';
  if (oc > 0.05) return 'algo sobreconfiado';
  if (oc < -0.15) return 'subestimás tu criterio: acertás más de lo que declarás';
  if (oc < -0.05) return 'algo prudente de más';
  return 'bien calibrado';
}
