"""
ATALAYA // Calificación de veredictos.

Módulo **puro**: sin base de datos, sin red. Implementa la regla que separa
una academia de un clicker — ver `docs/VERIFICACION.md`.

Idea central: no premiamos acertar, premiamos **calibrar**. Un analista que
declara 80% y acierta el 80% de las veces vale más que uno que declara 100% y
acierta el 85%: el segundo es más preciso y más peligroso, porque cuando se
equivoca arrastra al SOC con su certeza.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Call(str, Enum):
    """El veredicto que emite el analista."""

    MALICIOUS = "MALICIOUS"
    BENIGN = "BENIGN"
    #: Salida honesta. No puntúa ni penaliza: reconocer que no alcanza la
    #: evidencia es una respuesta legítima, pero no es análisis entregado.
    INCONCLUSIVE = "INCONCLUSIVE"


class GroundTruth(str, Enum):
    """Lo que resultó ser, según la fuente de verdad."""

    MALICIOUS = "MALICIOUS"
    BENIGN = "BENIGN"
    #: Todavía no se resolvió, o nunca se va a resolver.
    UNKNOWN = "UNKNOWN"


class TruthSource(str, Enum):
    """Qué autoriza a decir que algo es verdad. Determina también el CUÁNDO."""

    KEV = "KEV"  # catálogo de CISA: explotación activa observada
    MULTI_SOURCE = "MULTI_SOURCE"  # N fuentes independientes coinciden
    CORROBORATION = "CORROBORATION"  # diferida: qué pasó en las próximas 72 h
    CURATED = "CURATED"  # respuesta escrita por un instructor
    PEER = "PEER"  # consenso entre pares, ponderado por rango


#: Confianza mínima admitida. Por debajo de 50 el veredicto se contradice a sí
#: mismo: "MALICIOSO con 30% de confianza" es, en realidad, "BENIGNO con 70%".
#: Restringir el rango a [50, 100] mantiene el modelo coherente y obliga al
#: analista a elegir un lado antes de medir cuánta certeza tiene.
MIN_CONFIDENCE = 50
MAX_CONFIDENCE = 100

#: A partir de acá se exige fundamento escrito. Una certeza alta sin argumento
#: no es análisis: es una corazonada con buena presentación.
RATIONALE_REQUIRED_AT = 80

#: Operadores independientes necesarios para dar por corroborado un indicador.
#:
#: Era 3. Se bajó a 2 con datos reales en la mano (septiembre 2026):
#:
#:   · IPs de ThreatFox que también reporta Emerging Threats ......   2
#:   · IPs de ThreatFox dentro de rangos Spamhaus DROP ............ 287
#:   · IPs presentes en las TRES fuentes ..........................   2
#:
#: Con fuentes gratuitas, tres operadores coincidiendo es prácticamente
#: inalcanzable: con umbral 3 casi ninguna misión se resolvía nunca, y el
#: analista apostaba sin recibir respuesta jamás.
#:
#: El argumento original para 3 era "dos feeds que se copian entre sí no son
#: dos fuentes". Ese riesgo ya lo neutraliza el conteo por FAMILIA de operador
#: (ver ingestion/base.py): ThreatFox y URLhaus son abuse.ch y cuentan como uno.
#: Dos familias distintas son dos organizaciones que no se copian.
CORROBORATION_THRESHOLD = 2

#: Ventana de corroboración. 24 h deja afuera campañas que tardan en
#: propagarse entre feeds; 72 h es el punto donde la señal ya se estabilizó.
CORROBORATION_WINDOW_HOURS = 72


@dataclass(frozen=True)
class GradeResult:
    """Resultado de calificar un veredicto."""

    graded: bool
    brier: float | None
    xp: int
    was_correct: bool | None
    explanation: str


def probability_malicious(call: Call, confidence: int) -> float:
    """Traduce (veredicto, confianza) a una probabilidad de "es malicioso".

    Es el paso que permite calificar ambos lados con la misma regla: decir
    "BENIGNO con 90%" equivale a asignar 10% de probabilidad a malicioso.
    """
    p = max(MIN_CONFIDENCE, min(MAX_CONFIDENCE, confidence)) / 100
    return p if call is Call.MALICIOUS else 1 - p


def brier_score(call: Call, confidence: int, truth: GroundTruth) -> float:
    """Error cuadrático entre lo declarado y lo que pasó. Menos es mejor.

    Brier es una **regla de puntuación propia**: la estrategia que maximiza el
    puntaje esperado es declarar la creencia real. Exagerar o moderar la
    confianza da menos puntos a largo plazo — matemáticamente, no por política
    del producto. Eso es lo que hace que el sistema no se pueda jugar.
    """
    if truth is GroundTruth.UNKNOWN:
        raise ValueError("No se puede calificar contra una verdad desconocida.")
    outcome = 1.0 if truth is GroundTruth.MALICIOUS else 0.0
    return round((probability_malicious(call, confidence) - outcome) ** 2, 6)


#: Pendiente de la conversión Brier -> XP.
#:
#: El valor 4 NO es arbitrario: es el único que hace que declarar 50% pague
#: exactamente 0. Un veredicto de moneda al aire tiene brier 0.25, y
#: `1 - 4·0.25 = 0`. Con cualquier pendiente menor, cubrirse pagaría XP gratis
#: — que es justo el farmeo que este diseño viene a impedir.
#:
#: La transformación es AFÍN a propósito. Brier es una regla de puntuación
#: propia, y esa propiedad —que la estrategia óptima sea declarar tu creencia
#: real— sólo sobrevive a transformaciones afines. Una función por tramos que
#: "suavizara" el castigo rompería la matemática que hace que el sistema no se
#: pueda jugar.
BRIER_SLOPE = 4


def xp_from_brier(brier: float, base_xp: int) -> int:
    """Convierte el Brier en XP, con signo.

        brier 0.00  ->  +base       (certeza justificada)
        brier 0.04  ->  +0.84·base  (80% y acertó)
        brier 0.25  ->        0     (declaró 50%: cubrirse no paga)
        brier 0.64  ->  -1.56·base  (80% y erró)
        brier 1.00  ->    -3·base   (certeza infundada)

    La asimetría es deliberada y es la tesis del sistema: equivocarse con
    certeza cuesta el triple de lo que rinde acertar con certeza. En un SOC
    real esa es la proporción correcta — un falso negativo declarado con
    seguridad no cuesta lo mismo que un acierto, cuesta muchísimo más.
    El piso en cero de la XP total impide que esto expulse a nadie.
    """
    # El redondeo a XP entera desvía el óptimo uno o dos puntos de confianza
    # respecto del ideal continuo. Está medido: la ventaja de mentir nunca
    # supera 1 XP (ver tests/test_verificacion.py). Es ruido, no estrategia.
    return round(base_xp * (1 - BRIER_SLOPE * brier))


def grade_verdict(
    call: Call, confidence: int, truth: GroundTruth, base_xp: int
) -> GradeResult:
    """Califica un veredicto contra la verdad de referencia."""
    if truth is GroundTruth.UNKNOWN:
        return GradeResult(
            graded=False,
            brier=None,
            xp=0,
            was_correct=None,
            explanation="La verdad de referencia todavía no se resolvió.",
        )

    if call is Call.INCONCLUSIVE:
        return GradeResult(
            graded=True,
            brier=None,
            xp=0,
            was_correct=None,
            explanation=(
                ">> VEREDICTO NO CONCLUYENTE :: sin puntaje :: reconocer que la "
                "evidencia no alcanza es honesto, pero no es análisis entregado"
            ),
        )

    brier = brier_score(call, confidence, truth)
    xp = xp_from_brier(brier, base_xp)
    correct = (call is Call.MALICIOUS) == (truth is GroundTruth.MALICIOUS)

    if correct and brier <= 0.04:
        detalle = "lectura precisa y bien calibrada"
    elif correct and xp > 0:
        detalle = "acertaste, pero con menos confianza de la que ameritaba"
    elif correct:
        detalle = "acertaste por poco margen: una moneda al aire no puntúa"
    elif brier >= 0.64:
        detalle = "te equivocaste CON CERTEZA — el error más caro del oficio"
    else:
        detalle = "te equivocaste, aunque la duda que declaraste te protegió"

    signo = "+" if xp >= 0 else ""
    return GradeResult(
        graded=True,
        brier=brier,
        xp=xp,
        was_correct=correct,
        explanation=(
            f">> VEREDICTO CALIFICADO :: realidad {truth.value} :: "
            f"brier {brier:.3f} :: {signo}{xp} XP :: {detalle}"
        ),
    )


def requires_rationale(confidence: int) -> bool:
    """¿Este nivel de confianza exige fundamento escrito?"""
    return confidence >= RATIONALE_REQUIRED_AT


def calibration_score(briers: list[float]) -> float | None:
    """Calidad de la calibración en [0, 1]. Arriba de 0.75 es bueno.

    Es lo que dice cuánto vale la palabra del analista, a diferencia de la XP,
    que sólo dice cuánto trabajó.
    """
    if not briers:
        return None
    return round(1 - sum(briers) / len(briers), 4)


def overconfidence(confidences: list[int], correct: list[bool]) -> float | None:
    """Confianza media menos tasa de acierto.

    Positivo = el analista cree saber más de lo que sabe. Es el número que un
    jefe de SOC realmente quiere ver, y que ningún producto del rubro muestra.
    """
    if not confidences or len(confidences) != len(correct):
        return None
    conf_media = sum(confidences) / len(confidences) / 100
    acierto = sum(1 for c in correct if c) / len(correct)
    return round(conf_media - acierto, 4)


def corroboration_verdict(
    independent_sources: int, kev_listed: bool
) -> tuple[GroundTruth, TruthSource | None]:
    """Deduce la verdad de referencia a partir de las señales de la ingesta.

    Es el contrato que todo conector tiene que poder alimentar: sin número de
    fuentes independientes ni pertenencia a KEV, no hay nada que calificar.
    """
    if kev_listed:
        return GroundTruth.MALICIOUS, TruthSource.KEV
    if independent_sources >= CORROBORATION_THRESHOLD:
        return GroundTruth.MALICIOUS, TruthSource.MULTI_SOURCE
    return GroundTruth.UNKNOWN, None
