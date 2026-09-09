# 🎯 ATALAYA · El bucle de verificación

> El documento más importante del proyecto. Todo lo demás es infraestructura
> para que esto funcione.

---

## 1. El problema

Hoy el analista aprieta **"Verificar"** y cobra 60 XP. No hay verdad de
referencia. No hay forma de estar equivocado. Con autenticación, conectores
reales y PostgreSQL, seguiría siendo **un clicker con estética de SOC**.

Una academia necesita responder una pregunta que hoy no podemos responder:

> **¿El analista acertó?**

---

## 2. La idea central: no premiamos acertar, premiamos calibrar

Un buen analista de inteligencia **no es el que siempre acierta**. Es el que
sabe cuánto sabe.

Alguien que dice *"80% de confianza"* y acierta el 80% de las veces es mejor
analista que alguien que dice *"100% seguro"* y acierta el 85%. El segundo es
más preciso y **más peligroso**: cuando se equivoca, arrastra a todo el SOC
con su certeza.

Por eso el veredicto no es un botón. Es una apuesta declarada:

```json
{
  "call": "MALICIOUS",
  "confidence": 75,
  "rationale": "Registrado hace 6 días, certificado TLS compartido con
                dos dominios ya marcados, sin tráfico legítimo previo.",
  "evidence": ["indicator--...", "https://threatfox.abuse.ch/ioc/..."]
}
```

Y se califica con una **regla de puntuación propia** (Brier), que es la
herramienta estándar en torneos de pronóstico y en evaluación de analistas
de inteligencia:

```
brier = (confianza/100 − resultado)²          resultado ∈ {0, 1}
xp    = base × (1 − 4·brier)
```

| Declaró | Realidad | Brier | XP (base 100) | Lectura |
|---|---|---:|---:|---|
| 100% malicioso | malicioso | 0.00 | **+100** | Certeza justificada |
| 80% malicioso | malicioso | 0.04 | **+84** | Buena lectura |
| 50% cualquiera | cualquiera | 0.25 | **0** | Cubrirse no paga |
| 80% malicioso | benigno | 0.64 | **−156** | Se equivocó con confianza |
| 100% malicioso | benigno | 1.00 | **−300** | Certeza infundada: el peor error |

**La pendiente 4 no es arbitraria.** Es el único valor que hace que declarar
50% pague exactamente 0: un veredicto de moneda al aire tiene brier 0.25, y
`1 − 4·0.25 = 0`. Con cualquier pendiente menor, cubrirse pagaría XP gratis.

**La asimetría tampoco.** Equivocarse con certeza cuesta el triple de lo que
rinde acertar con certeza, y esa es la tesis entera: en un SOC, un falso
negativo declarado con seguridad no cuesta lo mismo que un acierto — cuesta
muchísimo más. El piso en cero de la XP total impide que esto expulse a nadie.

Las tres propiedades que importan:

1. **Cubrirse no paga.** Declarar 50% siempre da exactamente 0 XP. No se puede
   farmear hedgeando.
2. **La certeza infundada es el peor error posible.** Peor que equivocarse
   dudando. Es exactamente el incentivo que querés en un SOC.
3. **No se puede jugar con el sistema.** Brier es una *regla propia*: la
   estrategia que maximiza la XP esperada es **decir tu creencia real**.
   Cualquier otra cosa te da menos puntos a largo plazo. Matemáticamente,
   no por política.

---

## 3. De dónde sale la verdad de referencia

Cinco fuentes, ordenadas de más dura a más blanda. Cada misión declara **cuál**
la califica; eso determina también **cuándo**.

| Origen | Qué la hace verdad | Calificación |
|---|---|---|
| `KEV` | Estar en el catálogo de CISA es, por definición, explotación activa observada. No es opinión | Inmediata |
| `MULTI_SOURCE` | N fuentes independientes coinciden (ThreatFox + URLhaus + MalwareBazaar) | Inmediata |
| `CORROBORATION` | **Diferida**: se toma el IoC cuando todavía es ambiguo y se ve qué pasa en las próximas 72 h | A las 72 h |
| `CURATED` | Un instructor escribió la respuesta | Inmediata |
| `PEER` | Consenso ponderado por rango, sólo para lo genuinamente ambiguo | Al haber quórum |

### La corroboración diferida es el corazón pedagógico

Es la única que entrena lo que realmente pasa en un SOC: **decidir con
información incompleta y que el tiempo te dé o te quite la razón.**

```
T+0h    ThreatFox reporta 198.51.100.42 · confidence 50 · una sola fuente
        → entra al feed como misión AMBIGUA
        → el analista apuesta: "70% malicioso, el ASN es sospechoso"

T+72h   URLhaus y MalwareBazaar corroboran · 3 fuentes independientes
        → verdad de referencia: MALICIOUS
        → se califica el veredicto emitido a T+0, con lo que se sabía a T+0
```

El analista **no puede** hacer trampa esperando: el veredicto se sella con
marca de tiempo y sólo se califica lo que se emitió **antes** de que la verdad
se resolviera. Un veredicto tardío no puntúa.

---

## 4. Reglas anti-abuso

| Regla | Por qué |
|---|---|
| Un veredicto por analista y por misión. **Sin edición** | Sin esto se cambia la respuesta al ver el resultado |
| Sólo puntúa lo emitido antes de `resolved_at` | Impide esperar a que la verdad sea pública |
| Fundamento obligatorio si `confidence ≥ 80` | Una certeza alta sin argumento no es análisis |
| `INCONCLUSIVE` no puntúa ni penaliza | Salida honesta legítima. No se premia, no se castiga |
| El veredicto es append-only, igual que `xp_events` | Auditoría completa de cada llamada |

---

## 5. Métrica del analista: calibración, no puntaje

El puntaje dice cuánto trabajó. **La calibración dice cuánto vale su palabra.**

```
brier_medio     = promedio de todos sus veredictos calificados
calibracion     = 1 − brier_medio        (0 a 1; arriba de 0.75 es bueno)
sobreconfianza  = confianza_media − tasa_de_acierto
```

`sobreconfianza > 0` significa que el analista cree saber más de lo que sabe.
Es el número que un jefe de SOC realmente quiere ver, y ningún producto del
rubro lo muestra.

**Propuesta:** la calibración es un requisito de rango, no sólo la XP.
No alcanza con trabajar mucho para llegar a Cazador de Amenazas; hay que
tener razón cuando decís que la tenés.

| Rango | XP | Calibración mínima | Veredictos mínimos |
|---|---:|---:|---:|
| Novato | 0 | — | — |
| Analista Junior | 250 | — | 5 |
| Analista Senior | 1.200 | 0.65 | 25 |
| Cazador de Amenazas | 4.000 | 0.78 | 100 |

---

## 6. Qué le exige esto a la ingesta

Esta es la razón de diseñar antes de escribir los conectores. Cada conector
tiene que traer, además del IoC:

| Campo | Para qué |
|---|---|
| `source_confidence` | Distinguir ambiguo de conocido |
| `source_name` + `source_reference` | Contar fuentes **independientes** |
| `first_reported_at` | Sostener la ventana de corroboración |
| `kev_listed` | Verdad inmediata y dura |
| `sample_available` | Corroboración fuerte (hay muestra real) |

Un conector que sólo devuelva "IP maliciosa" **no sirve para calificar nada**.
Por eso este documento va antes que la Etapa 4.

---

## 7. Decisiones tomadas y sus alternativas

| Decisión | Alternativa descartada | Motivo |
|---|---|---|
| Brier sobre confianza declarada | Acierto/error binario | El binario premia adivinar y no distingue al calibrado del afortunado |
| `xp = base × (1 − 2·brier)` | Sólo XP positiva | Sin costo por equivocarse con certeza, la certeza es gratis |
| Corroboración a 72 h | 24 h | 24 h deja fuera campañas que tardan en propagarse entre feeds |
| 3 fuentes independientes | 2 | Dos feeds que se copian entre sí no son dos fuentes |
| Calibración como requisito de rango | Sólo XP | Sin esto, la constancia sola llega a Cazador |
| Un veredicto, sin edición | Permitir corregir | Corregir después de saber el resultado no es análisis |

---

## 8. Lo que este diseño **no** resuelve

Honestidad sobre los límites:

- **El arranque en frío.** Sin analistas no hay consenso entre pares, y sin
  historial no hay calibración. Los primeros 100 usuarios necesitan misiones
  curadas.
- **Sesgo de las fuentes.** *Parcialmente resuelto*: la independencia se cuenta
  por **operador** (`SourceFamily`), no por API, así que las tres puertas de
  abuse.ch cuentan como una. Lo que sigue faltando es el caso más sutil: dos
  operadores realmente distintos que copian del mismo origen upstream. Eso
  necesita un grafo de procedencia y todavía no existe.
- **La verdad no siempre llega.** Muchos IoCs nunca se corroboran ni se
  refutan. Esas misiones expiran sin calificar, y hay que decírselo al
  analista en vez de dejarlas colgadas.
- **Brier asume un resultado binario.** "Malicioso" no siempre es sí o no:
  un dominio comprometido y después limpiado fue ambas cosas.
