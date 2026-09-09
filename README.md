<div align="center">

```
   █████╗ ████████╗ █████╗ ██╗      █████╗ ██╗   ██╗ █████╗
  ██╔══██╗╚══██╔══╝██╔══██╗██║     ██╔══██╗╚██╗ ██╔╝██╔══██╗
  ███████║   ██║   ███████║██║     ███████║ ╚████╔╝ ███████║
  ██╔══██║   ██║   ██╔══██║██║     ██╔══██║  ╚██╔╝  ██╔══██║
  ██║  ██║   ██║   ██║  ██║███████╗██║  ██║   ██║   ██║  ██║
  ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝
              // C T I   O P S   A C A D E M Y //
```

**El que vigila desde arriba ve venir la amenaza primero.**

*Academia táctica de ciberseguridad sobre inteligencia de amenazas real.*

![STIX](https://img.shields.io/badge/STIX-2.1-39ff88?style=flat-square)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-22d3ee?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.12-ffb020?style=flat-square)
![Next.js](https://img.shields.io/badge/Next.js-15-ff2fb9?style=flat-square)
![Terraform](https://img.shields.io/badge/Terraform-1.10-a855f7?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square)

</div>

---

## 🎯 Qué es esto

**ATALAYA** es una plataforma de entrenamiento para analistas de ciberseguridad
que **no usa simulaciones**. Los ejercicios se construyen a partir de
indicadores de compromiso reales, ingeridos de fuentes OSINT vivas, modelados
en STIX 2.1 y correlacionados en OpenCTI y MISP.

Una *atalaya* es la torre de vigilancia y, a la vez, el centinela que la ocupa.
Eso es exactamente el rol que se entrena acá: ver venir la amenaza antes de que
llegue, y saber qué hacer cuando llega.

### 🪖 Doctrina

> *"Entrenar a la gente para ir a recuperar las Malvinas."*

Es la mentalidad interna del proyecto y hay que leerla como lo que es: **el
entrenamiento se toma en serio o no sirve**. Capacitación táctica, exigente y
aplicable el lunes a la mañana en un SOC de verdad — envuelta en un entorno
inmersivo que da ganas de volver.

Traducido a decisiones concretas de producto:

- 🔴 Los falsos positivos **restan** XP. En un SOC real, gritar "lobo" cuesta.
- 🔒 La XP se calcula **en el servidor**. El cliente no se regala rangos.
- 🎯 Las misiones bloqueadas **se ven igual**. Saber lo que todavía no podés
  tocar es la mitad del incentivo.
- 🧊 Los observables se muestran **siempre neutralizados** (`198[.]51[.]100[.]42`).
  Nunca clickeables.

### 🎨 Estética

Consola de un SOC del futuro: fósforo sobre vidrio negro. Rejilla holográfica,
líneas de barrido CRT, neón verde/cian/magenta/ámbar, tipografía monoespaciada
y paneles con esquina biselada. Sin humo: la severidad de la misión **manda**
sobre la armonía visual.

---

## 🏛️ Arquitectura

```mermaid
flowchart LR
    subgraph OSINT["🌐 Fuentes"]
        A1["AlienVault OTX"]
        A2["abuse.ch"]
        A3["CISA KEV"]
        A4["SpiderFoot"]
    end
    subgraph ING["⚙️ Ingesta"]
        B1["Conectores Python<br/>→ STIX 2.1"]
    end
    subgraph CTI["🧠 Correlación"]
        C1["OpenCTI"]
        C2["MISP"]
    end
    subgraph APP["🎮 Plataforma"]
        D1["FastAPI"]
        D2[("PostgreSQL")]
        D3["Next.js"]
    end

    A1 & A2 & A3 & A4 --> B1
    B1 --> C1 & C2
    C1 <--> C2
    C1 --> D1
    D1 <--> D2
    D1 --> D3
```

Detalle completo, decisiones de diseño y deuda técnica consciente:
📄 **[docs/ARQUITECTURA.md](docs/ARQUITECTURA.md)**

### 🧰 Stack

| Capa | Tecnología | Rol |
|---|---|---|
| 🌐 **Ingesta** | Python 3.12 · `httpx` · `tenacity` | CISA KEV, ThreatFox y OTX → STIX 2.1, con corroboración entre operadores |
| 🧠 **Correlación** | OpenCTI 6.4 · MISP | Grafo de conocimiento y compartición de IoCs |
| 📐 **Modelo de datos** | STIX 2.1 · MITRE ATT&CK | Único formato que cruza fronteras entre componentes |
| ⚡ **API** | FastAPI · Pydantic v2 | Feed de Misiones y motor de progresión |
| 🔐 **Identidad** | JWT + Argon2id · refresh rotativo | Sesiones revocables con detección de reutilización |
| 💾 **Persistencia** | PostgreSQL 16 · SQLAlchemy 2.0 async · Alembic | Eventos de XP append-only; la progresión se deriva de ellos |
| 🖥️ **Frontend** | Next.js 15 · React 19 · Tailwind 3.4 | Consola cyberpunk |
| 🐳 **Local** | Docker Compose (con perfiles) | 13 servicios, arrancables por partes |
| ☁️ **Nube** | Terraform 1.10 · GCP | Cloud Run con escalado a cero, Secret Manager, VPC + Cloud NAT |
| 🛡️ **CI/CD** | GitHub Actions | 9 puertas: secretos, lint, tests, STIX, IaC, contenedores |

---

## 🚀 Puesta en marcha

### Requisitos

| Herramienta | Versión | Necesaria para |
|---|---|---|
| Python | ≥ 3.12 | API y conectores |
| Node.js | ≥ 18.18 | Frontend |
| Docker + Compose V2 | reciente | Stack completo |
| Terraform | ≥ 1.6 | Despliegue en GCP (opcional) |

### ⚡ Ruta 1 — Sólo la consola (30 segundos, cero dependencias de red)

El frontend arranca en **modo autónomo** si la API no responde: sirve el
catálogo local y calcula la progresión del lado del cliente.

```bash
cd src/frontend && npm install && npm run dev
```

→ http://localhost:3000

### 🔧 Ruta 2 — API + consola (desarrollo normal)

La API **necesita PostgreSQL**: la progresión del analista es persistente y
arrancar sin base sería arrancar perdiendo datos en silencio.

```bash
cp .env.example .env    # ⚠️ editá los <<CAMBIAR>> antes de seguir
```

```bash
python3 -m venv .venv && source .venv/bin/activate && pip install -r src/api/requirements.txt
```

```bash
make db-up && make db-upgrade
```

```bash
cd src/api && uvicorn main:app --reload --port 8000
```

Y en otra terminal:

```bash
cd src/frontend && npm install && npm run dev
```

| Servicio | URL |
|---|---|
| 🖥️ Consola | http://localhost:3000 |
| ⚡ API | http://localhost:8000 |
| 📚 Documentación viva (Swagger) | http://localhost:8000/docs |

### 🐳 Ruta 3 — Stack CTI completo (~8 GB de RAM)

ElasticSearch no arranca sin este `sysctl`:

```bash
sudo sysctl -w vm.max_map_count=1048575
```

```bash
make env && make up-cti
```

| Servicio | URL | Notas |
|---|---|---|
| 🖥️ Consola | http://localhost:3000 | |
| ⚡ API | http://localhost:8000/docs | |
| 🧠 OpenCTI | http://localhost:8080 | Primer arranque: 2-4 min |
| 🤝 MISP | https://localhost:8443 | Certificado autofirmado |
| 🕷️ SpiderFoot | http://localhost:5001 | Perfil `hunt` |

Todos los objetivos disponibles:

```bash
make help
```

---

## 🔑 Variables de entorno

Todo sale de `.env`. La plantilla [`.env.example`](.env.example) trae los
comandos exactos para generar cada secreto:

```bash
openssl rand -hex 32       # API_SECRET_KEY
openssl rand -base64 24    # contraseñas de servicios
uuidgen                    # OPENCTI_ADMIN_TOKEN (debe ser UUIDv4)
```

> ⚠️ `.env` está en `.gitignore`. Si alguna vez lo commiteás, **rotá todo**:
> un secreto commiteado es un secreto quemado, aunque borres el commit.

---

## ⚡ API

Base: `http://localhost:8000` · Swagger interactivo en `/docs`

| Método | Endpoint | Qué hace |
|---|---|---|
| `GET` | `/health` | Sonda de **vida**. Sin dependencias externas a propósito |
| `GET` | `/health/ready` | Sonda de **preparación**: incluye PostgreSQL |
| `GET` | `/api/v1/feed` | Página del Feed de Misiones + bundle STIX 2.1 |
| `GET` | `/api/v1/feed/{id}` | Detalle de una misión |
| `GET` | `/api/v1/feed/{id}/stix` | Bundle crudo, importable en OpenCTI |
| `POST` | `/api/v1/auth/register` | Alta de analista |
| `POST` | `/api/v1/auth/login` | Inicia sesión (cookies httpOnly) |
| `POST` | `/api/v1/auth/refresh` | Rota la sesión |
| `POST` | `/api/v1/auth/logout` | Revoca del lado del servidor |
| `GET` | `/api/v1/auth/me` | Quién sos según tu token |
| `POST` | `/api/v1/level-up` 🔒 | Registra un evento de XP y resuelve el ascenso |
| `POST` | `/api/v1/missions/{id}/verdict` 🔒 | **Emite un veredicto**: qué creés y con cuánta certeza |
| `POST` | `/api/v1/missions/{id}/resolve` 🎓 | Fija la verdad y califica lo pendiente |
| `GET` | `/api/v1/analysts/{callsign}/calibration` | Cuánto vale su palabra, no cuánto trabajó |
| `GET` | `/api/v1/ranks` | Escalera completa de rangos |
| `GET` | `/api/v1/xp-table` | Cuánto vale cada acción (transparencia total) |
| `GET` | `/api/v1/analysts/{callsign}` | Estado del analista |
| `GET` | `/api/v1/leaderboard` | Ranking de la torre |
| `GET` | `/api/v1/stats` | Métricas del tablero |

🔒 requiere sesión · 🎓 requiere rol `INSTRUCTOR`. El feed y el leaderboard
son públicos: mirar no necesita cuenta, operar sí.

**Parámetros del feed:** `cursor` (opaco, para scroll infinito), `limit`
(1-100), `severity` (`low|medium|high|critical`). El rango del observador sale
del token, no de un parámetro.

```bash
curl "http://localhost:8000/api/v1/feed?limit=3&severity=critical"
```

```bash
curl -X POST http://localhost:8000/api/v1/level-up \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"event":"ioc_verified","severity":"high"}'
```

---

## 📐 El modelo de datos

Cada misión es, por debajo, un micro-bundle STIX 2.1 coherente:

```
🔍 Indicator ──indicates──▶ 🦠 Malware ──uses──▶ 🎯 Attack Pattern
   (patrón STIX)              (is_family)          (MITRE ATT&CK)
```

El conector de referencia genera ese grafo **sin una sola dependencia externa**,
para que cualquiera pueda verlo en un contenedor pelado:

```bash
python3 src/ingestion/misp_stix_connector.py --validate
```

```
╔══════════════════════════════════════════════════════════╗
║  ATALAYA · Validación STIX 2.1                           ║
╚══════════════════════════════════════════════════════════╝
  Objetos: 11
    Grafo:
      C2 Akira — 198.51.100.42     --indicates-> Akira
      Akira                        --uses-> Data Encrypted for Impact
  [✓] Bundle STIX 2.1 estructuralmente válido.
```

| Comando | Qué hace |
|---|---|
| `--pretty` | JSON indentado |
| `--validate` | Valida y muestra el grafo |
| `-o archivo.json` | Escribe a disco |
| `--push` | Publica en OpenCTI (requiere `pycti` y token) |

> 🧪 **El catálogo de arranque es sintético a propósito**: usa rangos
> reservados por RFC 5737 y dominios RFC 2606, así que copiarlo a un firewall
> no bloquea infraestructura de terceros. Sirve para que la consola tenga algo
> que mostrar antes de conectar nada.
>
> **Los IoCs que entran por los conectores sí son reales**, y por eso el
> normalizador descarta cualquier observable que caiga en rango reservado
> antes de publicarlo como amenaza.

---

## 🔐 Identidad

**El callsign sale del token. Nunca del cuerpo de la petición.**

Esa frase es la corrección de seguridad central del proyecto. Mientras el
analista viajaba en el cuerpo, `POST /api/v1/level-up` aceptaba el nombre que
uno quisiera: alcanzaba un `curl` para ascenderse a Cazador de Amenazas, o para
vaciarle la XP a otro. `LevelUpRequest` y `VerdictRequest` **ya no tienen campo
`callsign`**, y hay tests que lo demuestran mandándolo igual.

### Cómo está armado

| Pieza | Elección | Por qué |
|---|---|---|
| Contraseñas | **Argon2id** | bcrypt trunca en 72 bytes sin avisar |
| Access token | JWT HS256, **15 min** | Sin estado, rápido de validar, imposible de revocar — por eso dura poco |
| Refresh token | Cadena opaca, **30 días**, guardada **hasheada** | Revocable y rotatoria. Un volcado de la tabla no entrega sesiones |
| Transporte | Cookies **httpOnly + SameSite=strict** | Un token que JavaScript puede leer es un token que un XSS se lleva |
| Bearer | Aceptado además de la cookie | Para `curl`, scripts y el conector de ingesta |

### Rotación con detección de reutilización

Cada renovación emite un refresh nuevo y revoca el anterior. Si aparece un
token **ya rotado**, se asume que alguien clonó la sesión y se revoca **toda la
familia** del analista. Es la recomendación del BCP de OAuth 2.0, y el
razonamiento es simple: obligar a volver a entrar molesta; dejar viva una
sesión robada, no se arregla después.

### Lo que se defiende, y cómo

| Ataque | Defensa |
|---|---|
| Otorgarse XP como otro | La identidad sale del token; el `callsign` del cuerpo se ignora |
| Fuerza bruta | 5 intentos y bloqueo de 15 min, **persistido en la base** |
| Enumeración de cuentas | Mismo mensaje y mismo tiempo de respuesta exista o no la cuenta |
| Robo de token vía XSS | Cookies httpOnly: JavaScript nunca las ve |
| CSRF | `SameSite=strict` + CORS restringido al origen conocido |
| Fijar la verdad de una misión | Rol `INSTRUCTOR`: quien fija la verdad decide quién gana XP |
| Llenar la tabla con GETs | Las lecturas ya no dan de alta analistas |

### Roles

`ANALYST` opera misiones y emite veredictos · `INSTRUCTOR` además fija la
verdad de referencia · `ADMIN` todo. **El rol no se puede declarar al
registrarse**: hay un test que lo intenta.

## 💾 Persistencia

La progresión del analista vive en PostgreSQL, y con una regla que ordena todo
lo demás: **la XP no es un contador, es una suma**.

```
analysts    → identidad y nada más
xp_events   → append-only. La XP del analista ES la suma de esta tabla
```

No existe una columna `analysts.xp`. Un contador mutable es una segunda fuente
de verdad, y toda segunda fuente de verdad termina desincronizada del historial
que la produjo. Acá el historial **es** el saldo, y de paso es la auditoría
completa de cómo cada analista llegó a su rango.

### El detalle que hace que funcione

Cada evento guarda **dos** deltas:

| Campo | Qué es | Ejemplo |
|---|---|---|
| `xp_delta_nominal` | Lo que dice la tabla de XP | `-75` |
| `xp_delta_applied` | Lo que realmente movió el saldo | `-30` (sólo tenía 30) |

Sin esa distinción, `SUM(delta)` no coincide con aplicar los eventos en orden
respetando el piso en cero, y la suma daría un saldo negativo imposible. Con
ella, `SUM(xp_delta_applied)` es exacta siempre, y el nominal queda como
evidencia de qué se intentó cobrar.

### Anti-farmeo

Un índice **parcial** único sobre `(analyst_id, mission_id, event)` impide
cobrar el mismo evento dos veces sobre la misma misión. Sin él, clickear
"Triar" cien veces sobre la misma alerta te deja en Cazador de Amenazas sin
haber analizado nada. Es parcial —`WHERE mission_id IS NOT NULL`— para que los
eventos genéricos sigan siendo repetibles.

### Migraciones

```bash
make db-upgrade                          # aplicar pendientes
make db-revision M="agregar tabla X"     # generar una nueva
make db-sql                              # ver el SQL sin aplicarlo
make db-history                          # historial y revisión actual
```

El pipeline verifica en cada push que las migraciones **se apliquen, se
reviertan y vuelvan a aplicarse**, y que el esquema desplegado coincida con
`models.py`. Una migración que no sabe volver atrás no se puede desplegar con
confianza: si el despliegue falla a mitad de camino, no hay retirada.

### Dónde corre

| Entorno | Base |
|---|---|
| Local | Contenedor `postgres:16-alpine` (`make db-up`) |
| Tests | PostgreSQL efímero vía `pgserver` — nunca SQLite |
| CI | Servicio de Postgres de GitHub Actions |
| GCP | Neon/Supabase (gratis) o Cloud SQL (`enable_cloud_sql`) |

Los tests corren contra PostgreSQL **real** porque el repositorio usa índices
parciales, funciones de ventana y `SELECT ... FOR UPDATE`. Contra SQLite
pasarían verdes probando otra cosa.

## 📡 Ingesta

Tres conectores contra fuentes OSINT reales. Cada uno aporta algo distinto:

| Fuente | Qué aporta | Credencial |
|---|---|---|
| **CISA KEV** | Verdad de referencia **dura**: explotación activa observada, no inferida | ninguna, es público |
| **abuse.ch ThreatFox** | IoCs de C2 con familia de malware asociada | `ABUSECH_AUTH_KEY` |
| **AlienVault OTX** | Contexto narrativo: campañas, familias, técnicas ATT&CK | `OTX_API_KEY` |

```bash
make ingest-dry        # consulta y muestra, sin escribir nada
make ingest            # consulta y persiste las misiones
make ingest-resolve    # cierra la corroboración vencida
make ingest-loop       # ciclo continuo (perfil docker `ingesta`)
```

Sin credenciales, cada conector **avisa y se saltea**. CISA KEV no necesita
ninguna, así que el sistema produce misiones reales desde el primer minuto.

### Contar operadores, no APIs

Es la decisión que sostiene la corroboración, y es fácil de errar en silencio:

> ThreatFox, URLhaus y MalwareBazaar son tres APIs distintas del **mismo
> operador** (abuse.ch). Un indicador presente en las tres no está corroborado
> por tres partes: está corroborado por una, tres veces.

Si eso contara como 3, cruzaría el umbral solo y el sistema declararía verdades
que ninguna segunda parte verificó. Por eso la unidad de conteo es la
**familia** (`SourceFamily`), no el nombre de la fuente. Hay un test dedicado a
que nadie lo "optimice" después.

### Cómo se resuelve una misión

```
T+0h    Una sola fuente reporta el IoC · confianza 55
        → entra AMBIGUA · el analista apuesta a ciegas

T+72h   ¿Cuántos OPERADORES distintos terminaron corroborando?
        ≥ 3            → MALICIOUS  · se califican los veredictos
        1, baja conf.  → BENIGN     · nadie más lo vio: era ruido
        2             → sin resolver · la misión expira sin calificar
```

El tercer caso importa tanto como los otros dos: **no se inventa una verdad
para poder puntuar**. Enseñarle al analista una lección falsa es peor que no
enseñarle ninguna.

### Buena vecindad con las fuentes

Las APIs OSINT gratuitas se sostienen con buena fe, así que el respeto por sus
límites es parte del conector, no una opción:

- Espaciado mínimo entre peticiones, por fuente.
- Reintentos con espera creciente (2s → 4s → 8s); un `429` **corta** la corrida
  en vez de insistir.
- El catálogo KEV pesa 1,7 MB y cambia pocas veces por semana: se pide con
  petición condicional y sólo se transfiere si cambió.

> ⚠️ Medido contra el servidor real: el CDN de CISA **expone** un `ETag` pero
> **ignora** `If-None-Match` — sólo honra `If-Modified-Since`. Confiar sólo en
> el ETag, que es lo que uno escribiría por costumbre, deja la optimización
> como código muerto sin que nada falle a la vista.

Una fuente caída **nunca** tumba la corrida: cada conector se aísla, se
registra el fallo y se sigue con los demás.

## 🎯 El bucle de verificación

**Esto es el producto.** Todo lo demás es infraestructura para que funcione.

Una academia tiene que poder responder una pregunta: **¿el analista acertó?**
Sin eso, cualquier plataforma de "entrenamiento" es un clicker con estética de
SOC. Diseño completo en **[docs/VERIFICACION.md](docs/VERIFICACION.md)**.

### No premiamos acertar. Premiamos calibrar.

Un buen analista no es el que siempre acierta: es el que sabe cuánto sabe.
Quien dice *"80% de confianza"* y acierta el 80% de las veces vale más que
quien dice *"100% seguro"* y acierta el 85% — el segundo es más preciso y **más
peligroso**, porque cuando se equivoca arrastra al SOC con su certeza.

Por eso el veredicto no es un botón, es una apuesta declarada:

```bash
curl -X POST http://localhost:8000/api/v1/missions/MSN-D46B6B85/verdict \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"call":"MALICIOUS","confidence":75,
       "rationale":"Dominio de 6 días, certificado TLS compartido con dos dominios ya marcados."}'
```

Y se califica con **Brier**, la regla estándar en torneos de pronóstico:

```
brier = (confianza/100 − resultado)²        xp = base × (1 − 4·brier)
```

| Declaró | Realidad | XP (base 100) |
|---|---|---:|
| 100% malicioso | malicioso | **+100** |
| 80% malicioso | malicioso | **+84** |
| 50% cualquiera | cualquiera | **0** |
| 80% malicioso | benigno | **−156** |
| 100% malicioso | benigno | **−300** |

Tres propiedades, y ninguna es una política del producto — las tres salen de
la matemática:

1. **Cubrirse no paga.** La pendiente 4 es el único valor que hace que declarar
   50% dé exactamente 0. No se puede farmear hedgeando.
2. **Equivocarse con certeza cuesta el triple** de lo que rinde acertar con
   certeza. En un SOC, ésa es la proporción correcta.
3. **El sistema no se puede jugar.** Brier es una *regla propia*: la estrategia
   que maximiza la XP esperada es declarar tu creencia real. Hay un test que lo
   verifica numéricamente sobre todo el rango de confianzas.

### De dónde sale la verdad

| Origen | Qué la hace verdad | Cuándo califica |
|---|---|---|
| `KEV` | Estar en el catálogo de CISA **es** explotación observada | Inmediata |
| `MULTI_SOURCE` | 3 fuentes independientes coinciden | Inmediata |
| `CORROBORATION` | **Diferida**: qué pasó en las 72 h siguientes | A las 72 h |
| `CURATED` | Un instructor escribió la respuesta | Inmediata |

La corroboración diferida es el corazón pedagógico: entrena lo único que
importa en un SOC, **decidir con información incompleta y que el tiempo te dé
o te quite la razón**. El veredicto se sella con marca de tiempo; apostar
después de que la verdad se hizo pública no puntúa.

### El catálogo tiene verdades de los dos signos

De las 8 misiones, **4 son maliciosas, 2 benignas y 2 quedan sin resolver**.
Las benignas no son decorativas: sin ellas, *"decir siempre MALICIOSO"* sería
estrategia ganadora y el sistema mediría obediencia en vez de criterio. Hay un
test que protege esa propiedad.

### La métrica que ningún producto del rubro muestra

```
GET /api/v1/analysts/gon/calibration
```

| Analista | XP | Brier | Calibración | Sobreconfianza |
|---|---:|---:|---:|---:|
| prudente | 82 | 0.122 | 0.877 | −0.350 |
| cowboy | 160 | 0.000 | 1.000 | +0.000 |
| tímido | 0 | 0.302 | 0.698 | **+0.550** |

`sobreconfianza > 0` significa que el analista **cree saber más de lo que
sabe**. Es el número que un jefe de SOC realmente quiere ver. La XP dice
cuánto trabajó; la calibración dice cuánto vale su palabra.

## 🎮 Gamificación

### Rangos

| Nivel | Rango | XP | Clearance | Desbloquea |
|:---:|---|---:|---|---|
| 1️⃣ | 🟢 **Novato** | 0 | `OBSERVADOR` | Lectura del feed, triage |
| 2️⃣ | 🔵 **Analista Junior** | 250 | `CONTRIBUYENTE` | Enriquecer IoCs, reportar, sandbox |
| 3️⃣ | 🟣 **Analista Senior** | 1.200 | `VERIFICADOR` | Verificar, correlacionar campañas, pivotear el grafo |
| 4️⃣ | 🟠 **Cazador de Amenazas** | 4.000 | `OPERADOR` | Publicar en MISP, crear misiones, desplegar YARA, proponer atribución |

### Tabla de XP

| Acción | XP | |
|---|---:|---|
| Triar una misión | +10 | |
| Enriquecer un IoC | +25 | |
| Verificar un IoC | +60 | |
| Confirmar una correlación | +120 | |
| Regla YARA aceptada | +200 | |
| Atribuir una campaña | +300 | |
| Revisión entre pares | +40 | |
| Primera sangre (misión crítica) | +150 | |
| **Publicar un falso positivo** | **−75** | ⚠️ |
| **Dejar expirar una misión** | **−15** | ⚠️ |

**Multiplicador de severidad:** baja ×1.0 · media ×1.25 · alta ×1.6 · crítica ×2.0

> Las penalizaciones **no** se multiplican por severidad, y la XP nunca baja de
> cero. Castigamos el error, no la ambición: si equivocarse en lo difícil
> costara el doble, nadie se metería con lo difícil.

---

## 🛡️ DevSecOps

El pipeline ([`.github/workflows/devsecops.yml`](.github/workflows/devsecops.yml))
corre 9 puertas en cada push y PR:

| # | Puerta | Herramienta | Rompe el build si… |
|:---:|---|---|---|
| 1 | 🔑 Secretos | TruffleHog + Gitleaks | hay un secreto verificado |
| 2 | 🐍 Lint Python | flake8 + black + bandit | estilo o SAST de severidad alta |
| 3 | 🧪 Tests | pytest | falla un test |
| 4 | 📐 Contrato STIX | validador propio + `stix2-validator` | el bundle deja de ser válido |
| 5 | ⚡ Frontend | ESLint + `tsc` + `next build` | no compila |
| 6 | 🏗️ Terraform | `fmt` + `validate` | HCL mal formado o inválido |
| 7 | 🛡️ Trivy | vulns + secretos + misconfigs IaC | CVE **CRITICAL** con fix |
| 8 | 🐳 Dockerfiles | hadolint | error de nivel `error` |
| 9 | 🚦 Puerta | consolidación | cualquiera de las anteriores falló |

Dos escáneres de secretos porque usan criterios distintos: TruffleHog
**verifica activamente** las credenciales encontradas, Gitleaks trabaja por
patrón. Se complementan.

### Verificación local

```bash
make lint && make test && make stix-validate
```

---

## ☁️ Infraestructura (GCP)

```bash
cd infra/terraform && cp terraform.tfvars.example terraform.tfvars
```

Completá `project_id` y `admin_cidrs` con tu IP real (`curl -s https://ifconfig.me`), y:

```bash
terraform init && terraform plan
```

### Por qué Cloud Run

Escala a cero. Un proyecto de entrenamiento recibe visitas a ráfagas, y pagar
una máquina prendida 24/7 para tráfico intermitente es tirar plata. Además
corre los `Dockerfile` de este repo tal cual están.

**Qué construye:** VPC + subred con Flow Logs · Cloud NAT (salida sin IPs
públicas) · 5 reglas de firewall · Artifact Registry con política de limpieza ·
3 cuentas de servicio dedicadas · 3 secretos en Secret Manager · 2 servicios de
Cloud Run · y, opcionales y apagados por defecto, Cloud SQL y el nodo CTI.

### Endurecimiento incluido de fábrica

- ⛔ `admin_cidrs` **no tiene default** y **rechaza `0.0.0.0/0`** por validación.
  Junto con otras 7 validaciones, abortan el `plan` antes de tocar nada.
- 🔑 **Terraform crea los secretos, nunca sus valores.** Cargar el valor en el
  código lo deja en texto plano dentro del archivo de estado, que casi siempre
  tiene más lectores que el secreto original. Las versiones se cargan aparte
  con `gcloud secrets versions add`.
- 👤 **Cuentas de servicio dedicadas.** El proyecto trae una cuenta de cómputo
  por defecto con rol Editor sobre todo; usarla es el hallazgo #1 de cualquier
  auditoría de GCP. Acá cada carga de trabajo tiene identidad propia con lo
  mínimo, y los permisos de Secret Manager se conceden **secreto por secreto**.
- 🚪 **SSH sólo por IAP.** El puerto 22 nunca se abre a Internet: se entra con
  `--tunnel-through-iap`, con identidad de Google y auditoría completa.
- 🛡️ **Shielded VM** en el nodo CTI (arranque seguro, vTPM, monitoreo de
  integridad) y OS Login con claves de proyecto bloqueadas.
- 🌐 **Sin IPs públicas** en el nodo CTI ni en Cloud SQL. La salida va por NAT.
- 🧾 **Deny de ingreso explícito y registrado** en prioridad 65534: GCP ya
  deniega en 65535, pero de forma invisible en los logs.
- 💸 `max_instances` acotado: es el freno de mano contra la factura.

### Costo

| Componente | Costo |
|---|---|
| Cloud Run (2 servicios, escala a cero) | Nivel gratuito para tráfico de demo |
| Secret Manager, Artifact Registry, VPC | Nivel gratuito |
| Cloud SQL (`enable_cloud_sql`) | ❌ **Sin nivel gratuito.** Apagado por defecto |
| Nodo CTI (`enable_cti_node`) | ❌ ~8 GB sostenidos. Apagado por defecto |

La ruta de costo cero es dejar los dos últimos apagados y usar un PostgreSQL
serverless externo (Neon, Supabase), cargando su cadena de conexión en el
secreto `atalaya-database-url`. La API consume un `DATABASE_URL` y le da igual
de dónde salga.

> ⚠️ Los niveles gratuitos cambian. Verificá los límites vigentes antes de
> comprometerte.

### El detalle que muerde

`NEXT_PUBLIC_API_URL` se resuelve en tiempo de **build**, no de runtime: Next
la incrusta en el bundle del navegador. Pasarla como variable de entorno de
Cloud Run no afecta al código del cliente. Tiene que ir como `--build-arg` al
construir la imagen — el output `comandos_build` de Terraform te da la línea
exacta.

## 📁 Estructura

```
atalaya/
├── 📄 README.md · SECURITY.md · Makefile
├── 🔧 .env.example          # plantilla con generadores de secretos
├── 🛡️ .github/workflows/
│   └── devsecops.yml        # 9 puertas de calidad
├── 🐳 deployments/docker/
│   └── docker-compose.yml   # 13 servicios · perfiles: (base) · cti · hunt
├── ☁️ infra/terraform/          # GCP
│   ├── main.tf              # APIs · VPC · Cloud NAT · firewall
│   ├── identity.tf          # cuentas de servicio · registro · secretos
│   ├── cloudrun.tf          # API y consola, escalado a cero
│   ├── data_layer.tf        # Cloud SQL (opcional, apagado)
│   ├── cti_node.tf          # nodo OpenCTI/MISP (opcional, apagado)
│   ├── variables.tf         # 8 validaciones que abortan el plan
│   ├── outputs.tf · versions.tf · terraform.tfvars.example
├── 🧠 src/
│   ├── api/                 # FastAPI
│   │   ├── main.py          # endpoints + endurecimiento HTTP
│   │   ├── gamification.py  # motor de reglas PURO (sin estado)
│   │   ├── repository.py    # persistencia async: progresión + veredictos
│   │   ├── scoring.py       # Brier: el motor que califica los veredictos
│   │   ├── auth.py          # Argon2id + JWT (puro, sin base)
│   │   ├── auth_repository.py  # sesiones, rotación, bloqueos
│   │   ├── models.py        # SQLAlchemy: analysts + xp_events
│   │   ├── migrations/      # Alembic
│   │   ├── stix_feed.py     # generador del Feed de Misiones
│   │   ├── schemas.py · config.py · Dockerfile
│   ├── ingestion/
│   │   ├── misp_stix_connector.py   # STIX 2.1 puro, sin dependencias
│   │   ├── base.py          # contrato común · SourceFamily
│   │   ├── sources/         # cisa_kev · threatfox · otx
│   │   ├── normalize.py     # indicador crudo → misión
│   │   └── run.py           # orquestador CLI
│   └── frontend/            # Next.js 15
│       ├── app/page.tsx     # consola: panel + feed infinito
│       ├── tailwind.config.ts  # sistema de diseño cyberpunk
│       ├── components/      # MissionCard · AnalystPanel · StatusBar
│       └── lib/             # tipos · cliente API · catálogo local
├── 📚 docs/
│   ├── VERIFICACION.md      # ← el diseño que define el producto
│   └── ARQUITECTURA.md
└── 🧪 tests/                # 120 tests: identidad, progresión, persistencia, verificación, ingesta y STIX
```

---

## 🗺️ Hoja de ruta

- [x] Modelo de datos STIX 2.1 y conector de referencia
- [x] API del Feed de Misiones con paginación por cursor
- [x] Motor de progresión con 4 rangos y penalizaciones
- [x] Consola cyberpunk con scroll infinito y degradación autónoma
- [x] Pipeline DevSecOps de 9 puertas
- [x] Infraestructura en GCP (Cloud Run + Secret Manager + VPC)
- [x] Persistencia en PostgreSQL con progresión derivada de eventos
- [x] Bucle de verificación con puntuación por calibración (Brier)
- [x] Autenticación con JWT + refresh rotativo y roles
- [x] Conectores reales de CISA KEV, ThreatFox y OTX con corroboración entre operadores
- [ ] 🟡 Sincronización bidireccional OpenCTI ↔ MISP
- [ ] 🟢 Modo competitivo por equipos (CTF con multiplicador ×2)
- [ ] 🟢 Editor de reglas YARA/Sigma con validación en vivo

---

## ⚖️ Ética y uso responsable

ATALAYA es una plataforma **defensiva y educativa**. Procesa inteligencia de
amenazas para entrenar analistas, no para atacar a nadie.

- 🚫 El repositorio **no aloja muestras de malware**. Se referencian hashes.
- 🏷️ Se respeta el **TLP** de cada objeto. Publicar TLP:RED fuera de su círculo
  destruye la relación con la fuente y, muchas veces, la investigación.
- 🧊 Los observables se muestran **neutralizados**, nunca como enlace.
- 🧪 El catálogo de demostración usa **IoCs sintéticos**.

Reporte de vulnerabilidades: **[SECURITY.md](SECURITY.md)**

---

<div align="center">

**ATALAYA** · STIX 2.1 · MITRE ATT&CK

*El que vigila desde arriba ve venir la amenaza primero.*

</div>
