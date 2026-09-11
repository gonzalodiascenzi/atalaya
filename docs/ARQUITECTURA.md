# 🏗️ ATALAYA · Arquitectura

> Documento vivo. Si cambiás el flujo de datos y no actualizás esto, el
> próximo que llegue va a leer una mentira prolija.

---

## 1. Vista de 10.000 pies

```mermaid
flowchart LR
    subgraph OSINT["🌐 Fuentes OSINT"]
        OTX["AlienVault OTX<br/>pulsos"]
        ABUSE["abuse.ch<br/>ThreatFox · URLhaus"]
        KEV["CISA KEV<br/>explotadas activamente"]
        SF["SpiderFoot<br/>reconocimiento"]
    end

    subgraph ING["⚙️ Capa de ingesta (Python)"]
        CONN["Conectores<br/>normalizan a STIX 2.1"]
    end

    subgraph CORE["🧠 Correlación"]
        OCTI["OpenCTI<br/>grafo de conocimiento"]
        MISP["MISP<br/>compartición de IoCs"]
    end

    subgraph APP["🎮 Plataforma"]
        API["FastAPI<br/>feed + progresión"]
        PG[("PostgreSQL<br/>analistas · XP")]
        UI["Next.js<br/>consola cyberpunk"]
    end

    OTX --> CONN
    ABUSE --> CONN
    KEV --> CONN
    SF --> CONN
    CONN -->|"bundles STIX 2.1"| OCTI
    CONN -->|"eventos"| MISP
    MISP <-->|"sincronización"| OCTI
    OCTI -->|"consulta de indicadores"| API
    API <--> PG
    API -->|"REST · JSON"| UI
```

**La regla que sostiene todo:** el único formato que cruza fronteras entre
componentes es **STIX 2.1**. Ningún componente inventa su propio esquema de
indicadores. Cuando mañana entre una fuente nueva, se escribe un conector que
emite STIX y nada más se toca.

---

## 2. Recorrido de un IoC

Desde que aparece en el mundo hasta que un analista lo resuelve:

```mermaid
sequenceDiagram
    participant F as Fuente OSINT
    participant C as Conector
    participant O as OpenCTI
    participant A as API ATALAYA
    participant D as PostgreSQL
    participant U as Analista

    F->>C: IP maliciosa observada
    C->>C: normaliza a STIX 2.1<br/>(indicator + malware + attack-pattern)
    C->>C: UUIDv5 determinista → idempotencia
    C->>O: import_bundle (deduplica en el grafo)
    O->>A: indicador enriquecido + relaciones
    A->>A: envuelve como Misión<br/>(severidad → XP, rango requerido)
    A->>U: feed paginado (scroll infinito)
    U->>U: triage · enriquece · verifica
    U->>A: POST /api/v1/level-up
    A->>A: aplica tabla de XP + multiplicador
    A->>D: INSERT en xp_events (append-only)
    Note over A,D: el índice parcial único rechaza<br/>el mismo evento sobre la misma misión
    D-->>A: SUM(xp_delta_applied) = XP actual
    A-->>U: ¿ascenso? capacidades desbloqueadas
```

---

## 3. Decisiones de diseño y su porqué

| Decisión | Alternativa descartada | Motivo |
|---|---|---|
| **STIX 2.1 como lingua franca** | Esquema JSON propio | Interoperabilidad con OpenCTI, MISP, ATT&CK y cualquier plataforma del rubro. Un formato propio es una cárcel con vista linda. |
| **UUIDv5 determinista en los conectores** | UUIDv4 (lo que sugiere la spec) | Reingerir el mismo IoC debe actualizar, no duplicar. Con v4 el grafo se ensucia en días. |
| **XP calculada en el servidor** | Que el cliente mande el delta | Si el cliente decide cuánta XP gana, la gamificación dura hasta el primer `curl`. |
| **El callsign sale del token, jamás del cuerpo** | Confiar en el campo que manda el cliente | Con el callsign en el cuerpo, cualquiera opera en nombre de cualquiera. Es la corrección de seguridad central del proyecto. |
| **Refresh opaco en la base; access en JWT** | Refresh también en JWT | Un refresh en JWT no se puede revocar: no habría forma de cerrar sesión de verdad ni de cortar un token robado. |
| **Reutilizar un refresh revoca la familia entera** | Sólo rechazar ese token | Un token rotado que reaparece es señal de clonación. Volver a pedir login molesta; dejar viva una sesión robada, no se arregla. |
| **El contador de intentos fallidos se confirma antes de fallar** | Confiar en la transacción de la petición | La petición termina en 401 y el rollback se llevaba puesto el contador: el bloqueo por fuerza bruta no existía. |
| **XP derivada de `xp_events`, sin contador mutable** | Columna `analysts.xp` actualizada a mano | Un contador es una segunda fuente de verdad, y siempre termina discrepando del historial. Acá el historial *es* el saldo. |
| **Guardar el delta ya recortado por el piso en cero** | Guardar el nominal | Con el nominal, `SUM()` daría un saldo negativo imposible y el asiento afirmaría un descuento que nunca ocurrió. |
| **Índice parcial único por (analista, misión, evento)** | Confiar en el frontend | Sin él se farmea XP repitiendo la misma acción sobre la misma alerta. |
| **Tests contra PostgreSQL real** | SQLite en memoria | Índices parciales, funciones de ventana y `FOR UPDATE` no existen o difieren en SQLite: los tests pasarían verdes probando otra cosa. |
| **Migración como job previo, no al arrancar la API** | `create_all()` en el lifespan | Migrar desde N réplicas que arrancan a la vez es una carrera esperando a ocurrir. |
| **Penalización por falso positivo** | Sólo recompensas | En un SOC real, gritar "lobo" tiene costo. Entrenar sin ese costo produce analistas ruidosos. |
| **Penalización sin multiplicador de severidad** | Castigo proporcional | Castigar x2 por equivocarse en algo difícil desincentiva justamente lo que querés fomentar: que se metan con lo difícil. |
| **IoCs sintéticos (RFC 5737 / 2606)** | IoCs reales en el catálogo demo | Alguien va a copiar y pegar esto a un firewall. Que no bloquee infraestructura de un tercero. |
| **Contar familias de fuente, no nombres de fuente** | Contar cada API como una corroboración | ThreatFox, URLhaus y MalwareBazaar son un solo operador. Contarlos como tres haría que un IoC se corrobore a sí mismo. |
| **Sin corroboración y baja confianza ⇒ BENIGN** | Expirar todo lo no confirmado | Las misiones que enseñan a NO bloquear son tan valiosas como las otras, y sin ellas "decir siempre malicioso" gana. |
| **Evidencia a mitad de camino ⇒ sin resolver** | Forzar un veredicto para poder puntuar | Enseñar una lección falsa es peor que no enseñar ninguna. |
| **El worker de ingesta corre aparte de la API** | Una tarea de fondo dentro del proceso web | Si una fuente cuelga la conexión, no puede llevarse puesta la consola. |
| **El veredicto es la única acción que puntúa** | Conservar "triar" y "enriquecer" con XP | Dar XP por clickear era exactamente el clicker con estética de SOC que el producto viene a no ser. |
| **Vista previa de pagos calculada en el cliente** | Explicar la regla Brier con texto | Ver "+0 / −0" al 50% se entiende en un segundo; un párrafo de teoría no lo lee nadie. |
| **La fórmula del cliente se prueba contra la de Python** | Confiar en que se mantienen iguales | Si divergen, el analista ve un número que el servidor no le otorga. 176 filas de paridad. |
| **Contenido de la misión en JSONB** | Veinte columnas | Es contenido, no estado: nadie filtra por "objetivos", y cada conector nuevo aporta campos sin migración. |
| **Defang obligatorio en la UI** | Mostrar el observable crudo | Un feed de amenazas con URLs clickeables es un incidente esperando a ocurrir. |
| **Degradación autónoma del frontend** | Pantalla de error | Un entorno de entrenamiento que muere cuando muere el backend no entrena a nadie. |
| **Perfiles en Docker Compose** | Un compose monolítico | El stack CTI completo pide ~8 GB. Nadie debería necesitar eso para tocar el frontend. |
| **La API sólo detrás de CloudFront (OAC)** | Function URL pública | Abierta, cualquiera se salteaba CloudFront y elegía la IP que veía el limitador. |

---

## 4. Modelo de datos

El grafo mínimo que emite cada conector:

```mermaid
graph LR
    IND["🔍 Indicator<br/><small>pattern STIX<br/>valid_from / valid_until</small>"]
    MAL["🦠 Malware<br/><small>is_family: true<br/>malware_types</small>"]
    AP["🎯 Attack Pattern<br/><small>MITRE ATT&CK<br/>kill_chain_phases</small>"]
    INF["🖥️ Infrastructure<br/><small>command-and-control</small>"]
    OBS["👁️ Observed Data<br/><small>+ SCO ipv4-addr</small>"]
    ID["🏛️ Identity<br/><small>created_by_ref</small>"]

    IND -->|indicates| MAL
    IND -->|indicates| INF
    MAL -->|uses| AP
    MAL -->|uses| INF
    OBS -.->|object_refs| IND
    ID -.->|firma| IND
```

**Marcado TLP.** Todo objeto lleva `object_marking_refs`. Los IDs de las
marcas TLP están definidos por la propia spec STIX 2.1, así que se referencian
por ID y no se embeben: toda plataforma seria ya los tiene precargados.

**Nota histórica:** la spec conserva el nombre `TLP:WHITE`; TLP 2.0 lo renombró
a `TLP:CLEAR`, pero el objeto de marcado es el mismo.

---

## 5. Capas de red (AWS)

```mermaid
flowchart TB
    NET["🌍 Internet"]
    GH["🐙 GitHub Actions<br/>OIDC · sólo main"]

    subgraph AWS["Cuenta AWS · us-east-1"]
        CF["CloudFront<br/>CSP · HSTS · IP real → x-atalaya-ip"]
        S3[("S3 · consola estática<br/>privado · sólo esta distribución")]
        subgraph LAMBDA["Lambda · se apaga sin tráfico"]
            API["FastAPI + Web Adapter<br/>URL con AWS_IAM"]
        end
        SSM["🔑 SSM Parameter Store<br/>SecureString"]
        ECR["ECR · tags inmutables"]
    end

    NEON[("Neon · Postgres<br/>TLS verificado")]

    NET -->|"HTTPS"| CF
    CF -->|"/* · OAC"| S3
    CF -->|"/api/* · OAC firmado"| API
    API -->|"lee SUS 2 secretos al arrancar"| SSM
    API -->|"TLS verify-full"| NEON
    GH -->|"push de imagen"| ECR
    GH -->|"update-function-code"| API
    ECR -.-> API
```

**Una sola puerta.** La URL de la función exige firma IAM y sólo CloudFront
tiene permiso para firmarla (OAC, acotado a esta distribución). El bucket de
la consola, lo mismo. No hay camino a la API ni a la consola que no pase por
CloudFront, que es donde se ponen las cabeceras y se fija la IP del cliente.

**Por qué la IP la escribe CloudFront.** Una Function URL deja en
`X-Forwarded-For` sólo el valor de más a la izquierda: el que escribe el
cliente. Con la URL abierta y Uvicorn confiando en esa cabecera, el limitador
de tasa se salteaba rotando una IP inventada por pedido. Ahora una CloudFront
Function la pisa con `event.viewer.ip`, y Uvicorn corre con
`--no-proxy-headers`.

**Los secretos no pasan por Terraform.** Terraform sólo conoce los NOMBRES de
los parámetros para dar permiso de lectura; los valores se cargan con
`aws ssm put-parameter` y la API los lee al arrancar. Si el valor entrara por
Terraform quedaría en texto plano en el archivo de estado — y el estado suele
tener más lectores que el secreto que protege.

**Neon y `sslmode`.** Neon entrega `?sslmode=require&channel_binding=require`,
que asyncpg no entiende. `split_tls` los traduce a un `SSLContext` que
verifica cadena y nombre de host: perder channel binding sin compensarlo
habría sido una degradación silenciosa.

## 6. Qué falta (deuda consciente)

| Pendiente | Impacto | Prioridad |
|---|---|---|
| Rate limiting distribuido (hoy es por proceso) | Con N instancias de Lambda hay N contadores | 🟡 Media |
| Paginación del feed por desplazamiento, no por clave | Con ingesta concurrente, una misión nueva puede correr la página y repetir una | 🟢 Baja |
| Proveedor OIDC además de contraseñas locales | Hoy cada quien mantiene una contraseña más | 🟡 Media |
| Doble token anti-CSRF además de SameSite | SameSite=strict alcanza hoy, pero es una sola capa | 🟢 Baja |
| Sincronización bidireccional OpenCTI ↔ MISP | Duplicación manual de eventos | 🟢 Baja |
| Dominio propio + AWS WAF delante de CloudFront | Hoy se sirve en `*.cloudfront.net` sin WAF | 🟡 Media |
| Logs de acceso de CloudFront | Ante un incidente, sólo están los logs de la Lambda: no se ve lo que CloudFront cortó o sirvió de la consola | 🟡 Media |
| Ingesta programada en AWS | Hoy se corre a mano contra Neon | 🟡 Media |
