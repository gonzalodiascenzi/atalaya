# 🔐 Política de Seguridad — ATALAYA

Este proyecto manipula **inteligencia de amenazas real**. Un descuido acá no rompe
un build: expone infraestructura, quema fuentes o filtra indicadores bajo TLP.

## Reporte de vulnerabilidades

No abras un issue público. Escribí a `security@atalaya.localhost` (reemplazar por
el buzón real) con:

- Descripción y superficie afectada.
- PoC mínima y reproducible.
- Impacto estimado.

Compromiso de respuesta: **72 h** para acuse, **90 días** de disclosure coordinado.

## Reglas no negociables del repo

| Regla | Por qué |
|---|---|
| Ningún secreto en el repo, ni en tests, ni en fixtures | TruffleHog + Trivy fallan el build; y un secreto commiteado es un secreto quemado |
| Nada de muestras de malware vivas | El repo no es un zoo; usá hashes y referencias a MalwareBazaar |
| Respetar TLP en cada objeto STIX | Publicar TLP:RED fuera de su círculo destruye la relación con la fuente |
| Contenedores sin `privileged`, sin root donde se pueda | Contención del blast radius |
| `admin_cidrs` en Terraform jamás en `0.0.0.0/0` | Los puertos de OpenCTI/MISP son puertos de administración |

## Autenticación

| Aspecto | Implementación |
|---|---|
| Contraseñas | Argon2id, mínimo 12 caracteres, rehash automático al endurecer parámetros |
| Sesión | Access JWT de 15 min + refresh opaco de 30 días guardado hasheado |
| Transporte | Cookies httpOnly, SameSite=strict, Secure en producción |
| Rotación | Cada renovación revoca el anterior; reutilización revoca la familia |
| Fuerza bruta | 5 intentos → bloqueo de 15 min, persistido en base |
| Enumeración | Mismo mensaje y mismo tiempo exista o no la cuenta |

`API_SECRET_KEY` firma los access tokens. **Rotarla invalida todas las sesiones
activas**, que es exactamente lo que querés ante una sospecha de compromiso.

## Manejo de indicadores

Los IoCs que entran al feed de misiones se tratan como **datos no confiables**:
se renderizan defanged (`hxxp://`, `1.2.3[.]4`) y nunca como links clickeables.
La defensa contra un click accidental es de diseño, no de disciplina.
