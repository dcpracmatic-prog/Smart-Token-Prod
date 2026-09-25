[![CI](https://github.com/dcpracmatic-prog/Smart-Token-Prod/actions/workflows/ci.yml/badge.svg)](https://github.com/dcpracmatic-prog/Smart-Token-Prod/actions/workflows/ci.yml)

# Smart Token Prod v0.10.5

Token post-cuántico (ML-KEM-768 + AES-256-GCM) cuya **diferenciación** es la
**trampa lógica secuencial persistente** (fases 1 → 2 → 3 en `.stok`),
endurecida con Argon2id. Argon2+AES solos son commodity (“pan y leche”);
aquí Argon2 **endurece la trampa**, no la reemplaza.

Versión del paquete: **0.10.5** (`pyproject.toml` / `smart_token_prod.__version__`).
Licencia vigente: **Elastic License 2.0** (`LICENSE.txt`).

## Qué entrega esta versión

1. **ML-KEM-768** (pqcrypto) — wrap post-cuántico del secreto compartido
2. **AES-256-GCM** — payload; clave = HKDF(ss, salt=Argon2id(master))
3. **Binding v2** — `sk` sola no descifra; `.stok` v2 sin oráculo salt/material
4. **Trampa lógica 1→2→3** — `fail_count` / flags / `recovery_tier` en `friction_snapshot`
5. **Argon2id + trabajo de trampa** — en **cada** intento (correcto o incorrecto)
6. **Denegaciones opacas** — CLI `open` y API (`open_stok`/`open_artifact`) por
   defecto **no** anuncian tier, fail_count ni work_factor; dueño: `reveal_friction=True` o `status`
7. **Phase 3 hang** — wrong master con `fail_count ≥ 3` → bucle bloqueante que **no retorna**
8. **Validation ladder (v0.8.1+)** — tras N fallos, OPEN exige N+1 validaciones **consecutivas de la misma clave correcta** (tope 4). Cualquier clave incorrecta intermedia resetea el contador de aciertos a cero; no se pueden acumular créditos parciales entre candidatas distintas.
9. **Defensa autónoma (file-borne)** — `friction_snapshot` + `friction_mac` van **embebidos en el propio `.stok`**. El archivo se defiende solo; no requiere red ni configuración del operador. El FrictionStore compartido (`FileFrictionStore` / Redis) es refuerzo **opcional** solo para el escenario multi-host (réplicas que quieren compartir el mismo contador).
10. **Núcleo C++** — `libfriction.so` + FFI opcional (`auto`/`native`/`python`)
11. **`sk` fuera de banda** — `.stok.key`
12. **CLI** — `smart-token protect | open | status | demo | version | doctor | print-dep | integrate | repair-mac`

## Contrato de producto (v0.10.5)

```text
Cada open() paga Argon2id + trabajo de trampa (bound a material de cifrado)
  → master correcto  → cuenta hacia OPEN (ladder: tras N fallos hacen falta
                       N+1 correctos seguidos, tope 4) + plaintext + reset friction
                       (incluso tras fail_count≥3), cuando la ladder se completa
  → master incorrecto → DENIED opaco + escalate fase en .stok / store
       parciales correctos en ladder incompleta → DENIED opaco (sin reset)
       si fail_count ≥ 3 (fase 3) → entra grind Argon2+iters (+fib flavor) y NO RETORNA
       (atacante debe matar el proceso; .stok castigado ya persistió; la clave
        del hang es fail_count, no recovery_tier)

Fases (snapshot; no se imprimen en deny):
  fail 1 → fase 1 (flag_fibonacci)
  fail 2 → fase 2 (flag_persistencia)
  fail 3+ → fase 3 (tarpit_triggered); tier salta @11k/22k/33k cum iters (máx 3)

Réplicas (mismo host / disco compartido):
  FileFrictionStore + flock sobre el inode del .stok → un fail_count compartido
  (no sidecar .lock; writes vía fd + verificación de inode — unlink+recreate
   del .stok bajo lock → fail-closed)
  Hosts distintos sin Redis/store de red → fuera de alcance (ver límites)
  Hang fase 3: tope process-local SMART_TOKEN_MAX_CONCURRENT_HANGS (default 2);
  no es límite de cluster Redis
```

- Differentiator = **trampa lógica persistente + crypto PQ**, no Argon2 solo.
- Fibonacci dentro del grind de fase 3 es **sabor narrativo / non-oracle**,
  **no** dureza criptográfica por sí sola.
- El archivo **nunca se destruye** por fallos.
- `status` inspecciona el snapshot (herramienta del dueño); **open**/API deny es opaco
  salvo `reveal_friction=True`.
- **Integridad de fricción (v0.10):** `friction_mac` inválida → fail-closed (OPEN
  prohibido; no se acepta snapshot vacío; deuda en disco no se borra). Open sin
  `sk` no muta fricción (no se puede re-MAC).
- **Ligadura del `public_label` (v0.10.3):** el AAD del AES-GCM se **deriva** de
  `public_label` mediante `core.expected_aad()` y se **recalcula al abrir** desde
  el campo en disco. El `aad` que viaja en el `.stok` es descriptivo y nunca se
  confía. Falsificar `public_label` → `InvalidTag` → DENIED opaco. Hasta la
  v0.10.2 se pasaba el `aad` almacenado al AEAD, así que la etiqueta y el
  criptograma no estaban realmente ligados y un `public_label` manipulado abría
  con `status=OPEN`.
- **Garantía de producto** para trampa/ladder/hang: ruta autenticada
  `protect_file` / `open_stok` / `sdk.*` con fricción integrity-checked.
  Reimplementación offline con `sk`+master+fuente reduce a Argon2 (commodity);
  no se puede impedir crypto primitiva offline, pero la trampa **file-borne**
  sí resiste manipulación del `.stok` sin `sk` (A1).
- Quien posee `sk` puede re-MAC un snapshot reseteado offline y saltarse el
  tarpit oficial; **no** obtiene plaintext sin master (límite B1 honesto).
- `protect`/`open` CLI exigen `--master` o `SMART_TOKEN_MASTER` (sin default demo).


## Usar como componente en otro proyecto

En lugar de copiar a `vendor/smart_token_prod/` (esa copia se queda vieja),
instala el paquete y usa el scaffolding:

```bash
pip install "smart-token-prod @ git+https://github.com/dcpracmatic-prog/Smart-Token-Prod.git@v0.10.5"
smart-token integrate /ruta/al/proyecto
```

Detalle, migración fuera de vendor/ y API SDK: [`docs/INTEGRATION.md`](docs/INTEGRATION.md).

## Uso rápido

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
# opcional: cd cpp && make all

smart-token protect modelo.stl --master "mi-secreto"
# → modelo.stl.stok  +  modelo.stl.stok.key
# (protect/open EXIGEN --master o SMART_TOKEN_MASTER)

# Deny opaco (sin imprimir tier). Tras fail_count≥3 + wrong: el proceso puede colgarse.
smart-token open modelo.stl.stok --master "malo" --key modelo.stl.stok.key

# Correcto incluso tras castigo → OPEN + reset (respetando ladder si aplica)
smart-token open modelo.stl.stok --master "mi-secreto" --key modelo.stl.stok.key -o out.stl

smart-token status modelo.stl.stok   # inspección interna del snapshot
smart-token demo
```

Códigos de salida `open`: **0** = OPEN, **1** = DENIED (si retorna).
Tras hang de fase 3 el proceso no sale solo — hay que matarlo.

Env: `SMART_TOKEN_ARGON2_TIME`, `SMART_TOKEN_ARGON2_MEM` (KiB),
`SMART_TOKEN_ARGON2_PARALLELISM`. Hang de fase 3: `SMART_TOKEN_PHASE3_HANG`
(default `1`; `0`/`false`/`off` lo desactiva). Tope local de hangs concurrentes:
`SMART_TOKEN_MAX_CONCURRENT_HANGS` (default `2`; process-local, no cluster).
Tests también usan el override `_phase3_hang=False` en `open` / `open_stok`.
También: `SmartTokenProd.open(..., reveal_friction=False)` opaco por defecto.

## Demo: hang silencioso vs open correcto

```bash
# 1) Proteger y fallar hasta fail_count≥3 (hang OFF solo en tests; en prod hang ON)
smart-token demo   # la demo desactiva hang internamente

# 2) Castigar a fail_count≥3, luego wrong open con hang (proceso no retorna ~segundos)
#    Ver test_wrong_open_at_tier3_hangs_in_subprocess — subprocess + timeout.

# 3) Mismo .stok castigado + master correcto → ladder + OPEN + reset friction
```

## Límites de esta versión (v0.10.5)

| Garantía | Fuera de alcance |
|----------|------------------|
| Confidencialidad ML-KEM + AES-GCM del payload | Canales laterales |
| Trap + fail_count **embebidos en el `.stok`** (file-borne; autónomo) + flock; FrictionStore compartido opcional | Réplicas en hosts distintos que quieran un único contador sin disco/Redis compartido |
| Deuda de **cómputo / hang** viaja con el `.stok` si se copia *después* de fallar | Bloqueo de **copia limpia pre-ataque** |
| `sk` en `.stok.key` | HSM/KMS cableado al flujo; Android / Termux |
| Un master correcto siempre puede abrir (pagando el costo; ladder si hubo fallos) | “Destruir archivo tras N fallos” (**no**) |
| Hang de fase 3 best-effort + tope process-local de hangs concurrentes | Hang a prueba de ptrace; **límite multi-proceso/cluster** (no existe) |
| Binding v2 + MAC fail-closed + flock inode en open autenticado | **B1:** offline con `sk`+master+fuente salta la máquina oficial (dureza→Argon2); sin master no hay plaintext |

**Resumen:** el valor de producto es la **máquina de estados de trampa autónoma**
(file-borne en el `.stok`) + denegación opaca + PQ crypto; Argon2 endurece cada intento.
El FrictionStore compartido es solo refuerzo multi-host opcional.

Detalle en `THREAT_MODEL.md`. Historial en `CHANGELOG.md`.

## Estado del artefacto (honestidad operativa)

- Paquete instalable (`pip install -e ".[dev]"` o desde git `@v0.10.3`); CLI `smart-token`.
- SDK (`smart_token_prod.sdk`) + `smart-token integrate` para consumidores externos.
- Suite `tests/` y scripts bajo `scripts/` (replicas, flujo completo, costo de ataque).
- `deploy/` incluye compose Redis de ejemplo; HSM/`KeyProvider` existen como
  abstracción — **no** están cableados al path principal `protect`/`open`.
- **CI:** no hay workflow `.github/workflows/` en este repositorio todavía
  (una mención histórica en el CHANGELOG de v0.4.0 no implica que el archivo
  esté presente hoy).

## License

Source-available under the [Elastic License 2.0](LICENSE.txt). Not OSI open source: you may not provide the software to third parties as a hosted or managed service that exposes a substantial set of its features.
