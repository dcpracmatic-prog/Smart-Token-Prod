[![CI](https://github.com/dcpracmatic-prog/Smart-Token-Prod/actions/workflows/ci.yml/badge.svg)](https://github.com/dcpracmatic-prog/Smart-Token-Prod/actions/workflows/ci.yml)

# Smart Token Prod v0.10.5

**Protege archivos sensibles con crypto post-cuántica y una trampa lógica autónoma.**  
Cada `.stok` se defiende solo: ante fuerza bruta responde con denegación opaca, escalada de coste y, en fase avanzada, congelamiento del proceso atacante. No depende de red ni de configuración del operador.

Versión del paquete: **0.10.5** (`pyproject.toml` / `smart_token_prod.__version__`).  
Licencia: **Elastic License 2.0** (`LICENSE.txt`).

---

## Diferenciación

La mayoría de esquemas combinan cifrado + KDF (Argon2, scrypt…). Eso es commodity.  
Smart Token añade una **máquina de estados de fricción persistente** embebida en el propio archivo:

| Concepto | Comportamiento |
|----------|----------------|
| **Defensa autónoma (file-borne)** | `friction_snapshot` + `friction_mac` viajan dentro del `.stok`. El archivo se defiende solo. No requiere servicio externo ni configuración del operador. |
| **Denegación opaca** | Ante clave incorrecta el sistema no revela fase, `fail_count` ni `work_factor`. Se comporta como caja negra. |
| **Escalada 1 → 2 → 3** | Los fallos se acumulan y persisten. En fase 3 el proceso puede colgarse (hang) de forma bloqueante. |
| **Validation ladder** | Tras N fallos se exigen N+1 aciertos **consecutivos de la misma clave correcta** (tope 4). Cualquier clave incorrecta intermedia resetea el contador. |
| **Crypto PQ** | ML-KEM-768 (wrap) + AES-256-GCM (payload). Argon2id endurece cada intento; no es el diferenciador. |

El FrictionStore compartido (FileFrictionStore / Redis) es solo un **refuerzo opcional** para réplicas multi-host que quieran compartir el mismo contador. En el caso base no se necesita.

---

## Cómo funciona en la práctica

```text
1. protect
   Archivo + master  →  .stok (payload cifrado + friction_snapshot) + .stok.key

2. open con clave incorrecta
   → DENIED opaco
   → fail_count++ y posible escalada de fase (persistido en el .stok)
   → cada intento paga Argon2id + trabajo de trampa

3. Tras fail_count ≥ 3 (fase 3)
   → wrong master puede provocar hang bloqueante (el proceso no retorna)
   → el atacante debe matar el proceso; la deuda ya quedó escrita en el archivo

4. open con la clave correcta
   → cuenta hacia la ladder (N+1 aciertos consecutivos de ESA misma clave)
   → cualquier fallo intermedio resetea el contador de aciertos
   → al completar la ladder: OPEN + plaintext + reset de fricción
```

El archivo **nunca se destruye** por fallos. La penalización es coste operativo (tiempo, CPU, reinicios, orquestación), no borrado.

---

## Qué entrega esta versión

1. **ML-KEM-768** (pqcrypto) — wrap post-cuántico del secreto compartido  
2. **AES-256-GCM** — payload; clave = HKDF(ss, salt=Argon2id(master))  
3. **Binding v2** — `sk` sola no descifra; `.stok` v2 sin oráculo salt/material  
4. **Trampa lógica 1→2→3** — `fail_count` / flags / `recovery_tier` en `friction_snapshot`  
5. **Argon2id + trabajo de trampa** — en **cada** intento (correcto o incorrecto)  
6. **Denegaciones opacas** — CLI `open` y API por defecto no anuncian tier ni fail_count; dueño: `reveal_friction=True` o `status`  
7. **Phase 3 hang** — wrong master con `fail_count ≥ 3` → bucle bloqueante que no retorna  
8. **Validation ladder** — N+1 validaciones consecutivas de la misma clave correcta (tope 4); clave incorrecta intermedia resetea el contador  
9. **Defensa autónoma (file-borne)** — snapshot + MAC embebidos en el `.stok`; FrictionStore compartido solo como refuerzo multi-host opcional  
10. **Núcleo C++** — `libfriction.so` + FFI opcional (`auto` / `native` / `python`)  
11. **`sk` fuera de banda** — `.stok.key`  
12. **CLI** — `smart-token protect | open | status | demo | version | doctor | print-dep | integrate | repair-mac`

### Contrato de producto (resumen)

```text
Cada open() paga Argon2id + trabajo de trampa
  → master correcto  → cuenta hacia OPEN (ladder) + plaintext + reset friction
                       (incluso tras fail_count ≥ 3, cuando la ladder se completa)
  → master incorrecto → DENIED opaco + escalada de fase en el .stok
       si fail_count ≥ 3 → puede entrar en hang (no retorna; hay que matar el proceso)
```

- Differentiator = trampa lógica persistente + crypto PQ, no Argon2 solo.  
- El archivo nunca se destruye por fallos.  
- `status` es herramienta del dueño; `open`/API deny es opaco por defecto.  
- Integridad de fricción: `friction_mac` inválida → fail-closed (OPEN prohibido).  
- Garantía de trampa/ladder/hang aplica a la ruta autenticada oficial.  
  Reimplementación offline con `sk`+master+fuente reduce la dureza a Argon2 (límite B1 honesto).

---

## Uso rápido

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
# opcional: cd cpp && make all   # backend nativo

# Proteger
smart-token protect modelo.stl --master "mi-secreto"
# → modelo.stl.stok  +  modelo.stl.stok.key

# Intento fallido (DENIED opaco; no imprime fase ni fail_count)
smart-token open modelo.stl.stok --master "malo" --key modelo.stl.stok.key

# Correcto (respeta ladder si hubo fallos previos)
smart-token open modelo.stl.stok --master "mi-secreto" --key modelo.stl.stok.key -o out.stl

# Inspección (dueño)
smart-token status modelo.stl.stok
smart-token doctor
smart-token version
```

Códigos de salida de `open`: **0** = OPEN, **1** = DENIED (si retorna).  
Tras hang de fase 3 el proceso no sale solo; hay que matarlo.

Variables de entorno útiles:

| Variable | Descripción |
|----------|-------------|
| `SMART_TOKEN_MASTER` | Master por defecto (alternativa a `--master`) |
| `SMART_TOKEN_ARGON2_TIME` / `_MEM` / `_PARALLELISM` | Coste Argon2id |
| `SMART_TOKEN_PHASE3_HANG` | `1` (default) activa hang; `0`/`false`/`off` lo desactiva |
| `SMART_TOKEN_MAX_CONCURRENT_HANGS` | Tope process-local de hangs (default 2) |

---

## Integración en otro proyecto

En lugar de copiar a `vendor/`, instale el paquete y use el scaffolding:

```bash
pip install "smart-token-prod @ git+https://github.com/dcpracmatic-prog/Smart-Token-Prod.git@v0.10.5"
smart-token integrate /ruta/al/proyecto
```

También disponible en modo editable:

```bash
pip install -e ".[dev]"
```

Detalle de migración, API SDK y ejemplos: [`docs/INTEGRATION.md`](docs/INTEGRATION.md).

---

## Límites de esta versión (v0.10.5)

| Garantía | Fuera de alcance |
|----------|------------------|
| Confidencialidad ML-KEM + AES-GCM del payload | Canales laterales |
| Trap + fail_count **embebidos en el `.stok`** (file-borne; autónomo) + flock; FrictionStore compartido opcional | Réplicas en hosts distintos que quieran un único contador sin disco/Redis compartido |
| Deuda de cómputo / hang viaja con el `.stok` si se copia *después* de fallar | Bloqueo de copia limpia pre-ataque |
| `sk` en `.stok.key` | HSM/KMS cableado al flujo principal; Android / Termux |
| Un master correcto siempre puede abrir (pagando el costo; ladder si hubo fallos) | “Destruir archivo tras N fallos” (**no**) |
| Hang de fase 3 best-effort + tope process-local | Hang a prueba de ptrace; límite multi-proceso/cluster (no existe) |
| Binding v2 + MAC fail-closed + flock inode en open autenticado | **B1:** offline con `sk`+master+fuente puede omitir la máquina oficial (dureza → Argon2); sin master no hay plaintext |

**Resumen:** el valor de producto es la **máquina de estados de trampa autónoma** (file-borne en el `.stok`) + denegación opaca + crypto post-cuántica. Argon2 endurece cada intento. El FrictionStore compartido es solo refuerzo multi-host opcional.

Modelo de amenazas: [`THREAT_MODEL.md`](THREAT_MODEL.md).  
Historial de cambios: [`CHANGELOG.md`](CHANGELOG.md).  
Resultado de validación (Kaggle, 72/72 tests): [`RESULT.md`](RESULT.md).

---

## Estado del artefacto

- Paquete instalable (`pip install -e ".[dev]"` o desde git `@v0.10.5`); CLI `smart-token`.
- SDK (`smart_token_prod.sdk`) + `smart-token integrate` para consumidores externos.
- Suite `tests/` (72 tests) y scripts bajo `scripts/` (adversarial, flujo completo, costo de ataque).
- Backend nativo opcional (`cpp/libfriction.so`).
- `deploy/` incluye compose Redis de ejemplo; HSM/`KeyProvider` existen como abstracción y **no** están cableados al path principal `protect`/`open`.
- Validación externa (Kaggle): **PASS — PYTEST CLEAN + NATIVE + CLI + ADVERSARIAL**.

## License

Source-available under the [Elastic License 2.0](LICENSE.txt).  
Not OSI open source: you may not provide the software to third parties as a hosted or managed service that exposes a substantial set of its features.
