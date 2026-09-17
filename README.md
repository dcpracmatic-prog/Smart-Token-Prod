# Smart Token Prod v0.8.0

Token post-cuántico (ML-KEM-768 + AES-256-GCM) cuya **diferenciación** es la
**trampa lógica secuencial persistente** (fases 1 → 2 → 3 en `.stok`),
endurecida con Argon2id. Argon2+AES solos son commodity (“pan y leche”);
aquí Argon2 **endurece la trampa**, no la reemplaza.

## Qué entrega esta versión

1. **ML-KEM-768** (pqcrypto) — wrap post-cuántico del secreto compartido
2. **AES-256-GCM** — payload; clave = HKDF(ss, salt=Argon2id(master))
3. **Binding v2** — `sk` sola no descifra; `.stok` v2 sin oráculo salt/material
4. **Trampa lógica 1→2→3** — `fail_count` / flags / `recovery_tier` en `friction_snapshot`
5. **Argon2id + trabajo de trampa** — en **cada** intento (correcto o incorrecto)
6. **Denegaciones opacas** — CLI/API de deny **no** anuncian tier, fail_count ni work_factor
7. **Phase 3 hang** — wrong master con `recovery_tier ≥ 3` → bucle bloqueante que **no retorna**
8. **Núcleo C++** — `libfriction.so` + FFI opcional (`auto`/`native`/`python`)
9. **`sk` fuera de banda** — `.stok.key`
10. **CLI** — `smart-token protect | open | status | demo`

## Contrato de producto (v0.7.0)

```text
Cada open() paga Argon2id + trabajo de trampa (bound a material de cifrado)
  → master correcto  → OPEN + plaintext + reset friction (incluso si tier≥3)
  → master incorrecto → DENIED opaco + escalate fase en .stok
       si recovery_tier ≥ 3 → entra grind Argon2+iters (+fib flavor) y NO RETORNA
       (atacante debe matar el proceso; .stok castigado ya persistió)

Fases (snapshot; no se imprimen en deny):
  fail 1 → fase 1 (flag_fibonacci)
  fail 2 → fase 2 (flag_persistencia)
  fail 3+ → fase 3 (tarpit_triggered); tier salta @11k/22k/33k cum iters (máx 3)
```

- Differentiator = **trampa lógica persistente + crypto PQ**, no Argon2 solo.
- Fibonacci dentro del grind de fase 3 es **sabor narrativo / non-oracle**,
  **no** dureza criptográfica por sí sola.
- El archivo **nunca se destruye** por fallos.
- `status` inspecciona el snapshot (herramienta del dueño); **open** deny es opaco.

## Uso rápido

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
# opcional: cd cpp && make all

smart-token protect modelo.stl --master "mi-secreto"
# → modelo.stl.stok  +  modelo.stl.stok.key

# Deny opaco (sin imprimir tier). Tras phase 3 + wrong: el proceso puede colgarse.
smart-token open modelo.stl.stok --master "malo" --key modelo.stl.stok.key

# Correcto incluso tras castigo → OPEN + reset
smart-token open modelo.stl.stok --master "mi-secreto" --key modelo.stl.stok.key -o out.stl

smart-token status modelo.stl.stok   # inspección interna del snapshot
smart-token demo
```

Códigos de salida `open`: **0** = OPEN, **1** = DENIED (si retorna).
Tras hang de fase 3 el proceso no sale solo — hay que matarlo.

Env: `SMART_TOKEN_ARGON2_TIME`, `SMART_TOKEN_ARGON2_MEM` (KiB),
`SMART_TOKEN_ARGON2_PARALLELISM`. Hang de fase 3: `SMART_TOKEN_PHASE3_HANG`
(default `1`; `0`/`false`/`off` lo desactiva). Tests también usan el
override `_phase3_hang=False` en `open` / `open_stok`.

## Demo: hang silencioso vs open correcto

```bash
# 1) Proteger y fallar hasta tier 3 (hang OFF solo en tests; en prod hang ON)
smart-token demo   # demo desactiva hang vía _phase3_hang   # demo desactiva hang internamente

# 2) Castigar a tier≥3, luego wrong open con hang (proceso no retorna ~segundos)
#    Ver test_wrong_open_at_tier3_hangs_in_subprocess — subprocess + timeout.

# 3) Mismo .stok castigado + master correcto → OPEN + reset friction
```

## Límites de esta versión (v0.7.0)

| Garantía | Fuera de alcance |
|----------|------------------|
| Confidencialidad ML-KEM + AES-GCM del payload | Canales laterales |
| Trap + fail_count compartidos en el `.stok` (flock) y en `FileFrictionStore` | Réplicas en hosts distintos sin disco/Redis compartido |
| Deuda de **cómputo / hang** viaja con el `.stok` si se copia *después* de fallar | Bloqueo de **copia limpia pre-ataque** |
| `sk` en `.stok.key` | HSM/KMS; Android / Termux |
| Un master correcto siempre puede abrir (pagando el costo una vez) | “Destruir archivo tras N fallos” (**no**) |
| Hang de fase 3 es best-effort en-proceso (kill = salida) | Hang a prueba de ptrace / OS scheduler abuse |

**Resumen:** el valor de producto es la **máquina de estados de trampa**
persistente + PQ crypto; Argon2 es el endurecimiento commodity de cada intento.

Detalle en `THREAT_MODEL.md`.

## License

Source-available under the [Elastic License 2.0](LICENSE.txt). Not OSI open source: you may not provide the software to third parties as a hosted or managed service that exposes a substantial set of its features.
