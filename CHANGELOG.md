# Changelog

## v0.8.2 — FrictionStore compartido (réplicas)

- `FileFrictionStore` + `flock`: un fail_count por identidad en disco.
- `open_stok` toma lock exclusivo sobre `archivo.stok.lock` durante
  lectura/escritura; el hang de estado 3 ocurre *después* de soltar el lock
  para que otras réplicas vean el estado 3.
- `PersistentTarpit` rehidrata con `restore_snapshot` (no re-ejecuta fallos)
  y incrementa bajo `locked_update`.
- Comprobar: `scripts/validate_replicas.py` (3 procesos → fail_count=3).

## v0.8.1 — Validation ladder + no sandbox fallbacks

- After N failures, OPEN requires N+1 consecutive correct masters (cap 4).
- Partial correct validations stay DENIED (opaque).
- Removed FAKEKEM and PBKDF2 fallbacks; pqcrypto and argon2-cffi are required.
- Phase-3 hang stays ON by default.

## v0.8.0 — Binding ML-KEM ↔ master ↔ payload (design debt)

- AES-256 key is now `HKDF-SHA-256(ikm=ss, salt=master_km)` where `master_km`
  is the Argon2id + trap-iter output of the human secret. Possession of
  `.stok.key` (`sk`) is no longer sufficient to decrypt.
- `.stok` format v2: `kdf_params` persisted so protect/open share Argon2
  costs; `friction_mac` HMAC-SHA-256 over the snapshot (keyed by `ss`).
- `salt` / `material` are **not** written in v2 (removed offline master oracle).
- Coherence remains a public-view metric, not an authorization check.
- Tests: `test_wrong_master_cannot_decrypt_even_with_sk`,
  `test_v2_stok_has_no_offline_master_oracle`, `test_sk_alone_cannot_derive_aes_key`.
- Remaining (documented): a holder of `sk` can still re-MAC a reset snapshot
  and skip the official tarpit; they cannot obtain plaintext without master.

## v0.7.0 — Logical trap + Argon2 harden (opaque deny, phase-3 hang)

- **Product direction**: Argon2+AES alone is commodity; the **logical trap
  state machine** (phases 1→2→3 in `.stok` `friction_snapshot`) is the
  differentiator. Argon2id **hardens** that trap, does not replace it.
- Every open pays Argon2id (sane defaults) + trap keyed iters, bound to
  encryption material.
- **Opaque denials**: CLI/API deny path does **not** print tier, fail_count,
  work_factor, or rich error reasons.
- **Phase 3 hang**: wrong master with `recovery_tier ≥ 3` → non-returning
  Argon2 + keyed grind (+ optional fib flavor, non-oracle). Castigated
  `.stok` is persisted first; restart without replace re-enters trap.
- Correct master at any tier (incl. ≥3): pay once → OPEN + reset friction.
- File never destroyed. Fibonacci alone is **not** claimed hardness.
- Tests: silent phase escalation in snapshot; correct open after tier 3;
  subprocess hang assert; opaque CLI deny.

## v0.6.0 — Equalized Argon2id + 10k iters (jump @ 11k)

- **Equalized work**: every open pays **1× Argon2id** (time=2, mem=65536 KiB,
  parallelism=1) **plus exactly 10_000** keyed SHA-256 iterations — not multi-round
  Argon2 escalation and not `time_cost=10000`.
- Persist `cumulative_iters` in `friction_snapshot`. Tier jumps at 11k / 22k / 33k
  (max `recovery_tier` = 3). First fail stays tier 0; second crosses 11k → tier 1.
- Default `tarpit_mode=off` (Fibonacci wall-clock burn disabled). Fib flags remain
  as legacy labels only. File is never destroyed.
- `work_factor` kept as legacy label (=1 under equalized pay).

## v0.5.0 — Argon2id work-factor ratchet (2/3/4×)

- **Work-factor ratchet**: fallos 1/2/3+ escalan `recovery_tier` y
  `work_factor` a 2/3/4 **rondas internas Argon2id** (no reingresos de password).
- **Cada** `open` (correcto o incorrecto) paga el work_factor actual **antes**
  de devolver OPEN/DENIED. Un master correcto abre en un solo intento y
  resetea fricción.
- Campos en `friction_snapshot`: `recovery_tier`, `work_factor`, `stok_id`
  (aditivos; ausentes ⇒ defaults). `recovery_debt` / `AUTH_PARTIAL` de
  multi-keystroke **cancelados**.
- El archivo **nunca se destruye** por fallos.
- Dependencia `argon2-cffi`. Tarpit nativo/Python queda opcional; Fibonacci
  no es la narrativa de dureza.
- CLI: `protect` / `open` / `status` / `demo`; exit 0=OPEN, 1=DENIED.
- README: límites honestos (copia limpia pre-ataque, multi-instancia,
  sin Android/Termux).
- Tests: OPEN, DENIED + escalada, un correcto tras escalada, persistencia
  across reopen, sin AUTH_PARTIAL.

## v0.4.2 — sk fuera de banda; límites contractuales en README

- La clave secreta ML-KEM (`sk`) **ya no se escribe dentro del `.stok`**.
  Se entrega en archivo hermano `.stok.key` (formato `STKEY`).
- `protect_file` devuelve `(stok_path, key_path)`.
- `open_stok` exige `sk` / `--key` / `.stok.key` (compatibilidad con `.stok`
  legados que aún embebían `sk`).
- Sin la clave, el intento falla y se registra fricción.
- `README.md` define el **contrato y los límites de esta versión** de forma
  explícita (tabla de garantías vs. fuera de alcance). No son notas de
  mejora futura: son el borde del producto en v0.4.2.

## v0.4.1 — Capa de archivo .stok y CLI

- **Capa de archivo `.stok`** (`smart_token_prod/stok.py`): serializa el token
  (payload cifrado + material público/privado de prototipo + snapshot de
  fricción) a un archivo binario con cabecera mágica. La máquina de estados
  de fricción sobrevive reinicios y es visible sobre un archivo real
  (STL, ZIP, etc.), no solo sobre un objeto Python en memoria.
- **CLI** (`smart-token`): subcomandos `protect`, `open`, `status` y `demo`.
  - `protect archivo.stl` → genera `archivo.stl.stok`
  - `open archivo.stl.stok` → simula intento legítimo o rechazado; actualiza
    el snapshot de fricción en el propio archivo
  - `demo` → protege un STL de muestra, apertura legítima, luego 4 intentos
    de fuerza bruta mostrando degradación temporal y persistencia de
    `fail_count` / flags / tarpit
- Entry point `smart-token` registrado en `pyproject.toml`.

## v0.4.0 — Endurecimiento hacia viabilidad comercial

- **Fix de paridad Python↔C++**: `fib_seed` en el núcleo nativo solo usaba
  el primer byte de la clave base; ahora usa los mismos 2 bytes big-endian
  que Python. Detectado por la nueva suite de pruebas — antes de esto,
  ambos backends podían producir mutaciones de clave *distintas* para el
  mismo secreto, lo cual habría sido un problema serio si un cliente
  auditaba el sistema.
- Suite de pruebas automatizadas (`tests/`, pytest) cubriendo ciclo de
  vida del token, paridad de backends, persistencia y gestión de claves.
- `smart_token_prod/persistence.py`: abstracción de persistencia del
  estado de fricción (`FrictionStore`), con backend en memoria y shape
  lista para Redis (no probado contra Redis real — requiere infra propia).
- `smart_token_prod/keymgmt.py`: abstracción de gestión de claves
  (`KeyProvider`), con backend en memoria y contrato explícito para un
  futuro HSM/KMS (no implementado — requiere decisión de proveedor propia).
- `THREAT_MODEL.md`: modelo de amenazas explícito, incluyendo qué el
  sistema NO protege.
- `benchmarks/bench_tarpit_concurrency.py`: medido que el backend Python
  degrada ~2.2x bajo 8 tarpits concurrentes por el GIL; el backend nativo
  ~1.2x. Ninguno tiene límite de concurrencia — pendiente.
- Empaquetado como paquete instalable (`pyproject.toml`), con `pip install -e .`
  funcional.
- CI (`.github/workflows/ci.yml`) escrito y listo — no ejecutado aquí
  porque requiere un repositorio real en GitHub.

## v0.3.0-aes-gcm

- AES-256-GCM reemplaza XOR para el cifrado del payload.
- Núcleo C++ (`libfriction.so`) compilado por primera vez, sin FFI expuesta.

## v0.3.1 (dentro de esta sesión, previo a v0.4.0)

- API C plana (`extern "C"`) sobre `SequentialTarpit` y `coherence_metric`.
- `smart_token_prod/native.py`: binding `ctypes` completo, con fallback
  automático a Python si `libfriction.so` no está disponible.
- Parámetro `friction_backend` en `SmartTokenProd` (`"auto"|"native"|"python"`).
