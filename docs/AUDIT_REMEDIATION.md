# Remediación de auditoría — Smart Token Prod v0.10.1

Documento en español. Resume qué fallaba en la narrativa vs. el código,
qué cambió en **0.10.0**, cómo la evidencia respalda el contrato, y el
límite residual **B1** (honesto).

## Qué estaba mal (tesis rota)

### A1 — MAC de fricción fail-open (crítico)

El `.stok` lleva `friction_mac` (HMAC sobre el snapshot, keyed por `ss`)
para que la trampa persistente no se pueda borrar a mano. En la práctica,
si el MAC **no coincidía**, el código hacía:

```text
friction_mac inválido → friction_snapshot = {} → deuda borrada
```

Un atacante **sin** `sk` podía:

1. Provocar N opens incorrectos (trampa / ladder activos en disco).
2. Bit-flip de `friction_mac` en el archivo.
3. Presentar el master correcto → el path oficial aceptaba snapshot
   "fresco" y hacía **OPEN** + reset, **saltándose** la trampa.

Eso contradecía el claim de trampa file-borne persistente.

Además, `open` **sin** `sk` aún escribía un snapshot nuevo **sin** poder
re-MAC → dejaba MAC viejo + estado nuevo (corrupción) o borraba castigo
para el siguiente open con clave.

### A2 — API no opaca (claim de producto mentía)

El README/CHANGELOG afirmaban denegaciones opacas en CLI/**API**, pero
`open_stok` devolvía `friction_state` con `fail_count`, `recovery_tier`,
`work_factor`, etc. Solo la CLI `open` ocultaba eso en stdout. Un
integrador vía SDK obtenía un oráculo de ladder.

### D1 / D2 / D3 — footguns

- **D1:** `protect`/`open` caían en `demo-master-secret` si faltaba
  `--master` / env.
- **D2:** `integrate --bridge` aceptaba rutas con `..` o absolutas fuera
  del proyecto.
- **D3:** docs hablaban de hang con `recovery_tier ≥ 3`; el código cuelga
  con **`fail_count ≥ 3`** (fase 3). Tras el 3.er fallo el tier puede
  seguir en 2.

## Qué cambió en 0.10.0 (diseño lógico intacto)

Se **conservan** fases 1→2→3, trampa persistente, ladder, hang-after-persist,
binding v2, AES-GCM, ML-KEM, archivo nunca destruido.

| Ítem | Cambio |
|------|--------|
| A1 | MAC inválido/ausente (v2) → fail-closed: OPEN prohibido; **no** `{}`; disco intacto |
| A1 | Sin `sk`/`ss` → DENY solo-lectura (no muta friction) |
| A1 | MAC válido → escalate/ladder/hang igual que antes |
| A2 | `reveal_friction=False` por defecto en `open_stok` / `open_artifact` |
| D1 | CLI exige master; solo `demo` usa default con WARNING |
| D2 | Bridge resuelto bajo root del proyecto |
| D3 | Docs alineados a `fail_count >= 3` |

## Cómo la narrativa queda respaldada con evidencia

```bash
pytest -q
# Incluye:
#   test_a1_mac_tamper_does_not_grant_free_open
#   test_a1_open_without_key_does_not_erase_trap
#   test_api_denied_is_opaque_by_default
#   test_cli_protect_open_require_master
#   test_integrate_rejects_bridge_escape
#   + suite previa de fases / ladder / hang / binding v2
```

Script adversarial (repro del ataque A1 antiguo → debe fail-closed):

```bash
python scripts/adversarial_a1_mac_tamper.py
```

Contrato actualizado: `README.md` (sección Contrato), `THREAT_MODEL.md`,
este archivo.

## Límite residual B1 (honesto)

No se puede impedir que alguien con **`sk` + master + código fuente**
llame primitivas crypto offline (decaps + Argon2 + AES-GCM) y se salte la
máquina de estados oficial. Eso reduce la dureza offline a **Argon2
work-factor** (commodity).

Lo que **sí** garantiza el producto:

1. La superficie soportada es `protect_file` / `open_stok` /
   `sdk.protect_artifact` / `sdk.open_artifact`.
2. En esa ruta, con `friction_mac` integrity-checked, la trampa **viaja
   con el `.stok`** y resiste manipulación del archivo **sin** `sk`
   (A1 fail-closed).
3. Sin master no hay plaintext (binding v2), aunque se resetee friction
   offline con `sk`.

Funciones de bajo nivel (`SmartTokenProd`, `mlkem_decaps`, etc.) siguen
disponibles como building blocks internos; los claims de producto se
atan a la ruta autenticada anterior.

## Resumen

0.10.0 no es greenwashing: cierra el bypass A1, hace opaca la API como
se anunciaba, elimina footguns D1/D2, alinea hang (D3), y admite B1 sin
vaciar fases/ladder/hang.


## Cycle 1 adversarial (v0.10.1)

Hallazgos bajo ataque hostil tras 0.10.0:

| ID | Severidad | Estado |
|----|-----------|--------|
| S1 store≻disk MAC DoS | P0 | FIXED — MAC sobre disk_snap; merge después |
| S2 sidecar lock unlink | P0 | FIXED — flock inode `.stok` |
| S3 MAC tamper owner DoS | P1 | FIXED — `repair_friction_mac` / CLI `repair-mac` |
| S4 sdk pin v0.9.0 | P2 | FIXED → v0.10.1 |
| S5 integrate CLI traceback | P2 | FIXED — catch ValueError |
| A1/A2/D1/D2 | — | HOLD bajo re-ataque |
| B1 offline sk+master+fuente | residual | NO eliminable sin rediseño |

