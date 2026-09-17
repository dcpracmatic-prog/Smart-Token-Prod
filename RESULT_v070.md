# RESULT — Smart Token Prod v0.7.0

**Path:** `/workspace/smart-token-prod`  
**Zone:** America/Mexico_City (CST)  
**Pytest:** **28 passed** in ~3.2s

## What changed (product direction)

- Differentiator restored: **persistent logical trap** phases 1→2→3 in
  `.stok` `friction_snapshot` (not an Argon2-only equalized race).
- Argon2id **hardens** every attempt inside that trap (commodity crypto).
- **Opaque denials**: CLI `open` deny prints only `DENIED` + time — no
  tier / fail_count / work_factor / coherence dump.
- **Phase-3 hang**: wrong master with `recovery_tier ≥ 3` persists
  castigated `.stok`, then enters non-returning Argon2 + keyed grind
  (+ fib flavor, non-oracle). Attacker must kill the process.
- Correct master at any tier (incl. ≥3): pay once → OPEN + reset.
- File never destroyed. Package version **0.7.0**.

## Key modules touched

| File | Change |
|------|--------|
| `smart_token_prod/recovery.py` | `phase3_blocking_grind`, hang gate, trap docs |
| `smart_token_prod/core.py` | hang after wrong @ tier≥3; opaque deny path |
| `smart_token_prod/stok.py` | persist castigated then hang; correct opens @ ≥3 |
| `smart_token_prod/cli.py` | opaque DENIED; demo hang-off helper; status inspect |
| `tests/test_smart_token_prod.py` | silent escalate, hang subprocess, opaque CLI |
| `README.md` / `CHANGELOG.md` / `pyproject.toml` | contract + 0.7.0 |

## Demo: silent hang vs correct open

```bash
cd /workspace/smart-token-prod

# Hang assert (subprocess still alive after ~2.5s, no success return):
.venv/bin/pytest tests/test_smart_token_prod.py::test_wrong_open_at_tier3_hangs_in_subprocess -v

# Correct open after tier 3:
.venv/bin/pytest tests/test_smart_token_prod.py::test_stok_one_correct_after_tier3_opens -v

# CLI opacity (no tier/fail_count on deny stdout):
.venv/bin/pytest tests/test_smart_token_prod.py::test_cli_denied_is_opaque -v

# Interactive demo (opaque denies; hang disabled inside demo helper):
.venv/bin/smart-token demo
```

Manual hang (after escalating a real `.stok` to tier≥3 with hang off, then):

```bash
# With hang ON (default), wrong open will not return — Ctrl-C / kill:
.venv/bin/smart-token open castigated.stok --master wrong --key castigated.stok.key
# Correct master still opens:
.venv/bin/smart-token open castigated.stok --master "$RIGHT" --key castigated.stok.key -o out.bin
```

## Pytest summary

```
28 passed in 3.21s
```

Command:

```bash
cd /workspace/smart-token-prod
.venv/bin/pytest tests/ -v
```
