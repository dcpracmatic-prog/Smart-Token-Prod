# Resultado de validación — Smart Token Prod v0.10.5

> **Corrección 2026-11-11 (no se borra el registro original, que sigue abajo intacto):**
> el re-conteo independiente en este mismo checkout (commit `7dcd6eb`,
> `pytest tests/ --collect-only`: **71 tests**; por archivo 6 + 11 + 7 + 47;
> segunda definición: 63 funciones `def test` + 8 expansiones parametrizadas = 71)
> **no reproduce el 72** que se afirma abajo. `tests/` no cambió desde esta
> validación (el commit `db677d2` del 2026-09-25 solo tocó 4 líneas de
> aserciones de versión), así que el 72 no se explica por un test eliminado;
> queda como cifra **no reproducida** de la corrida Kaggle 2026-09-25. Tras el
> parche del `.stok` corrupto (DENIED opaco, ver CHANGELOG "Unreleased") la
> suite es de **73 tests** (71 + 2 nuevos de regresión).

**Fecha de validación:** 2026-09-25  
**Entorno:** Kaggle (Python 3.12.13, Linux x86_64)  
**Artefacto validado:** `Smart-Token-Prod-v0.10.5-final` (copia escribible + parche de aserciones de versión 0.10.4 → 0.10.5 en tests)

## Veredicto

```
PASS — PYTEST CLEAN + NATIVE + CLI + ADVERSARIAL
```

| Check                    | Resultado |
|--------------------------|-----------|
| pytest_clean             | PASS      |
| native_backend_loads     | PASS      |
| cli_smoke                | PASS      |
| adversarial_clean        | PASS      |
| native_python_parity     | PASS      |

## Suite pytest

- **72 tests ejecutados**
- **72 passed**
- **0 failed**
- Tiempo ≈ 9.76 s

Los dos únicos tests que fallaban en versiones anteriores de los tests (aserciones hardcodeadas a `"0.10.4"`) fueron corregidos para esperar `"0.10.5"`. Tras el ajuste, la suite completa queda limpia.

## Componentes verificados

- Instalación editable (`pip install -e ".[dev]"`) desde directorio escribible
- Dependencias críticas: `pqcrypto`, `cryptography`, `numpy`, `argon2-cffi`, `pytest`
- Backend nativo: `cpp/libfriction.so` compilado y cargable (`native: OK`)
- CLI: `version`, `doctor`, `protect`, `status`, `open` (round-trip + rechazo de secreto incorrecto), `integrate --dry-run`
- Batería adversarial:
  - `scripts/adversarial_a1_mac_tamper.py` → exit 0
  - `scripts/adversarial_r1_inode_replace.py` → exit 0
  - `scripts/adversarial_r2_inmemory_oracle.py` → exit 0
  - `scripts/validate_full_flow.py` → exit 0
- Paridad Python/C++: 7/7 tests passed

## Notas de diseño confirmadas en la validación

1. **Defensa autónoma (file-borne)**  
   El `friction_snapshot` y el `friction_mac` viven embebidos en el propio `.stok`.  
   El FrictionStore compartido (FileFrictionStore / Redis) es refuerzo **opcional** para el escenario multi-host.  
   En el caso base (un archivo defendiéndose solo) no se requiere configuración del operador ni red.

2. **Validation ladder con memoria cruzada**  
   Cualquier clave incorrecta intermedia resetea el contador de aciertos consecutivos.  
   Solo la *misma* clave correcta repetida de forma consecutiva cuenta hacia el OPEN.  
   Tras fase 3 (hang), se exigen hasta 4 validaciones consecutivas correctas de esa misma clave.

3. **Denegación opaca**  
   Por defecto, `open` / API no revelan tier, fail_count ni work_factor.  
   La inspección detallada queda reservada a `status` / `reveal_friction=True` (dueño).

## Artefactos generados durante la validación

- `/kaggle/working/smart_token_v0.10.5_validation_summary.json`
- `/kaggle/working/pytest_full_log.txt` (72 passed)

## Conclusión

El release **v0.10.5** se considera **técnicamente limpio** en el entorno de validación descrito.  
La implementación es coherente con el modelo de amenaza y con el contrato de producto documentado en `README.md` y `THREAT_MODEL.md`.
