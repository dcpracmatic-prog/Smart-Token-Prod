# Integrar Smart Token Prod como componente

## El problema del vendoring

Copiar el árbol a `vendor/smart_token_prod/` (o fijarlo con
`PYTHONPATH=vendor:.`) hace que el consumidor se quede en una versión
antigua mientras el paquete upstream avanza (binding v2, ladder,
FrictionStore compartido, SDK, etc.). Cada mejora hay que re-copiar a
mano; los forks divergen y los bugs de crypto/fricción no se
sincronizan.

**Solución:** instalar Smart Token Prod como dependencia pip (git o
editable) y usar la API pública / CLI `smart-token integrate`.

## Instalación

### Desde git (recomendado en CI / otros repos)

```bash
pip install "smart-token-prod @ git+https://github.com/dcpracmatic-prog/Smart-Token-Prod.git@v0.10.0"
```

O imprime la línea con:

```bash
smart-token print-dep
```

### Editable (desarrollo local)

```bash
pip install -e /ruta/a/Smart-Token-Prod
# equivalente:
smart-token print-dep --editable /ruta/a/Smart-Token-Prod
```

## Scaffolding con la CLI

Desde un entorno donde ya esté instalado este paquete:

```bash
smart-token integrate /ruta/al/proyecto
# plan sin escribir:
smart-token integrate /ruta/al/proyecto --dry-run
# bridge en otra ruta + dep editable:
smart-token integrate /ruta/al/proyecto --bridge src/smart_token_bridge.py \
  --editable /ruta/a/Smart-Token-Prod
```

Qué escribe (dentro del proyecto destino únicamente):

| Artefacto | Rol |
|-----------|-----|
| `smart_token_bridge.py` (o `--bridge`) | Re-exporta `smart_token_prod.sdk` |
| `requirements.txt` (append) o `requirements-smart-token.txt` | Línea de dependencia |
| `INTEGRATION.smart-token.md` | Pasos para quitar vendor / PYTHONPATH |
| `INTEGRATION.generated.md` | Solo si hay `pyproject.toml` sin `requirements.txt` (no se reescribe TOML a ciegas) |

Comprobar el entorno:

```bash
smart-token doctor
smart-token version
```

## Uso en biblioteca

### API de alto nivel (SDK)

```python
from smart_token_prod.sdk import (
    is_available,
    status,
    protect_artifact,
    open_artifact,
    artifact_friction_status,
)

assert is_available()
print(status())  # version, native_friction, import_error, role

stok, key = protect_artifact("modelo.stl", master_secret="mi-secreto")
pt, info = open_artifact(stok, master_secret="mi-secreto", key_path=key)
print(info["status"])  # OPEN | DENIED
print(artifact_friction_status(stok))
```

`master_secret` acepta `str` (UTF-8) o `bytes`. Si el stack crypto no
está disponible, las funciones del SDK lanzan `RuntimeError` con un
mensaje claro.

Desde el bridge generado:

```python
from smart_token_bridge import protect_artifact, open_artifact, status
```

### API de bajo nivel (inchangada)

```python
from smart_token_prod import (
    protect_file,
    open_stok,
    friction_status,
    SmartTokenProd,
    __version__,
)
from smart_token_prod.native import is_available as native_available
```

CLI: `protect`/`open` exigen `--master` o `SMART_TOKEN_MASTER`. API DENIED opaca por defecto (`reveal_friction`). Hang de fase 3: `fail_count >= 3`.

## Checklist de migración (fuera de vendor/)

1. Instalar la dependencia (git o editable) en el venv del proyecto.
2. Ejecutar `smart-token integrate <proyecto>` (o crear el bridge a mano).
3. Sustituir imports que dependían de `PYTHONPATH=vendor` por el bridge
   o por `smart_token_prod.sdk`.
4. Eliminar `vendor/smart_token_prod/` del árbol y del VCS.
5. Quitar `PYTHONPATH=vendor:.` (o fragmentos equivalentes) **solo**
   usados para STP.
6. `smart-token doctor` y una smoke de protect/open en un archivo de prueba.
7. Actualizar CI para `pip install` la dep (tag `@v0.10.0` o editable en
   monorepo local).

## Límites (honestidad)

- No inventa features crypto nuevas: envuelve `protect_file` /
  `open_stok` / `friction_status`.
- El núcleo C++ (`libfriction.so`) sigue siendo **opcional**.
- Licencia: Elastic License 2.0 (source-available; no OSI open source).

Más detalle de producto: `README.md`, `THREAT_MODEL.md`, `CHANGELOG.md`.
