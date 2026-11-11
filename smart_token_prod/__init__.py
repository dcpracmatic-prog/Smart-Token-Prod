"""Smart Token Prod — API pública (carga perezosa).

El stack cripto pesado (numpy, cryptography, pqcrypto) solo se importa
cuando un nombre público se usa de verdad. Antes, importar el paquete —
por ejemplo, al arrancar `smart-token version` — pagaba ~0,17 s de
imports cripto que ese comando no necesita. `__version__` sigue siendo
una constante normal y siempre es barata.

La API no cambia: los mismos nombres, el mismo `__all__`, los mismos
módulos de origen. La carga perezosa usa PEP 562 (`__getattr__` a nivel
de módulo) y cada nombre se cachea en `globals()` tras el primer uso.
Los submódulos (`smart_token_prod.stok`, `.core`, ...) se siguen
importando directamente, como antes.
"""

from __future__ import annotations

__version__ = "0.10.5"

__all__ = [
    "SmartTokenProd",
    "PublicView",
    "SequentialTarpit",
    "governance_fingerprint",
    "protect_file",
    "open_stok",
    "read_stok",
    "write_stok",
    "friction_status",
    "repair_friction_mac",
    "StokFile",
    "CorruptStokError",
    "FrictionStore",
    "FileFrictionStore",
    "InMemoryFrictionStore",
    "PersistentTarpit",
    "is_available",
    "status",
    "protect_artifact",
    "open_artifact",
    "artifact_friction_status",
    "repair_artifact_mac",
    "__version__",
]

# nombre público -> (módulo, atributo). Los módulos pesados (core, stok)
# arrastran numpy + cryptography + pqcrypto; no se tocan hasta que se
# pide uno de sus nombres.
_LAZY_ATTRS = {
    "SmartTokenProd": ("smart_token_prod.core", "SmartTokenProd"),
    "PublicView": ("smart_token_prod.core", "PublicView"),
    "SequentialTarpit": ("smart_token_prod.core", "SequentialTarpit"),
    "governance_fingerprint": ("smart_token_prod.core", "governance_fingerprint"),
    "protect_file": ("smart_token_prod.stok", "protect_file"),
    "open_stok": ("smart_token_prod.stok", "open_stok"),
    "read_stok": ("smart_token_prod.stok", "read_stok"),
    "write_stok": ("smart_token_prod.stok", "write_stok"),
    "friction_status": ("smart_token_prod.stok", "friction_status"),
    "repair_friction_mac": ("smart_token_prod.stok", "repair_friction_mac"),
    "StokFile": ("smart_token_prod.stok", "StokFile"),
    "CorruptStokError": ("smart_token_prod.stok", "CorruptStokError"),
    "FrictionStore": ("smart_token_prod.persistence", "FrictionStore"),
    "FileFrictionStore": ("smart_token_prod.persistence", "FileFrictionStore"),
    "InMemoryFrictionStore": ("smart_token_prod.persistence", "InMemoryFrictionStore"),
    "PersistentTarpit": ("smart_token_prod.persistence", "PersistentTarpit"),
    "is_available": ("smart_token_prod.sdk", "is_available"),
    "status": ("smart_token_prod.sdk", "status"),
    "protect_artifact": ("smart_token_prod.sdk", "protect_artifact"),
    "open_artifact": ("smart_token_prod.sdk", "open_artifact"),
    "artifact_friction_status": ("smart_token_prod.sdk", "artifact_friction_status"),
    "repair_artifact_mac": ("smart_token_prod.sdk", "repair_artifact_mac"),
}


def __getattr__(name: str):
    """PEP 562: importa el nombre público bajo demanda y lo cachea."""
    try:
        module_name, attr = _LAZY_ATTRS[name]
    except KeyError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None
    import importlib

    module = importlib.import_module(module_name)
    value = getattr(module, attr)
    globals()[name] = value
    return value


def __dir__():
    return sorted(set(globals()) | set(__all__))
