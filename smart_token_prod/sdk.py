"""
High-level public API for host projects (e.g. ATL Edge wrappers).

Mirrors a thin long-lived protection façade without requiring PYTHONPATH=vendor.
Uses existing stok / native APIs; does not invent crypto behaviour.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

PathLike = Union[str, Path]
MasterSecret = Union[str, bytes]


def _encode_master(master_secret: MasterSecret) -> bytes:
    if isinstance(master_secret, str):
        return master_secret.encode("utf-8")
    if isinstance(master_secret, bytes):
        return master_secret
    raise TypeError("master_secret must be str or bytes")


def _require_stack() -> None:
    """Raise RuntimeError if the crypto stack cannot be imported."""
    missing = []
    try:
        import pqcrypto  # noqa: F401
    except Exception as exc:  # pragma: no cover - env dependent
        missing.append(f"pqcrypto ({exc})")
    try:
        import cryptography  # noqa: F401
    except Exception as exc:  # pragma: no cover
        missing.append(f"cryptography ({exc})")
    try:
        import argon2  # noqa: F401
    except Exception as exc:  # pragma: no cover
        missing.append(f"argon2 ({exc})")
    if missing:
        raise RuntimeError(
            "Smart Token Prod stack unavailable — missing/broken deps: "
            + ", ".join(missing)
            + ". Install with: pip install 'smart-token-prod @ "
            "git+https://github.com/dcpracmatic-prog/Smart-Token-Prod.git@v0.10.4'"
        )


def is_available() -> bool:
    """True if the Python crypto stack imports; native C++ friction is optional."""
    try:
        _require_stack()
        from . import stok  # noqa: F401

        return True
    except Exception:
        return False


def status() -> Dict[str, Any]:
    """Package / environment status for doctor and host health checks."""
    from . import __version__

    import_error: Optional[str] = None
    try:
        _require_stack()
    except RuntimeError as exc:
        import_error = str(exc)

    native_friction = False
    try:
        from . import native as _native

        native_friction = bool(_native.is_available())
    except Exception as exc:  # pragma: no cover
        if import_error is None:
            import_error = f"native import: {exc}"

    return {
        "version": __version__,
        "native_friction": native_friction,
        "import_error": import_error,
        "role": "sdk",
        "available": import_error is None,
    }


def protect_artifact(
    input_path: PathLike,
    *,
    master_secret: MasterSecret,
    output_path: PathLike | None = None,
    key_path: PathLike | None = None,
    tarpit_mode: str = "off",
    tarpit_seconds: float = 0.0,
    friction_backend: str = "auto",
    **kwargs: Any,
) -> Tuple[Path, Path]:
    """
    Protect a file → (.stok, .stok.key).

    Accepts str or bytes master_secret (str encoded as UTF-8).
    Extra kwargs are forwarded to protect_file.
    """
    _require_stack()
    from .stok import protect_file

    return protect_file(
        input_path,
        output_path=output_path,
        master_secret=_encode_master(master_secret),
        tarpit_mode=tarpit_mode,
        tarpit_seconds=tarpit_seconds,
        friction_backend=friction_backend,
        key_path=key_path,
        **kwargs,
    )


def open_artifact(
    path: PathLike,
    *,
    master_secret: MasterSecret,
    key_path: PathLike | None = None,
    sk: Optional[bytes] = None,
    output_path: PathLike | None = None,
    force_failure: bool = False,
    update_friction: bool = True,
    reveal_friction: bool = False,
    **kwargs: Any,
) -> Tuple[Optional[bytes], Dict[str, Any]]:
    """
    Attempt to open a .stok artifact (product surface).

    DENIED info is opaque by default (no fail_count / tier / friction_state).
    Pass reveal_friction=True for owner inspection of ladder/debt.
    Returns (plaintext_or_None, info) same as open_stok.
    """
    _require_stack()
    from .stok import open_stok

    return open_stok(
        path,
        master_secret=_encode_master(master_secret),
        sk=sk,
        key_path=key_path,
        force_failure=force_failure,
        output_path=output_path,
        update_friction=update_friction,
        reveal_friction=reveal_friction,
        **kwargs,
    )


def artifact_friction_status(path: PathLike) -> Dict[str, Any]:
    """Owner inspection of friction_snapshot for a .stok path."""
    _require_stack()
    from .stok import friction_status

    return friction_status(path)


def repair_artifact_mac(
    path: PathLike,
    *,
    key_path: PathLike | None = None,
    sk: Optional[bytes] = None,
) -> Dict[str, Any]:
    """Owner: re-MAC friction_snapshot after tamper/bitrot. Debt preserved."""
    _require_stack()
    from .stok import repair_friction_mac

    return repair_friction_mac(path, sk=sk, key_path=key_path)

