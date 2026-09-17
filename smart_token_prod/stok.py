"""
Capa de archivo .stok — serialización del token protegido a disco.

Permite que la máquina de estados de fricción (fail_count, flags, tarpit)
sobreviva reinicios de proceso y sea observable sobre un archivo real
(p. ej. un CAD/STL embebido), no solo sobre un objeto Python en memoria.

Formato (v1):
  - Cabecera mágica: b"STOK" (4) + version u8 (1)
  - Longitud del bloque JSON (u32 big-endian)
  - Bloque JSON (metadatos + blobs en base64)

Por defecto la clave secreta ML-KEM (sk) NO se escribe en el .stok.
Se entrega en un archivo hermano `.stok.key` (o se suministra en open
vía parámetro / KeyProvider). Así el archivo protegido no contiene
material que permita decapsular sin la clave de custodia.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .core import (
    SmartTokenProd,
    make_tarpit,
    coherence_metric,
    derive_aes_key,
    aes_gcm_decrypt,
    mlkem_decaps,
)
from .recovery import (
    apply_failure_to_snapshot,
    clear_friction_fields,
    compute_stok_id,
    pay_work_factor,
    work_factor_for_tier,
    phase3_hang_enabled,
    phase3_blocking_grind,
    MAX_TIER,
)

MAGIC = b"STOK"
VERSION = 1
KEY_MAGIC = b"STKEY"
KEY_VERSION = 1


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


@dataclass
class StokFile:
    """Representación en memoria de un archivo .stok."""

    governance_outcomes: List[int]
    public_label: bytes
    epsilon: float
    pk: bytes
    ct: bytes
    nonce: bytes
    ciphertext: bytes
    salt: bytes
    material: bytes
    target_coherence: float
    aad: bytes
    friction_snapshot: Dict[str, Any] = field(default_factory=dict)
    tarpit_mode: str = "off"
    tarpit_seconds: float = 0.0
    friction_backend: str = "auto"
    # sk solo presente si se cargó desde un .stok legado o se inyectó en memoria
    sk: Optional[bytes] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "version": VERSION,
            "governance_outcomes": self.governance_outcomes,
            "public_label": _b64(self.public_label),
            "epsilon": self.epsilon,
            "pk": _b64(self.pk),
            "ct": _b64(self.ct),
            "nonce": _b64(self.nonce),
            "ciphertext": _b64(self.ciphertext),
            "salt": _b64(self.salt),
            "material": _b64(self.material),
            "target_coherence": self.target_coherence,
            "aad": _b64(self.aad),
            "friction_snapshot": self.friction_snapshot,
            "tarpit_mode": self.tarpit_mode,
            "tarpit_seconds": self.tarpit_seconds,
            "friction_backend": self.friction_backend,
        }
        # Nunca serializar sk al .stok por defecto
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "StokFile":
        sk = None
        if "sk" in d and d["sk"]:
            sk = _unb64(d["sk"])  # compatibilidad con .stok v0.4.0 que sí la llevaban
        return cls(
            governance_outcomes=list(d["governance_outcomes"]),
            public_label=_unb64(d["public_label"]),
            epsilon=float(d["epsilon"]),
            pk=_unb64(d["pk"]),
            ct=_unb64(d["ct"]),
            nonce=_unb64(d["nonce"]),
            ciphertext=_unb64(d["ciphertext"]),
            salt=_unb64(d["salt"]),
            material=_unb64(d["material"]),
            target_coherence=float(d["target_coherence"]),
            aad=_unb64(d["aad"]),
            friction_snapshot=dict(d.get("friction_snapshot") or {}),
            tarpit_mode=d.get("tarpit_mode", "off"),
            tarpit_seconds=float(d.get("tarpit_seconds", 0.0)),
            friction_backend=d.get("friction_backend", "auto"),
            sk=sk,
        )


def write_key_file(sk: bytes, path: str | Path) -> None:
    """Escribe la sk en un archivo hermano con cabecera STKEY (no es el .stok)."""
    path = Path(path)
    body = json.dumps({"version": KEY_VERSION, "sk": _b64(sk)}, separators=(",", ":")).encode("utf-8")
    header = KEY_MAGIC + struct.pack(">B", KEY_VERSION) + struct.pack(">I", len(body))
    path.write_bytes(header + body)


def read_key_file(path: str | Path) -> bytes:
    path = Path(path)
    data = path.read_bytes()
    # KEY_MAGIC(5) + version(1) + body_len(4) = 10
    if len(data) < 10 or data[:5] != KEY_MAGIC:
        raise ValueError(f"Archivo de clave no válido: {path}")
    (body_len,) = struct.unpack(">I", data[6:10])
    body = data[10 : 10 + body_len]
    if len(body) != body_len:
        raise ValueError("Longitud de clave inconsistente")
    d = json.loads(body.decode("utf-8"))
    return _unb64(d["sk"])


def protect_file(
    input_path: str | Path,
    output_path: str | Path | None = None,
    *,
    master_secret: bytes,
    governance_outcomes: Optional[List[int]] = None,
    public_label: bytes = b"DCP-SMART-PROD",
    epsilon: float = 0.008,
    tarpit_mode: str = "off",
    tarpit_seconds: float = 0.0,
    friction_backend: str = "auto",
    key_path: str | Path | None = None,
) -> Tuple[Path, Path]:
    """
    Cifra el contenido de `input_path` y escribe:
      - el archivo .stok (sin sk)
      - el archivo de clave (.stok.key) con la sk

    Devuelve (ruta_stok, ruta_key).
    """
    input_path = Path(input_path)
    if not input_path.is_file():
        raise FileNotFoundError(f"No existe el archivo de entrada: {input_path}")

    if output_path is None:
        output_path = input_path.with_suffix(input_path.suffix + ".stok")
    else:
        output_path = Path(output_path)

    if key_path is None:
        key_path = Path(str(output_path) + ".key")
    else:
        key_path = Path(key_path)

    payload = input_path.read_bytes()
    if governance_outcomes is None:
        governance_outcomes = [0, 0, 0, 1, 0, 1, 1, 1]

    tok = SmartTokenProd(
        governance_outcomes=governance_outcomes,
        secret_payload=payload,
        master_secret=master_secret,
        public_label=public_label,
        epsilon=epsilon,
        tarpit_mode=tarpit_mode,
        tarpit_seconds=tarpit_seconds,
        friction_backend=friction_backend,
    )

    snap = tok.friction_snapshot()
    snap["stok_id"] = compute_stok_id(tok.pk, tok.ct, public_label)
    snap.setdefault("recovery_tier", 0)
    snap.setdefault("work_factor", 1)
    snap.pop("recovery_debt", None)
    stok = StokFile(
        governance_outcomes=governance_outcomes,
        public_label=public_label,
        epsilon=epsilon,
        pk=tok.pk,
        ct=tok.ct,
        nonce=tok.nonce,
        ciphertext=tok.ciphertext,
        salt=tok.salt,
        material=tok.material,
        target_coherence=tok.target_coherence,
        aad=tok._aad,
        friction_snapshot=snap,
        tarpit_mode=tarpit_mode,
        tarpit_seconds=tarpit_seconds,
        friction_backend=friction_backend,
        sk=None,
    )
    write_stok(stok, output_path)
    write_key_file(tok.sk, key_path)
    return output_path, key_path


def write_stok(stok: StokFile, path: str | Path) -> None:
    path = Path(path)
    body = json.dumps(stok.to_dict(), separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    header = MAGIC + struct.pack(">B", VERSION) + struct.pack(">I", len(body))
    path.write_bytes(header + body)


def read_stok(path: str | Path) -> StokFile:
    path = Path(path)
    data = path.read_bytes()
    if len(data) < 9 or data[:4] != MAGIC:
        raise ValueError(f"Archivo no es un .stok válido (magic incorrecto): {path}")
    version = data[4]
    if version != VERSION:
        raise ValueError(f"Versión de .stok no soportada: {version} (esperada {VERSION})")
    (body_len,) = struct.unpack(">I", data[5:9])
    body = data[9 : 9 + body_len]
    if len(body) != body_len:
        raise ValueError("Longitud del bloque JSON inconsistente")
    d = json.loads(body.decode("utf-8"))
    return StokFile.from_dict(d)


def _rehydrate_tarpit(stok: StokFile, shared_secret: bytes):
    tarpit = make_tarpit(
        shared_secret,
        stok.tarpit_mode,
        stok.tarpit_seconds,
        stok.friction_backend,
    )
    snap = stok.friction_snapshot or {}
    if hasattr(tarpit, "restore_snapshot"):
        tarpit.restore_snapshot(snap)
    else:
        fail_count = int(snap.get("fail_count", 0))
        for _ in range(min(fail_count, 2)):
            tarpit.register_failure()
    return tarpit


def open_stok(
    path: str | Path,
    *,
    master_secret: bytes,
    sk: Optional[bytes] = None,
    key_path: Optional[str | Path] = None,
    provided_salt: Optional[bytes] = None,
    provided_material: Optional[bytes] = None,
    force_failure: bool = False,
    output_path: Optional[str | Path] = None,
    update_friction: bool = True,
) -> Tuple[Optional[bytes], Dict[str, Any]]:
    """
    Intenta abrir un .stok.

    La sk debe suministrarse por uno de estos caminos (en orden):
      1. parámetro `sk`
      2. archivo `key_path`
      3. archivo hermano por defecto: `<path>.key`
      4. sk embebida en el .stok (solo archivos legados)

    Si no hay sk disponible, el intento falla y se registra fricción.
    """
    path = Path(path)
    stok = read_stok(path)

    info: Dict[str, Any] = {
        "path": str(path),
        "friction_before": dict(stok.friction_snapshot or {}),
    }

    # Resolver sk
    resolved_sk = sk
    if resolved_sk is None and key_path is not None:
        resolved_sk = read_key_file(key_path)
    if resolved_sk is None:
        default_key = Path(str(path) + ".key")
        if default_key.is_file():
            resolved_sk = read_key_file(default_key)
    if resolved_sk is None and stok.sk is not None:
        resolved_sk = stok.sk  # legado

    salt = provided_salt if provided_salt is not None else stok.salt
    material = provided_material if provided_material is not None else stok.material

    expected_salt = hashlib.sha256(master_secret + b"|SALT|" + stok.public_label).digest()[:16]
    expected_material = hashlib.sha256(master_secret + b"|MATERIAL|" + expected_salt).digest()
    H = coherence_metric(material, salt)
    delta = abs(H - stok.target_coherence)
    ok_coh = delta <= stok.epsilon
    master_matches = (expected_salt == stok.salt) and (expected_material == stok.material)
    if provided_salt is None and provided_material is None:
        ok_coh = ok_coh and master_matches

    info["coherence"] = {
        "H": round(H, 6),
        "target": round(stok.target_coherence, 6),
        "delta": round(delta, 6),
        "within_window": ok_coh,
        "master_matches": master_matches,
    }

    ss = None
    if resolved_sk is None:
        info["mlkem_ok"] = False
        info["mlkem_error"] = "sk no disponible (suministre --key / archivo .stok.key)"
    else:
        try:
            ss = mlkem_decaps(resolved_sk, stok.ct)
            info["mlkem_ok"] = True
        except Exception as e:
            info["mlkem_ok"] = False
            info["mlkem_error"] = str(e)

    legitimate = ok_coh and info.get("mlkem_ok") and not force_failure

    base_key = ss if ss is not None else b"\x00" * 32
    tarpit = _rehydrate_tarpit(stok, base_key)

    stok_id = (stok.friction_snapshot or {}).get("stok_id") or compute_stok_id(
        stok.pk, stok.ct, stok.public_label
    )
    import os as _os
    argon2_time = getattr(open_stok, "_argon2_time_cost", None)
    argon2_mem = getattr(open_stok, "_argon2_memory_cost", None)
    if argon2_time is None:
        argon2_time = int(_os.environ.get("SMART_TOKEN_ARGON2_TIME", "2"))
    if argon2_mem is None:
        argon2_mem = int(_os.environ.get("SMART_TOKEN_ARGON2_MEM", str(64 * 1024)))

    persisted = dict(stok.friction_snapshot or {})
    cum0 = int(persisted.get("cumulative_iters", 0) or 0)

    # EVERY attempt pays Argon2id + trap work
    from .recovery import ITERS_PER_ATTEMPT
    info["work_factor_paid"] = 1
    info["hash_iters_paid"] = ITERS_PER_ATTEMPT
    info["cumulative_iters_before"] = cum0
    hang_on = getattr(open_stok, "_phase3_hang", None)
    if hang_on is None:
        hang_on = phase3_hang_enabled()
    try:
        pay_work_factor(
            stok_id=stok_id,
            master_secret=master_secret,
            work_factor=1,
            time_cost=int(argon2_time),
            memory_cost=int(argon2_mem),
        )
    except ImportError:
        pass

    if not legitimate:
        friction_info = tarpit.register_failure()
        new_snap = apply_failure_to_snapshot(tarpit.snapshot())
        if hasattr(tarpit, "state"):
            tarpit.state.recovery_tier = int(new_snap["recovery_tier"])
            if hasattr(tarpit.state, "work_factor"):
                tarpit.state.work_factor = int(new_snap["work_factor"])
            if hasattr(tarpit.state, "cumulative_iters"):
                tarpit.state.cumulative_iters = int(new_snap.get("cumulative_iters", 0) or 0)
        elif hasattr(tarpit, "_recovery_tier"):
            tarpit._recovery_tier = int(new_snap["recovery_tier"])
            tarpit._work_factor = int(new_snap["work_factor"])
            if hasattr(tarpit, "_cumulative_iters"):
                tarpit._cumulative_iters = int(new_snap.get("cumulative_iters", 0) or 0)
        new_snap["stok_id"] = stok_id
        new_snap.pop("recovery_debt", None)
        info["friction"] = friction_info
        info["friction_state"] = new_snap
        info["status"] = "DENIED"
        info["work_factor"] = int(new_snap.get("work_factor", 1))
        info["cumulative_iters"] = int(new_snap.get("cumulative_iters", 0) or 0)
        info["recoverable"] = False

        # Persist castigated state FIRST, then hang if phase 3 / tier≥3
        if update_friction:
            stok.friction_snapshot = new_snap
            write_stok(stok, path)

        if int(new_snap.get("recovery_tier", 0) or 0) >= MAX_TIER and hang_on:
            phase3_blocking_grind(
                stok_id=stok_id,
                master_secret=master_secret,
                time_cost=int(argon2_time),
                memory_cost=int(argon2_mem),
            )
        return None, info

    # Correct master at any tier (incl. ≥3): OPEN + reset (file never destroyed)
    tarpit.reset()
    key = derive_aes_key(ss)
    try:
        plaintext = aes_gcm_decrypt(key, stok.nonce, stok.ciphertext, stok.aad)
        cleared = clear_friction_fields(tarpit.snapshot())
        cleared["stok_id"] = stok_id
        cleared["work_factor"] = 1
        cleared["recovery_tier"] = 0
        cleared["cumulative_iters"] = 0
        info["aes_gcm_ok"] = True
        info["payload_len"] = len(plaintext)
        info["friction_state"] = cleared
        info["status"] = "OPEN"
        info["work_factor"] = 1
        info["recoverable"] = True

        if update_friction:
            stok.friction_snapshot = cleared
            write_stok(stok, path)

        if output_path is not None:
            Path(output_path).write_bytes(plaintext)

        return plaintext, info
    except Exception as e:
        info["aes_gcm_ok"] = False
        info["aes_error"] = str(e)
        info["status"] = "DENIED"
        info["recoverable"] = False
        friction_info = tarpit.register_failure()
        new_snap = apply_failure_to_snapshot(tarpit.snapshot())
        new_snap["stok_id"] = stok_id
        new_snap.pop("recovery_debt", None)
        info["friction"] = friction_info
        info["friction_state"] = new_snap
        info["work_factor"] = int(new_snap.get("work_factor", 1))
        if update_friction:
            stok.friction_snapshot = new_snap
            write_stok(stok, path)
        if int(new_snap.get("recovery_tier", 0) or 0) >= MAX_TIER and hang_on:
            phase3_blocking_grind(
                stok_id=stok_id,
                master_secret=master_secret,
                time_cost=int(argon2_time),
                memory_cost=int(argon2_mem),
            )
        return None, info



def friction_status(path: str | Path) -> Dict[str, Any]:
    stok = read_stok(path)
    snap = dict(stok.friction_snapshot or {})
    snap.setdefault("recovery_tier", 0)
    snap.setdefault("work_factor", work_factor_for_tier(int(snap.get("recovery_tier", 0) or 0)))
    snap.setdefault("cumulative_iters", 0)
    snap.pop("recovery_debt", None)
    return {
        "path": str(path),
        "friction_snapshot": snap,
        "public_label": stok.public_label.decode(errors="replace"),
        "target_coherence": stok.target_coherence,
        "has_embedded_sk": stok.sk is not None,
        "recovery_tier": int(snap.get("recovery_tier", 0) or 0),
        "work_factor": int(snap.get("work_factor", 1) or 1),
        "cumulative_iters": int(snap.get("cumulative_iters", 0) or 0),
    }
