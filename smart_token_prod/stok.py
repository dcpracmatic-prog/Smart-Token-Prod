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
import hmac
import json
import struct
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

try:
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore

from .core import (
    SmartTokenProd,
    make_tarpit,
    derive_aes_key,
    aes_gcm_decrypt,
    mlkem_decaps,
    friction_mac,
    BINDING_VERSION,
)
from .recovery import (
    apply_failure_to_snapshot,
    apply_correct_validation,
    validations_required,
    clear_friction_fields,
    compute_stok_id,
    pay_work_factor,
    work_factor_for_tier,
    phase3_hang_enabled,
    phase3_blocking_grind,
    trap_should_hang,
    MAX_TIER,
)


# Fields safe to return on DENIED when reveal_friction=False (product API opacity).
_OPAQUE_DENY_KEYS = (
    "path",
    "status",
    "binding_version",
    "work_factor_paid",
    "hash_iters_paid",
)


def _public_info(info: Dict[str, Any], *, reveal_friction: bool) -> Dict[str, Any]:
    """Strip friction/ladder oracle from DENIED responses unless owner opts in."""
    if reveal_friction or info.get("status") != "DENIED":
        # Never leak hang kwargs to callers
        out = dict(info)
        out.pop("_hang", None)
        return out
    return {k: info[k] for k in _OPAQUE_DENY_KEYS if k in info}


MAGIC = b"STOK"
VERSION = 2
KEY_MAGIC = b"STKEY"
KEY_VERSION = 1


@contextmanager
def exclusive_stok(path: str | Path) -> Iterator[None]:
    """Serialize open_stok writers on the .stok inode itself.

    Sidecar `.stok.lock` files are NOT used: an attacker who unlinks the
    sidecar can create a fresh lock inode and bypass the critical section.
    Advisory flock on the data file inode cannot be bypassed that way.
    """
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"No existe el .stok: {path}")
    fh = open(path, "rb+")
    try:
        if fcntl is not None:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        if fcntl is not None:
            try:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
        fh.close()


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
    binding_version: int = BINDING_VERSION
    kdf_params: Dict[str, Any] = field(default_factory=dict)
    friction_mac: Optional[bytes] = None

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
            "binding_version": int(self.binding_version),
            "kdf_params": dict(self.kdf_params or {}),
        }
        if self.friction_mac:
            d["friction_mac"] = _b64(self.friction_mac)
        # v2: do not persist salt/material as an offline master oracle
        if int(self.binding_version) >= 2:
            d["salt"] = ""
            d["material"] = ""
            d["target_coherence"] = 0.0
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
            salt=_unb64(d["salt"]) if d.get("salt") else b"",
            material=_unb64(d["material"]) if d.get("material") else b"",
            target_coherence=float(d.get("target_coherence") or 0.0),
            aad=_unb64(d["aad"]),
            friction_snapshot=dict(d.get("friction_snapshot") or {}),
            tarpit_mode=d.get("tarpit_mode", "off"),
            tarpit_seconds=float(d.get("tarpit_seconds", 0.0)),
            friction_backend=d.get("friction_backend", "auto"),
            sk=sk,
            binding_version=int(d.get("binding_version") or d.get("version") or BINDING_VERSION),
            kdf_params=dict(d.get("kdf_params") or {}),
            friction_mac=_unb64(d["friction_mac"]) if d.get("friction_mac") else None,
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
    snap["stok_id"] = tok.stok_id
    snap.setdefault("recovery_tier", 0)
    snap.setdefault("work_factor", 1)
    snap.pop("recovery_debt", None)
    mac = friction_mac(tok.shared_secret, snap, tok.pk, tok.ct)
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
        binding_version=tok.binding_version,
        kdf_params=dict(tok.kdf_params),
        friction_mac=mac,
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
    if version not in (1, 2, VERSION):
        raise ValueError(f"Versión de .stok no soportada: {version} (esperada 1 o {VERSION})")
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
    reveal_friction: bool = False,
) -> Tuple[Optional[bytes], Dict[str, Any]]:
    """
    Intenta abrir un .stok (superficie de producto autenticada).

    La sk debe suministrarse por uno de estos caminos (en orden):
      1. parámetro `sk`
      2. archivo `key_path`
      3. archivo hermano por defecto: `<path>.key`
      4. sk embebida en el .stok (solo archivos legados)

    Si no hay sk/ss: DENIED en modo solo-lectura (no muta friction en disco;
    sin ss no se puede re-MAC de forma íntegra).

    Si friction_mac está presente e inválida: fall-closed — OPEN prohibido,
    no se acepta snapshot "fresco" vacío, no se resetea fail_count/ladder,
    bytes previos en disco se dejan intactos.

    Por defecto, info en DENIED es opaca (sin fail_count / tier / friction_state).
    Dueño: reveal_friction=True o CLI `status`.
    """
    path = Path(path)
    with exclusive_stok(path):
        plaintext, info = _open_stok_body(
            path=path,
            master_secret=master_secret,
            sk=sk,
            key_path=key_path,
            provided_salt=provided_salt,
            provided_material=provided_material,
            force_failure=force_failure,
            output_path=output_path,
            update_friction=update_friction,
            hang_after_holder=None,
        )
    hang = info.pop("_hang", None)
    public = _public_info(info, reveal_friction=reveal_friction)
    if hang:
        phase3_blocking_grind(**hang)
    return plaintext, public


def _open_stok_body(
    *,
    path: Path,
    master_secret: bytes,
    sk,
    key_path,
    provided_salt,
    provided_material,
    force_failure: bool,
    output_path,
    update_friction: bool,
    hang_after_holder,
):
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

    # Verify friction MAC against the ON-DISK snapshot only (what the MAC covers).
    # NEVER MAC-check a store-merged view — that was a 0.10 fail-closed DoS when
    # Redis/broker/dir store was harsher than a stale replica's disk bytes.
    # NEVER clear debt to {} on MAC failure — that was the A1 free-OPEN bug.
    disk_snap = dict(stok.friction_snapshot or {})
    from .persistence import store_from_env, merge_friction
    _store = store_from_env()
    _store_id = compute_stok_id(stok.pk, stok.ct, stok.public_label)

    mac_ok = True
    if ss is not None:
        if stok.friction_mac:
            expected_mac = friction_mac(ss, disk_snap, stok.pk, stok.ct)
            if not hmac.compare_digest(expected_mac, stok.friction_mac):
                info["friction_mac_ok"] = False
                mac_ok = False
                # Keep prior snapshot bytes; do not accept a "fresh" empty debt.
            else:
                info["friction_mac_ok"] = True
        elif int(stok.binding_version) >= 2:
            # Binding v2 artifacts must carry an integrity MAC over friction.
            info["friction_mac_ok"] = False
            mac_ok = False
            info["integrity_error"] = "friction_mac_missing"
        else:
            info["friction_mac_ok"] = None  # legacy pre-MAC artifact

    # Merge shared store only AFTER disk MAC authenticity (or legacy / no-ss).
    persisted = disk_snap
    if _store is not None and mac_ok:
        persisted = merge_friction(disk_snap, _store.load(_store_id)) or disk_snap
        stok.friction_snapshot = dict(persisted)
    else:
        stok.friction_snapshot = dict(disk_snap)

    base_key = ss if ss is not None else b"\x00" * 32
    # Rehydrate tarpit from persisted state only when MAC is trusted (or no ss yet).
    # On MAC failure keep the on-disk snapshot for inspection but do not treat it
    # as an authenticated ladder to escalate/reset.
    tarpit = _rehydrate_tarpit(stok, base_key)

    stok_id = persisted.get("stok_id") or compute_stok_id(
        stok.pk, stok.ct, stok.public_label
    )
    kp = dict(stok.kdf_params or {})
    argon2_time = int(kp.get("time_cost") or getattr(open_stok, "_argon2_time_cost", 2))
    argon2_mem = int(kp.get("memory_cost") or getattr(open_stok, "_argon2_memory_cost", 64 * 1024))
    argon2_par = int(kp.get("parallelism") or 1)

    cum0 = int(persisted.get("cumulative_iters", 0) or 0)

    # EVERY attempt pays Argon2id + trap work; output binds AES
    from .recovery import ITERS_PER_ATTEMPT
    info["work_factor_paid"] = 1
    info["hash_iters_paid"] = ITERS_PER_ATTEMPT
    info["cumulative_iters_before"] = cum0
    info["binding_version"] = int(stok.binding_version)
    hang_on = getattr(open_stok, "_phase3_hang", None)
    if hang_on is None:
        hang_on = phase3_hang_enabled()
    master_km = pay_work_factor(
        stok_id=stok_id,
        master_secret=master_secret,
        work_factor=1,
        time_cost=int(argon2_time),
        memory_cost=int(argon2_mem),
        parallelism=int(argon2_par),
    )

    plaintext = None
    decrypt_ok = False
    if ss is not None and not force_failure and mac_ok:
        try:
            key = derive_aes_key(ss, master_km)
            plaintext = aes_gcm_decrypt(key, stok.nonce, stok.ciphertext, stok.aad)
            decrypt_ok = True
            info["aes_gcm_ok"] = True
        except Exception as e:
            info["aes_gcm_ok"] = False
            info["aes_error"] = str(e)
    elif not mac_ok:
        info["aes_gcm_ok"] = False
        info["integrity_error"] = info.get("integrity_error") or "friction_mac_invalid"
        # Decrypt may still be cryptographically possible, but OPEN is forbidden
        # on the authenticated product path until friction integrity holds.
        plaintext = None
        decrypt_ok = False

    legitimate = bool(decrypt_ok) and not force_failure and mac_ok
    # Re-MAC requires ss + integrity. Without it: read-only deny (do not mutate disk).
    can_re_mac = bool(ss is not None and mac_ok)
    can_persist_friction = bool(update_friction and can_re_mac)

    if not legitimate:
        if not can_re_mac:
            # Read-only deny: missing sk/ss (cannot re-MAC) or friction MAC integrity failure.
            info["status"] = "DENIED"
            info["recoverable"] = False
            info["friction_state"] = dict(persisted)
            info["friction_persisted"] = False
            if not mac_ok:
                info["integrity_error"] = info.get("integrity_error") or "friction_mac_invalid"
            return None, info

        if _store is not None:
            def _mut(current):
                base = merge_friction(persisted, current) or {}
                if hasattr(tarpit, "restore_snapshot"):
                    tarpit.restore_snapshot(base)
                tarpit.register_failure()
                snap = apply_failure_to_snapshot(tarpit.snapshot())
                snap["stok_id"] = stok_id
                snap["validations_ok"] = 0
                snap["validations_required"] = validations_required(int(snap.get("fail_count", 0) or 0))
                snap.pop("recovery_debt", None)
                return snap
            new_snap = _store.locked_update(_store_id, _mut) or {}
            friction_info = {"fail_count": new_snap.get("fail_count"), "action": "shared_store"}
        else:
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
        new_snap["validations_ok"] = 0
        new_snap["validations_required"] = validations_required(int(new_snap.get("fail_count", 0) or 0))
        new_snap.pop("recovery_debt", None)
        info["friction"] = friction_info
        info["friction_state"] = new_snap
        info["status"] = "DENIED"
        info["work_factor"] = int(new_snap.get("work_factor", 1))
        info["cumulative_iters"] = int(new_snap.get("cumulative_iters", 0) or 0)
        info["recoverable"] = False

        # Persist castigated state FIRST, then hang if fail_count≥3 (phase 3).
        if can_persist_friction:
            stok.friction_snapshot = new_snap
            stok.friction_mac = friction_mac(ss, new_snap, stok.pk, stok.ct)
            write_stok(stok, path)
            if _store is not None:
                _store.save(_store_id, new_snap)
        else:
            info["friction_persisted"] = False

        if trap_should_hang(new_snap) and hang_on:
            info["_hang"] = {
                "stok_id": stok_id,
                "master_secret": master_secret,
                "time_cost": int(argon2_time),
                "memory_cost": int(argon2_mem),
            }
        return None, info

    # Correct master: accumulate validations. N fails → N+1 correct (cap 4).
    current = dict(stok.friction_snapshot or {})
    current.setdefault("fail_count", int((tarpit.snapshot() or {}).get("fail_count", 0)))
    progressed = apply_correct_validation(current)
    progressed["stok_id"] = stok_id
    if not progressed.get("ready_to_open"):
        info["status"] = "DENIED"
        info["recoverable"] = False
        info["friction_state"] = progressed
        if can_persist_friction:
            stok.friction_snapshot = progressed
            stok.friction_mac = friction_mac(ss, progressed, stok.pk, stok.ct)
            write_stok(stok, path)
            if _store is not None:
                _store.save(_store_id, progressed)
        return None, info

    tarpit.reset()
    cleared = clear_friction_fields(tarpit.snapshot())
    cleared["stok_id"] = stok_id
    cleared["work_factor"] = 1
    cleared["recovery_tier"] = 0
    cleared["cumulative_iters"] = 0
    info["payload_len"] = len(plaintext)
    info["friction_state"] = cleared
    info["status"] = "OPEN"
    info["work_factor"] = 1
    info["recoverable"] = True

    if can_persist_friction:
        stok.friction_snapshot = cleared
        stok.friction_mac = friction_mac(ss, cleared, stok.pk, stok.ct)
        write_stok(stok, path)
        if _store is not None:
            _store.clear(_store_id)

    if output_path is not None:
        Path(output_path).write_bytes(plaintext)

    return plaintext, info




def repair_friction_mac(
    path: str | Path,
    *,
    sk: Optional[bytes] = None,
    key_path: Optional[str | Path] = None,
) -> Dict[str, Any]:
    """
    Owner recovery after friction_mac bitrot / tamper DoS.

    Re-MACs the current on-disk friction_snapshot with ss derived from sk.
    Does NOT clear fail_count / ladder / hang debt and does NOT decrypt.
    Requires sk (parameter, key_path, sibling .key, or legacy embedded sk).
    """
    path = Path(path)
    with exclusive_stok(path):
        stok = read_stok(path)
        resolved_sk = sk
        if resolved_sk is None and key_path is not None:
            resolved_sk = read_key_file(key_path)
        if resolved_sk is None:
            default_key = Path(str(path) + ".key")
            if default_key.is_file():
                resolved_sk = read_key_file(default_key)
        if resolved_sk is None and stok.sk is not None:
            resolved_sk = stok.sk
        if resolved_sk is None:
            raise ValueError("sk no disponible para repair-mac (suministre --key / .stok.key)")
        ss = mlkem_decaps(resolved_sk, stok.ct)
        snap = dict(stok.friction_snapshot or {})
        new_mac = friction_mac(ss, snap, stok.pk, stok.ct)
        stok.friction_mac = new_mac
        write_stok(stok, path)
        return {
            "path": str(path),
            "status": "REPAIRED",
            "fail_count": int(snap.get("fail_count", 0) or 0),
            "cumulative_iters": int(snap.get("cumulative_iters", 0) or 0),
            "recovery_tier": int(snap.get("recovery_tier", 0) or 0),
            "friction_mac_repaired": True,
        }


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
