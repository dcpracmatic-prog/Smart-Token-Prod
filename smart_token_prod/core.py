"""
Smart Token Production Prototype
- ML-KEM-768 (pqcrypto)
- AES-256-GCM for payload encryption
- Coherence check
- Sequential Tarpit (friction)
"""

from __future__ import annotations
import hashlib
import os
import time
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple, Any
import numpy as np

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import native as _native

# ---------------------------------------------------------------------------
# ML-KEM backend
# ---------------------------------------------------------------------------
try:
    from pqcrypto.kem.ml_kem_768 import keygen as pq_keygen, encaps as pq_encaps, decaps as pq_decaps
except ImportError as e:
    raise ImportError("pip install pqcrypto") from e

def mlkem_keygen():
    return pq_keygen()

def mlkem_encaps(pk):
    ct, ss = pq_encaps(pk)
    return ss, ct

def mlkem_decaps(sk, ct):
    return pq_decaps(sk, ct)

# ---------------------------------------------------------------------------
# Structural
# ---------------------------------------------------------------------------
LABELS_Q3 = ["const", "A", "B", "AB", "C", "AC", "BC", "ABC"]

def walsh_hadamard_matrix(n_bits: int = 3) -> np.ndarray:
    N = 2 ** n_bits
    H = np.empty((N, N), dtype=int)
    for r in range(N):
        for c in range(N):
            parity = bin(r & c).count("1") % 2
            H[r, c] = 1 if parity == 0 else -1
    return H

def governance_fingerprint(outcomes: List[int]) -> Dict[str, int]:
    H = walsh_hadamard_matrix(3)
    return dict(zip(LABELS_Q3, (H @ np.array(outcomes)).tolist()))

# ---------------------------------------------------------------------------
# Coherence
# ---------------------------------------------------------------------------
def coherence_metric(material: bytes, salt: bytes) -> float:
    h1 = hashlib.sha256(material + b"|C1|" + salt).digest()
    h2 = hashlib.sha256(salt + b"|C2|" + material).digest()
    v1 = int.from_bytes(h1[:8], "big") / (2**64 - 1)
    v2 = int.from_bytes(h2[:8], "big") / (2**64 - 1)
    c = 1.0 - abs(v1 - v2)
    b = (v1 + v2) / 2.0
    return float(np.clip(0.55 * c + 0.45 * b, 0.0, 1.0))

# ---------------------------------------------------------------------------
# AES-256-GCM helpers
# ---------------------------------------------------------------------------
def derive_aes_key(shared_secret: bytes, info: bytes = b"SMART-TOKEN-AES") -> bytes:
    """HKDF-like derivation: SHA-256(ss || info) -> 32 bytes."""
    return hashlib.sha256(shared_secret + info).digest()

def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
    """Returns (nonce, ciphertext_with_tag). nonce is 12 bytes."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ct

def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)

# ---------------------------------------------------------------------------
# Friction / Tarpit
# ---------------------------------------------------------------------------
def fib(n: int) -> int:
    if n <= 1:
        return n
    a, b = 0, 1
    for _ in range(2, n + 1):
        a, b = b, a + b
    return b

@dataclass
class FrictionState:
    fail_count: int = 0
    flag_fibonacci: bool = False
    flag_persistencia: bool = False
    fib_seed: int = 0
    working_key_material: bytes = b""
    tarpit_triggered: bool = False
    # Trap + Argon2 (v0.7.0): tier from cumulative_iters; work_factor legacy=1
    recovery_tier: int = 0
    work_factor: int = 1
    cumulative_iters: int = 0

class SequentialTarpit:
    def __init__(self, base_key: bytes, tarpit_mode: str = "off", tarpit_seconds: float = 0.0):
        self.base_key = base_key
        self.tarpit_mode = tarpit_mode
        self.tarpit_seconds = tarpit_seconds
        self.state = FrictionState(working_key_material=base_key)

    def _mutate_key(self, key: bytes, n: int) -> bytes:
        return hashlib.sha256(key + fib(n).to_bytes(16, "big") + b"|FRICTION").digest()

    def register_failure(self) -> Dict[str, Any]:
        self.state.fail_count += 1
        info: Dict[str, Any] = {"fail_count": self.state.fail_count, "action": None}
        if self.state.fail_count == 1:
            self.state.flag_fibonacci = True
            self.state.fib_seed = 20 + (int.from_bytes(self.base_key[:2], "big") % 10)
            info["action"] = "warning_seed"
            info["fib_seed"] = self.state.fib_seed
        elif self.state.fail_count == 2:
            self.state.flag_persistencia = True
            n = self.state.fib_seed + 5
            self.state.working_key_material = self._mutate_key(self.base_key, n)
            info["action"] = "key_mutated"
            info["fib_n"] = n
        else:
            self.state.tarpit_triggered = True
            # Phase 3 labels: wall fibonacci burn OFF by default; Argon2+grind
            # hang is applied in open()/open_stok when recovery_tier >= 3.
            # Modes "off"/"none"/"labels" keep fib flags only. Mode "cpu" still
            # supports legacy burn when tarpit_seconds > 0 (tests / old demos).
            if self.tarpit_mode in ("off", "none", "labels"):
                info["action"] = "tarpit_labels_only"
            elif self.tarpit_mode == "cpu" and float(self.tarpit_seconds) > 0:
                info["action"] = "tarpit_cpu"
                deadline = time.perf_counter() + self.tarpit_seconds
                n = 2
                while time.perf_counter() < deadline:
                    _ = fib(n)
                    n = (n % 40) + 2
            elif self.tarpit_mode == "mutate":
                n = self.state.fib_seed + 30
                self.state.working_key_material = self._mutate_key(self.base_key, n)
                info["action"] = "final_mutation"
                info["fib_n"] = n
            else:
                info["action"] = "blocked"
        # Work-factor ratchet: escalate tier + Argon2id rounds multiplier
        from .recovery import apply_failure_to_snapshot
        snap = self.snapshot()
        snap = apply_failure_to_snapshot(snap)
        self.state.recovery_tier = int(snap["recovery_tier"])
        self.state.work_factor = int(snap["work_factor"])
        self.state.cumulative_iters = int(snap.get("cumulative_iters", 0) or 0)
        info["recovery_tier"] = self.state.recovery_tier
        info["work_factor"] = self.state.work_factor
        info["cumulative_iters"] = self.state.cumulative_iters
        return info

    def reset(self):
        self.state = FrictionState(working_key_material=self.base_key)

    def restore_snapshot(self, snap: Dict[str, Any]) -> None:
        """
        Restaura el estado de fricción desde un snapshot persistido sin
        re-ejecutar los efectos secundarios (tarpit de CPU, mutaciones).
        Útil al rehidratar desde un .stok o FrictionStore.
        """
        fc = int(snap.get("fail_count", 0))
        self.state.fail_count = fc
        self.state.flag_fibonacci = bool(snap.get("flag_fibonacci", False))
        self.state.flag_persistencia = bool(snap.get("flag_persistencia", False))
        self.state.tarpit_triggered = bool(snap.get("tarpit_triggered", False))
        self.state.fib_seed = int(snap.get("fib_seed", 0))
        self.state.recovery_tier = int(snap.get("recovery_tier", 0) or 0)
        wf = snap.get("work_factor", snap.get("recovery_debt", 1))
        self.state.work_factor = int(wf) if wf not in (None, 0) else 1
        self.state.cumulative_iters = int(snap.get("cumulative_iters", 0) or 0)
        if fc >= 2 and self.state.fib_seed:
            n = self.state.fib_seed + 5
            self.state.working_key_material = self._mutate_key(self.base_key, n)
        else:
            self.state.working_key_material = self.base_key

    def snapshot(self) -> Dict[str, Any]:
        return {
            "fail_count": self.state.fail_count,
            "flag_fibonacci": self.state.flag_fibonacci,
            "flag_persistencia": self.state.flag_persistencia,
            "tarpit_triggered": self.state.tarpit_triggered,
            "fib_seed": self.state.fib_seed,
            "recovery_tier": self.state.recovery_tier,
            "work_factor": self.state.work_factor,
            "cumulative_iters": self.state.cumulative_iters,
        }

def make_tarpit(base_key: bytes, tarpit_mode: str = "off", tarpit_seconds: float = 0.0,
                 backend: str = "auto"):
    """
    Fábrica que elige el backend del tarpit de fricción.

    backend:
      - "native": fuerza smart_token_prod.native.NativeTarpit (libfriction.so).
                  Lanza NativeUnavailableError si la lib no está compilada.
      - "python": fuerza SequentialTarpit (puro Python), siempre disponible.
      - "auto"  : usa el nativo si libfriction.so está disponible, si no
                  cae automáticamente a Python. (default)
    """
    if backend == "native":
        return _native.NativeTarpit(base_key, tarpit_mode, tarpit_seconds)
    if backend == "python":
        return SequentialTarpit(base_key, tarpit_mode, tarpit_seconds)
    if backend == "auto":
        if _native.is_available():
            return _native.NativeTarpit(base_key, tarpit_mode, tarpit_seconds)
        return SequentialTarpit(base_key, tarpit_mode, tarpit_seconds)
    raise ValueError(f"backend desconocido: {backend!r} (usa 'auto', 'native' o 'python')")

# ---------------------------------------------------------------------------
# Token
# ---------------------------------------------------------------------------
@dataclass
class PublicView:
    governance_fingerprint: Dict
    public_label: str
    coherence_window: float
    friction_level: int

class SmartTokenProd:
    def __init__(
        self,
        governance_outcomes: List[int],
        secret_payload: bytes,
        master_secret: bytes,
        public_label: bytes = b"DCP-SMART-PROD",
        epsilon: float = 0.008,
        tarpit_mode: str = "off",
        tarpit_seconds: float = 0.0,
        friction_backend: str = "auto",
    ):
        assert len(governance_outcomes) == 8
        self.fingerprint = governance_fingerprint(governance_outcomes)
        self.public_label = public_label
        self.epsilon = epsilon
        self._plaintext = secret_payload

        # ML-KEM
        self.pk, self.sk = mlkem_keygen()
        self.shared_secret, self.ct = mlkem_encaps(self.pk)

        # AES-256-GCM
        self.aes_key = derive_aes_key(self.shared_secret)
        aad = public_label + b"|AAD"
        self.nonce, self.ciphertext = aes_gcm_encrypt(self.aes_key, secret_payload, aad)
        self._aad = aad

        # Coherence
        self._master_secret = master_secret
        self.salt = hashlib.sha256(master_secret + b"|SALT|" + public_label).digest()[:16]
        self.material = hashlib.sha256(master_secret + b"|MATERIAL|" + self.salt).digest()
        self.target_coherence = coherence_metric(self.material, self.salt)

        # Friction (usa el núcleo C++ vía FFI si está disponible; cae a Python si no)
        self.friction_backend = friction_backend
        self.tarpit = make_tarpit(self.shared_secret, tarpit_mode, tarpit_seconds, friction_backend)

    def public_view(self) -> PublicView:
        return PublicView(
            governance_fingerprint=self.fingerprint,
            public_label=self.public_label.decode(),
            coherence_window=self.epsilon,
            friction_level=self.tarpit.snapshot()["fail_count"],
        )

    def _check_coherence(self, provided_salt=None, provided_material=None) -> Tuple[bool, Dict]:
        salt = provided_salt if provided_salt is not None else self.salt
        material = provided_material if provided_material is not None else self.material
        H = coherence_metric(material, salt)
        delta = abs(H - self.target_coherence)
        return delta <= self.epsilon, {
            "H": round(H, 6),
            "target": round(self.target_coherence, 6),
            "delta": round(delta, 6),
            "within_window": delta <= self.epsilon,
        }

    def open(
        self,
        provided_salt=None,
        provided_material=None,
        force_failure: bool = False,
    ) -> Tuple[Optional[bytes], Dict]:
        info: Dict[str, Any] = {}
        ok_coh, coh_info = self._check_coherence(provided_salt, provided_material)
        info.update(coh_info)

        try:
            ss = mlkem_decaps(self.sk, self.ct)
            info["mlkem_ok"] = (ss == self.shared_secret)
        except Exception as e:
            info["mlkem_ok"] = False
            info["mlkem_error"] = str(e)
            ss = None

        legitimate = ok_coh and info.get("mlkem_ok") and not force_failure

        # Every attempt pays Argon2id + trap work BEFORE result
        from .recovery import (
            pay_work_factor,
            compute_stok_id,
            apply_failure_to_snapshot,
            ITERS_PER_ATTEMPT,
            MAX_TIER,
            _base_argon2_params,
            phase3_hang_enabled,
            phase3_blocking_grind,
        )
        snap0 = self.friction_snapshot()
        tier0 = int(snap0.get("recovery_tier", 0) or 0)
        stok_id = compute_stok_id(self.pk, self.ct, self.public_label)
        info["work_factor_paid"] = 1
        info["hash_iters_paid"] = ITERS_PER_ATTEMPT
        info["cumulative_iters_before"] = int(snap0.get("cumulative_iters", 0) or 0)
        t_cost, m_cost, _p = _base_argon2_params()
        t_cost = getattr(SmartTokenProd.open, "_argon2_time_cost", t_cost)
        m_cost = getattr(SmartTokenProd.open, "_argon2_memory_cost", m_cost)
        hang_on = getattr(SmartTokenProd.open, "_phase3_hang", None)
        if hang_on is None:
            hang_on = phase3_hang_enabled()
        pay_work_factor(
            stok_id=stok_id,
            master_secret=self._master_secret,
            work_factor=1,
            time_cost=int(t_cost),
            memory_cost=int(m_cost),
        )

        if not legitimate:
            friction_info = self.tarpit.register_failure()
            if hasattr(self.tarpit, "state"):
                synced = apply_failure_to_snapshot(self.tarpit.snapshot())
                self.tarpit.state.recovery_tier = int(synced["recovery_tier"])
                self.tarpit.state.work_factor = int(synced["work_factor"])
                self.tarpit.state.cumulative_iters = int(synced.get("cumulative_iters", 0) or 0)
            elif hasattr(self.tarpit, "_recovery_tier"):
                synced = apply_failure_to_snapshot(self.tarpit.snapshot())
                self.tarpit._recovery_tier = int(synced["recovery_tier"])
                self.tarpit._work_factor = int(synced["work_factor"])
                self.tarpit._cumulative_iters = int(synced.get("cumulative_iters", 0) or 0)
            fr = self.friction_snapshot()
            info["friction"] = friction_info
            info["friction_state"] = fr
            info["status"] = "DENIED"
            info["recoverable"] = False
            # Phase 3 / tier≥3: silent non-returning grind (opaque — no tier leak)
            if int(fr.get("recovery_tier", 0) or 0) >= MAX_TIER and hang_on:
                phase3_blocking_grind(
                    stok_id=stok_id,
                    master_secret=self._master_secret,
                    time_cost=int(t_cost),
                    memory_cost=int(m_cost),
                )
            return None, info

        # Correct master at any tier (incl. ≥3): pay once → OPEN + reset
        self.tarpit.reset()
        key = derive_aes_key(ss)
        try:
            plaintext = aes_gcm_decrypt(key, self.nonce, self.ciphertext, self._aad)
            info["aes_gcm_ok"] = True
            info["payload"] = plaintext
            info["friction_state"] = self.friction_snapshot()
            info["status"] = "OPEN"
            info["recoverable"] = True
            info["work_factor"] = 1
            return plaintext, info
        except Exception as e:
            info["aes_gcm_ok"] = False
            info["aes_error"] = str(e)
            info["status"] = "DENIED"
            info["recoverable"] = False
            return None, info

    def friction_snapshot(self) -> Dict:
        snap = dict(self.tarpit.snapshot())
        snap.setdefault("recovery_tier", 0)
        snap.setdefault("work_factor", 1)
        snap.setdefault("cumulative_iters", 0)
        snap.pop("recovery_debt", None)
        return snap
