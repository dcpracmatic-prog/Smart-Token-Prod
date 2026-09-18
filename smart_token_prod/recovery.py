"""
Logical trap + Argon2 hardening (v0.7.0):

  Differentiator = persistent sequential trap phases 1 → 2 → 3 in
  friction_snapshot (fail_count / flags / recovery_tier). Argon2id is
  commodity crypto that HARDENS that trap — it does not replace it.

  On EVERY open attempt (wrong or right):
    1) One Argon2id call bound to encryption / attempt material
    2) Exactly ITERS_PER_ATTEMPT (10_000) countable keyed SHA-256 iterations
       (trap work), optionally with fib mixing as non-oracle flavor

  On wrong open: persist cumulative_iters += 10_000; tier jumps at
  11k / 22k / 33k (max recovery_tier = 3). Phases mirror fail_count:
    fail 1 → phase 1 (flag_fibonacci)
    fail 2 → phase 2 (flag_persistencia)
    fail 3+ → phase 3 (tarpit_triggered); when fail_count >= 3,
              open enters a NON-RETURNING Argon2+grind loop (attacker
              must kill the process). Castigated .stok already persisted.
              (Hang key is fail_count, not recovery_tier — tier may still be 2
              at the first hang after the 3rd fail.)

  Correct master at any tier (incl. ≥3): pay once → OPEN + reset friction.
  File is NEVER destroyed.

  Do NOT claim Fibonacci alone as cryptographic hardness.

  Argon2id defaults (sane — NOT time_cost=10000):
    time_cost=2, memory_cost=65536 KiB, parallelism=1
"""

from __future__ import annotations

import hashlib
import os
from typing import Any, Dict, Tuple

ITERS_PER_ATTEMPT = 10_000
JUMP_EVERY = 11_000
MAX_TIER = 3
MAX_VALIDATIONS_REQUIRED = 4

DEFAULT_TIME_COST = 2
DEFAULT_MEMORY_COST = 64 * 1024  # KiB
DEFAULT_PARALLELISM = 1
DEFAULT_HASH_LEN = 32

# Legacy label: trap hardness is phase machine + Argon2; work_factor stays 1.
WORK_FACTOR_BY_TIER = {0: 1, 1: 1, 2: 1, 3: 1}


def tier_for_cumulative_iters(cumulative_iters: int) -> int:
    cum = max(int(cumulative_iters), 0)
    return min(MAX_TIER, cum // JUMP_EVERY)


def tier_for_fail_count(fail_count: int) -> int:
    """Derive tier from fail_count assuming each fail paid ITERS_PER_ATTEMPT."""
    return tier_for_cumulative_iters(int(fail_count) * ITERS_PER_ATTEMPT)


def work_factor_for_tier(tier: int) -> int:
    """Legacy label — pay is always 1× Argon2 + fixed trap iters."""
    return WORK_FACTOR_BY_TIER.get(int(tier), 1)


def compute_stok_id(pk: bytes, ct: bytes, public_label: bytes = b"") -> str:
    h = hashlib.sha256(pk + b"|" + ct + b"|" + public_label).hexdigest()
    return h[:32]


def validations_required(fail_count: int) -> int:
    """Owner recovery: N failures require N+1 consecutive correct validations (cap 4).

    fail 0 → 1, fail 1 → 2, fail 2 → 3, fail ≥3 / trap → 4.
    """
    fc = max(int(fail_count or 0), 0)
    if fc <= 0:
        return 1
    return min(fc + 1, MAX_VALIDATIONS_REQUIRED)


def apply_correct_validation(snap: Dict[str, Any]) -> Dict[str, Any]:
    """Record one correct master presentation. Does not reset the trap."""
    out = dict(snap or {})
    need = validations_required(int(out.get("fail_count", 0) or 0))
    ok = int(out.get("validations_ok", 0) or 0) + 1
    out["validations_ok"] = ok
    out["validations_required"] = need
    out["ready_to_open"] = ok >= need
    return out


def apply_failure_to_snapshot(snap: Dict[str, Any]) -> Dict[str, Any]:
    """
    After fail_count was incremented: sync cumulative_iters + recovery_tier.

    Idempotent w.r.t. fail_count: cumulative_iters = max(existing, fail_count * 10k).
    """
    out = dict(snap or {})
    fc = int(out.get("fail_count", 0))
    expected = fc * ITERS_PER_ATTEMPT
    prev_cum = int(out.get("cumulative_iters", 0) or 0)
    cum = max(prev_cum, expected)
    out["cumulative_iters"] = cum
    new_tier = tier_for_cumulative_iters(cum)
    prev_tier = int(out.get("recovery_tier", 0) or 0)
    out["recovery_tier"] = max(prev_tier, new_tier)
    out["work_factor"] = work_factor_for_tier(out["recovery_tier"])
    out["validations_ok"] = 0
    out["validations_required"] = validations_required(fc)
    out["ready_to_open"] = False
    out.pop("recovery_debt", None)
    return out


def clear_friction_fields(snap: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(snap or {})
    out["fail_count"] = 0
    out["flag_fibonacci"] = False
    out["flag_persistencia"] = False
    out["tarpit_triggered"] = False
    out["fib_seed"] = 0
    out["recovery_tier"] = 0
    out["work_factor"] = 1
    out["cumulative_iters"] = 0
    out["validations_ok"] = 0
    out["validations_required"] = 1
    out["ready_to_open"] = True
    out.pop("recovery_debt", None)
    return out


def _base_argon2_params() -> Tuple[int, int, int]:
    """(time_cost, memory_cost_kib, parallelism) with env / test overrides."""
    time_cost = int(os.environ.get("SMART_TOKEN_ARGON2_TIME", str(DEFAULT_TIME_COST)))
    memory_cost = int(os.environ.get("SMART_TOKEN_ARGON2_MEM", str(DEFAULT_MEMORY_COST)))
    parallelism = int(os.environ.get("SMART_TOKEN_ARGON2_PARALLELISM", str(DEFAULT_PARALLELISM)))
    return time_cost, memory_cost, parallelism


def trap_should_hang(snap: Dict[str, Any] | None) -> bool:
    """Logical trap: after fail_count reaches 3 the next grind does not return.

    The snapshot is persisted at state 3 first; the process then hangs.
    Killing it leaves the .stok at estado 3 (4 correct validations to OPEN).
    """
    return int((snap or {}).get("fail_count", 0) or 0) >= 3


def phase3_hang_enabled() -> bool:
    """
    Phase-3 non-returning grind is ON by default (product contract).
    Disable only for unit tests: SMART_TOKEN_PHASE3_HANG=0 or attribute overrides.
    """
    v = os.environ.get("SMART_TOKEN_PHASE3_HANG", "1").strip().lower()
    return v not in ("0", "false", "off", "no")


def _fib_flavor(n: int) -> int:
    """Small fibonacci mix — narrative flavor inside Argon2 grind, NOT sole hardness."""
    if n <= 1:
        return n
    a, b = 0, 1
    for _ in range(2, n + 1):
        a, b = b, a + b
    return b


def pay_keyed_hash_iters(
    *,
    stok_id: str,
    master_secret: bytes,
    seed: bytes,
    iterations: int = ITERS_PER_ATTEMPT,
) -> bytes:
    """Exactly `iterations` countable keyed SHA-256 chain steps (trap work)."""
    n = max(int(iterations), 0)
    block = hashlib.sha256(
        b"STOK-EQ-ITERS|"
        + stok_id.encode("ascii")
        + b"|"
        + master_secret
        + b"|"
        + seed
    ).digest()
    for i in range(n):
        block = hashlib.sha256(
            block + i.to_bytes(4, "big") + stok_id.encode("ascii")[:8]
        ).digest()
    return block


def pay_work_factor(
    *,
    stok_id: str,
    master_secret: bytes,
    work_factor: int = 1,
    time_cost: int | None = None,
    memory_cost: int | None = None,
    parallelism: int | None = None,
    hash_iters: int | None = None,
) -> bytes:
    """
    Trap pay: ONE Argon2id (encryption-integration) + hash_iters SHA-256.

    `work_factor` is accepted for API back-compat but does NOT multiply Argon2
    rounds (always a single Argon2id call per pay).
    """
    base_t, base_m, base_p = _base_argon2_params()
    t = int(time_cost if time_cost is not None else base_t)
    m = int(memory_cost if memory_cost is not None else base_m)
    p = int(parallelism if parallelism is not None else base_p)
    iters = int(hash_iters if hash_iters is not None else ITERS_PER_ATTEMPT)
    _ = work_factor  # legacy unused for round count

    salt = hashlib.sha256(
        stok_id.encode("ascii") + b"|eq-argon2|v1"
    ).digest()[:16]
    try:
        from argon2.low_level import Type, hash_secret_raw
    except ImportError as e:
        raise ImportError("argon2-cffi is required: pip install argon2-cffi") from e
    argon_out = hash_secret_raw(
        secret=master_secret,
        salt=salt,
        time_cost=t,
        memory_cost=m,
        parallelism=p,
        hash_len=DEFAULT_HASH_LEN,
        type=Type.ID,
    )
    return pay_keyed_hash_iters(
        stok_id=stok_id,
        master_secret=master_secret,
        seed=argon_out,
        iterations=iters,
    )


def phase3_blocking_grind(
    *,
    stok_id: str,
    master_secret: bytes,
    time_cost: int | None = None,
    memory_cost: int | None = None,
    parallelism: int | None = None,
) -> None:
    """
    Non-returning phase-3 trap loop.

    Combines Argon2id + keyed iteration grind; optional fib mixing as
    non-oracle flavor. Does not return — caller must kill the process.
    Castigated friction must already be persisted before entering.
    """
    fib_n = 2
    while True:
        pay_work_factor(
            stok_id=stok_id,
            master_secret=master_secret,
            work_factor=1,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
        )
        # Narrative spice only — not an oracle and not claimed hardness alone.
        _ = _fib_flavor(fib_n)
        fib_n = (fib_n % 40) + 2


# Back-compat aliases
def debt_for_tier(tier: int) -> int:
    return work_factor_for_tier(tier)


def pay_recovery_step(**kwargs):
    """Deprecated alias → pay_work_factor (maps debt_before → work_factor)."""
    wf = kwargs.pop("debt_before", None)
    if wf is not None and "work_factor" not in kwargs:
        kwargs["work_factor"] = wf
    return pay_work_factor(**kwargs)


def clear_recovery_fields(snap: Dict[str, Any]) -> Dict[str, Any]:
    return clear_friction_fields(snap)
