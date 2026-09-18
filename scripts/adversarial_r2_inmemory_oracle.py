#!/usr/bin/env python3
"""Adversarial R2: SmartTokenProd.open DENIED must be opaque by default."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from smart_token_prod import SmartTokenProd

GOV = [0, 0, 0, 1, 0, 1, 1, 1]
BANNED = (
    "fail_count", "recovery_tier", "work_factor", "cumulative_iters",
    "friction_state", "friction", "recoverable", "mlkem_ok", "aes_error",
)


def main() -> int:
    tok = SmartTokenProd(GOV, b"r2", b"master", tarpit_mode="off", friction_backend="python")
    # Disable hang for this script
    SmartTokenProd.open._phase3_hang = False
    pt, info = tok.open(force_failure=True)
    if pt is not None or info.get("status") != "DENIED":
        print("FAIL: expected DENIED", info)
        return 1
    leaks = [k for k in BANNED if k in info]
    if leaks:
        print("FAIL: oracle leaks", leaks, "keys=", sorted(info))
        return 1
    _, rich = tok.open(force_failure=True, reveal_friction=True)
    if "friction_state" not in rich:
        print("FAIL: reveal_friction did not expose friction_state")
        return 1
    print("OK: in-memory DENIED opaque; reveal_friction works")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
