#!/usr/bin/env python3
"""Adversarial R3: process-local hang slot exhaustion → DENIED without extra grind."""
from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ["SMART_TOKEN_ARGON2_TIME"] = "1"
os.environ["SMART_TOKEN_ARGON2_MEM"] = str(8 * 1024)
os.environ["SMART_TOKEN_MAX_CONCURRENT_HANGS"] = "1"

from smart_token_prod.stok import protect_file, open_stok
from smart_token_prod import stok as stok_mod
from smart_token_prod.recovery import (
    try_acquire_hang_slot,
    release_hang_slot,
    reset_hang_backpressure_for_tests,
)


def main() -> int:
    reset_hang_backpressure_for_tests()
    assert try_acquire_hang_slot() is True
    assert try_acquire_hang_slot() is False

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        sample = td / "x.stl"
        sample.write_bytes(b"bp")
        stok_path, key_path = protect_file(
            sample, master_secret=b"bp-m", tarpit_mode="off", friction_backend="python"
        )
        stok_mod.open_stok._argon2_time_cost = 1
        stok_mod.open_stok._argon2_memory_cost = 8 * 1024
        stok_mod.open_stok._phase3_hang = False
        open_stok(stok_path, master_secret=b"w1", key_path=key_path)
        open_stok(stok_path, master_secret=b"w2", key_path=key_path)
        stok_mod.open_stok._phase3_hang = True
        t0 = time.time()
        pt, info = open_stok(stok_path, master_secret=b"w3", key_path=key_path)
        elapsed = time.time() - t0
        release_hang_slot()
        reset_hang_backpressure_for_tests()
        if pt is not None or info.get("status") != "DENIED":
            print("FAIL: expected DENIED", info)
            return 1
        if elapsed >= 1.5:
            print(f"FAIL: hang not skipped under backpressure ({elapsed:.2f}s)")
            return 1
        print(f"OK: hang skipped under local backpressure in {elapsed:.3f}s")
        print("NOTE: multi-process/multi-host hang limits remain residual (not Redis-cluster).")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
