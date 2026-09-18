#!/usr/bin/env python3
"""Adversarial R1: unlink+recreate .stok under flock → must fail-closed (no silent write)."""
from __future__ import annotations

import os
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from smart_token_prod.stok import protect_file, exclusive_stok, read_stok, write_stok


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        sample = td / "a.stl"
        sample.write_bytes(b"r1-adv")
        stok_path, _ = protect_file(
            sample, master_secret=b"r1-adv-m", tarpit_mode="off", friction_backend="python"
        )
        st0 = os.stat(stok_path)
        events: list = []

        def holder():
            with exclusive_stok(stok_path) as lock:
                time.sleep(0.4)
                try:
                    s = read_stok(stok_path, lock=lock)
                    snap = dict(s.friction_snapshot or {})
                    snap["fail_count"] = 99
                    s.friction_snapshot = snap
                    write_stok(s, stok_path, lock=lock)
                    events.append("WRITE_OK")
                except RuntimeError as e:
                    events.append(f"WRITE_FAIL:{e}")

        def attacker():
            time.sleep(0.05)
            raw = stok_path.read_bytes()
            stok_path.unlink()
            stok_path.write_bytes(raw)
            st1 = os.stat(stok_path)
            events.append(
                "REPLACED" if (st0.st_dev, st0.st_ino) != (st1.st_dev, st1.st_ino) else "SAME_INODE"
            )

        th = threading.Thread(target=holder)
        ta = threading.Thread(target=attacker)
        th.start(); ta.start(); th.join(); ta.join()
        print("events:", events)
        if "REPLACED" not in events:
            print("FAIL: path was not replaced with new inode")
            return 1
        if not any(str(e).startswith("WRITE_FAIL") for e in events):
            print("FAIL: write succeeded after inode replace (bypass)")
            return 1
        if "WRITE_OK" in events:
            print("FAIL: unexpected successful write")
            return 1
        print("OK: inode-replace under lock fail-closed")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
