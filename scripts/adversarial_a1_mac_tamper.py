#!/usr/bin/env python3
"""Reproduce former A1 attack: bit-flip friction_mac after wrong opens.

Expected on v0.10+: fail-closed DENIED (no free OPEN / trap wipe).
Exit 0 = attack blocked (good). Exit 1 = regression (free OPEN).
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("SMART_TOKEN_ARGON2_TIME", "1")
os.environ.setdefault("SMART_TOKEN_ARGON2_MEM", str(8 * 1024))

from smart_token_prod import stok as stok_mod
from smart_token_prod.stok import (
    protect_file,
    open_stok,
    friction_status,
    read_stok,
    write_stok,
)

stok_mod.open_stok._argon2_time_cost = 1
stok_mod.open_stok._argon2_memory_cost = 8 * 1024
stok_mod.open_stok._phase3_hang = False


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        sample = td / "victim.stl"
        sample.write_bytes(b"classified-payload")
        master = b"correct-master-secret"
        stok_path, key_path = protect_file(
            sample,
            master_secret=master,
            tarpit_mode="off",
            friction_backend="python",
        )
        for i in range(3):
            pt, info = open_stok(
                stok_path,
                master_secret=f"wrong-{i}".encode(),
                key_path=key_path,
                reveal_friction=True,
            )
            assert pt is None and info["status"] == "DENIED"

        snap = friction_status(stok_path)["friction_snapshot"]
        print(
            f"debt before tamper: fail_count={snap.get('fail_count')} "
            f"cum={snap.get('cumulative_iters')}"
        )
        assert int(snap["fail_count"]) == 3

        st = read_stok(stok_path)
        mac = bytearray(st.friction_mac)
        mac[0] ^= 0xFF
        st.friction_mac = bytes(mac)
        write_stok(st, stok_path)
        print("bit-flipped friction_mac")

        pt, info = open_stok(
            stok_path,
            master_secret=master,
            key_path=key_path,
            reveal_friction=True,
        )
        after = read_stok(stok_path).friction_snapshot
        print(
            f"after correct master: status={info.get('status')} "
            f"pt={pt is not None} fail_count={after.get('fail_count')} "
            f"mac_ok={info.get('friction_mac_ok')}"
        )

        if (
            info.get("status") == "OPEN"
            or pt is not None
            or after.get("fail_count", 3) == 0
        ):
            print("REGRESSION: A1 free-OPEN / trap wipe still possible")
            return 1
        if after.get("fail_count") != 3:
            print("REGRESSION: debt mutated under invalid MAC")
            return 1
        print("OK: fail-closed — attack blocked")
        return 0


if __name__ == "__main__":
    sys.exit(main())
