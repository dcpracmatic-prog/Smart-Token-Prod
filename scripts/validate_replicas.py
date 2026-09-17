#!/usr/bin/env python3
"""Comprueba que 3 réplicas no tienen 3 contadores: un solo fail_count global."""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["SMART_TOKEN_PHASE3_HANG"] = "0"


def worker(stok: str, key: str, guess: bytes) -> None:
    from smart_token_prod.stok import open_stok
    open_stok(stok, master_secret=guess, key_path=key)


def main() -> int:
    from smart_token_prod.stok import protect_file, friction_status
    from smart_token_prod.persistence import FileFrictionStore, PersistentTarpit
    from smart_token_prod.core import SequentialTarpit

    work = Path("/tmp/stp-replicas")
    work.mkdir(parents=True, exist_ok=True)
    sample = work / "doc.bin"
    sample.write_bytes(b"REPLICA-PROOF")
    stok, key = protect_file(
        sample, output_path=work / "doc.stok",
        master_secret=b"m", tarpit_mode="off", friction_backend="python",
    )

    print("3 procesos en paralelo, 1 fallo cada uno, mismo .stok")
    procs = []
    t0 = time.perf_counter()
    for i in range(3):
        p = subprocess.Popen(
            [sys.executable, "-c",
             "import os,sys; sys.path.insert(0," + repr(str(ROOT)) + "); "
             "os.environ['SMART_TOKEN_PHASE3_HANG']='0'; "
             "from smart_token_prod.stok import open_stok; "
             "open_stok(" + repr(str(stok)) + ", master_secret=b'bad%d', key_path=" % i
             + repr(str(key)) + ")"],
            env={**os.environ, "PYTHONPATH": str(ROOT), "SMART_TOKEN_PHASE3_HANG": "0"},
        )
        procs.append(p)
    rc = [p.wait() for p in procs]
    dt = time.perf_counter() - t0
    snap = friction_status(stok)["friction_snapshot"]
    fc = int(snap.get("fail_count", 0))
    print(f"  rc={rc}  {dt:.3f}s  fail_count={fc}")
    if fc != 3:
        print("FALLO: réplicas no compartieron el contador")
        return 1
    print("  OK .stok: 3 réplicas → estado 3 (no 1+1+1 locales)")

    print("\nFileFrictionStore: 3 PersistentTarpit, misma identity")
    store = FileFrictionStore(work / "store")
    keyb = b"k" * 32
    for i in range(3):
        t = PersistentTarpit(SequentialTarpit(keyb, "off", 0.0), store, "token-A")
        t.register_failure()
    saved = store.load("token-A")
    print(f"  fail_count store={saved.get('fail_count')}")
    if int(saved.get("fail_count", 0)) != 3:
        print("FALLO: FileFrictionStore no acumuló")
        return 1
    print("  OK store: identity compartida → 3")
    print("\nCOMPROBADO: la fuerza bruta no se parte entre réplicas del mismo disco.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
