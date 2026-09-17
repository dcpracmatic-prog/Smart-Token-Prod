#!/usr/bin/env python3
"""Attacker-shaped script: double-tap each guess, hang on the 4th attempt."""
from __future__ import annotations

import os
import resource
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
# Hang ON — this is the product trap.
os.environ.pop("SMART_TOKEN_PHASE3_HANG", None)
os.environ["SMART_TOKEN_PHASE3_HANG"] = "1"

from smart_token_prod.stok import protect_file, open_stok, friction_status


def main() -> int:
    work = Path("/tmp/stp-trap")
    work.mkdir(parents=True, exist_ok=True)
    sample = work / "doc.bin"
    sample.write_bytes(b"TRAP-PAYLOAD")
    master = b"owner-secret-never-guessed"
    stok, key = protect_file(
        sample, output_path=work / "doc.stok",
        master_secret=master, tarpit_mode="off", friction_backend="python",
    )

    print("Ataque ingenuo: cada combinación se prueba 2 veces")
    print("(después del 1er fallo hacen falta 2 validaciones para saber si ganó)")
    print("Hang de fase 3 ENCENDIDO.\n")

    guesses = [b"combo-alpha", b"combo-beta", b"combo-gamma"]
    unique = 0
    attempts = 0
    t_all = time.perf_counter()

    for g in guesses:
        unique += 1
        for tap in (1, 2):
            attempts += 1
            print(f"-- intento {attempts}  combinación #{unique}  tap {tap}/2  guess={g.decode()}")
            t0 = time.perf_counter()
            # 4th attempt (state already 3) must hang: run in child so we can measure 15s
            snap = friction_status(stok)["friction_snapshot"]
            fc = int(snap.get("fail_count", 0) or 0)
            will_hang = fc >= 3
            if will_hang or attempts >= 4:
                print("   estado previo ≥3 → el open no debe retornar; midiendo 15s de quema")
                env = os.environ.copy()
                env["PYTHONPATH"] = str(ROOT)
                env["SMART_TOKEN_PHASE3_HANG"] = "1"
                child = rf"""
import os, sys, time, resource
sys.path.insert(0, {str(ROOT)!r})
os.environ['SMART_TOKEN_PHASE3_HANG'] = '1'
from smart_token_prod.stok import open_stok
ru0 = resource.getrusage(resource.RUSAGE_SELF)
t0 = time.perf_counter()
open_stok({str(stok)!r}, master_secret={g!r}, key_path={str(key)!r})
print('UNEXPECTED_RETURN', time.perf_counter()-t0)
"""
                p = subprocess.Popen(
                    [sys.executable, "-c", child],
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                try:
                    out, err = p.communicate(timeout=15)
                    print("   RETORNÓ (no debería):", out, err, "rc", p.returncode)
                except subprocess.TimeoutExpired:
                    ru = resource.getrusage(resource.RUSAGE_CHILDREN)
                    p.kill()
                    p.wait()
                    elapsed = time.perf_counter() - t0
                    print(f"   NO RETORNÓ en {elapsed:.3f}s (kill)")
                    print(f"   CPU hijos (aprox) : {ru.ru_utime + ru.ru_stime:.3f}s")
                    print(f"   combinaciones únicas antes del hang: {unique}")
                    print(f"   intentos que SÍ devolvieron DENIED : {attempts-1}")
                    print("   Para seguir, el atacante borra proceso, recarga copia, empieza en 0.")
                    print(f"   tiempo total del script padre: {time.perf_counter()-t_all:.3f}s")
                    return 0

            pt, info = open_stok(stok, master_secret=g, key_path=key)
            dt = time.perf_counter() - t0
            st = friction_status(stok)
            snap = st["friction_snapshot"]
            print(f"   vista atacante : {info.get('status')}  payload={pt is not None}  {dt:.3f}s")
            print(f"   vista dueño    : fail_count={snap.get('fail_count')} "
                  f"tier={snap.get('recovery_tier')} "
                  f"validations_ok={snap.get('validations_ok')} "
                  f"need={snap.get('validations_required')}")

    print("no se alcanzó el hang")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
