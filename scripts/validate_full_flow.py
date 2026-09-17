#!/usr/bin/env python3
"""Flujo completo comprobable (sin apagar la trampa):

  estado 0 + 1 fallo → 1
  estado 1 + 1 fallo → 2
  estado 2 + 1 fallo → 3  (persiste) + ∞ (el open no retorna)
  kill → documento sigue en estado 3
  4 aciertos consecutivos del master → OPEN
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Producto real: hang ON, Argon2 por defecto. No recortar.
os.environ.pop("SMART_TOKEN_PHASE3_HANG", None)
os.environ.pop("SMART_TOKEN_ARGON2_TIME", None)
os.environ.pop("SMART_TOKEN_ARGON2_MEM", None)


def estado(stok_path: Path) -> dict:
    from smart_token_prod.stok import friction_status
    snap = friction_status(stok_path)["friction_snapshot"]
    return {
        "fail_count": int(snap.get("fail_count", 0) or 0),
        "tier": int(snap.get("recovery_tier", 0) or 0),
        "flags": {
            "fib": bool(snap.get("flag_fibonacci")),
            "persist": bool(snap.get("flag_persistencia")),
            "trap": bool(snap.get("tarpit_triggered")),
        },
        "need": int(snap.get("validations_required") or 0),
        "oks": int(snap.get("validations_ok") or 0),
    }


def main() -> int:
    from smart_token_prod.stok import protect_file, open_stok

    work = Path("/tmp/stp-full-flow")
    work.mkdir(parents=True, exist_ok=True)
    sample = work / "documento.bin"
    sample.write_bytes(b"PAYLOAD-FLUJO-COMPLETO")
    master = b"clave-dueno"
    stok, key = protect_file(
        sample,
        output_path=work / "documento.stok",
        key_path=work / "documento.stok.key",
        master_secret=master,
        tarpit_mode="off",
        friction_backend="python",
    )

    print("=" * 64)
    print("FLUJO COMPLETO — trampa lógica 0→1→2→3→∞  luego 4 aciertos")
    print("=" * 64)
    e0 = estado(stok)
    print(f"estado inicial: {e0}")
    assert e0["fail_count"] == 0

    for n, guess in enumerate((b"fallo-A", b"fallo-B"), start=1):
        t0 = time.perf_counter()
        pt, info = open_stok(stok, master_secret=guess, key_path=key)
        dt = time.perf_counter() - t0
        e = estado(stok)
        print(f"\nfallo {n}: atacante={info['status']} payload={pt is not None} {dt:.3f}s")
        print(f"  documento → estado {e['fail_count']}  {e}")
        assert info["status"] == "DENIED" and pt is None
        assert e["fail_count"] == n

    print("\nfallo 3: persiste estado 3 y el proceso hijo entra en ∞")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    env["SMART_TOKEN_PHASE3_HANG"] = "1"
    child = f"""
import sys, os
sys.path.insert(0, {str(ROOT)!r})
os.environ["SMART_TOKEN_PHASE3_HANG"] = "1"
from smart_token_prod.stok import open_stok
open_stok({str(stok)!r}, master_secret=b"fallo-C", key_path={str(key)!r})
print("RETURNED")
"""
    t0 = time.perf_counter()
    proc = subprocess.Popen(
        [sys.executable, "-c", child],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        out, err = proc.communicate(timeout=4)
        print("ERROR: el 3er fallo RETORNÓ", out, err, proc.returncode)
        return 2
    except subprocess.TimeoutExpired:
        alive = proc.poll() is None
        print(f"  hijo vivo tras 4.0s: {alive} (∞ confirmada)")
        proc.kill()
        proc.wait(timeout=5)
        hang_wall = time.perf_counter() - t0
        print(f"  proceso detenido a los {hang_wall:.3f}s")

    e3 = estado(stok)
    print(f"\ndocumento tras kill: estado {e3['fail_count']}  {e3}")
    assert e3["fail_count"] == 3, e3
    assert e3["need"] == 4

    print("\n4 aciertos consecutivos del master (documento en estado 3)")
    last = None
    for i in range(1, 5):
        t0 = time.perf_counter()
        pt, info = open_stok(stok, master_secret=master, key_path=key)
        dt = time.perf_counter() - t0
        e = estado(stok)
        print(f"  acierto {i}/4 → {info['status']} payload={pt is not None} {dt:.3f}s  {e}")
        last = (pt, info, e)
        if i < 4:
            assert info["status"] == "DENIED" and pt is None
            assert e["fail_count"] == 3
        else:
            assert info["status"] == "OPEN" and pt == sample.read_bytes()
            assert e["fail_count"] == 0

    print("\nOK — flujo completo verificado")
    print("  0→1→2→3 persistido, ∞ no retorna, kill deja estado 3, 4 aciertos OPEN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
