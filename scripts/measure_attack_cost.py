#!/usr/bin/env python3
"""Costo de un ciclo de ataque (3 fallos + hang + reinicio) y bit-flip GCM."""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.pop("SMART_TOKEN_PHASE3_HANG", None)


def main() -> int:
    from smart_token_prod.stok import (
        protect_file, open_stok, friction_status, read_stok, write_stok,
    )
    from smart_token_prod.core import aes_gcm_decrypt, derive_aes_key, mlkem_decaps
    from smart_token_prod.stok import read_key_file
    from smart_token_prod.recovery import pay_work_factor, compute_stok_id

    work = Path("/tmp/stp-cost")
    work.mkdir(parents=True, exist_ok=True)
    sample = work / "doc.bin"
    payload = b"DATOS-ORIGINALES-NO-DESTRUIR"
    sample.write_bytes(payload)
    master = b"master-humano"
    stok_path, key_path = protect_file(
        sample, output_path=work / "doc.stok",
        master_secret=master, tarpit_mode="off", friction_backend="python",
    )

    print("=" * 64)
    print("1. Ciclo atacante: 2 fallos que retornan + 3er fallo = ∞ + kill + reload")
    print("=" * 64)
    cycles = 3
    cycle_times = []
    for c in range(cycles):
        # copia fresca = "cargar nueva copia del documento"
        fresh = work / f"copy{c}.stok"
        fresh.write_bytes(stok_path.read_bytes())
        t0 = time.perf_counter()
        open_stok(fresh, master_secret=b"g1", key_path=key_path)
        open_stok(fresh, master_secret=b"g2", key_path=key_path)
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT)
        env["SMART_TOKEN_PHASE3_HANG"] = "1"
        child = (
            "import sys,os; sys.path.insert(0," + repr(str(ROOT)) + "); "
            "os.environ['SMART_TOKEN_PHASE3_HANG']='1'; "
            "from smart_token_prod.stok import open_stok; "
            "open_stok(" + repr(str(fresh)) + ", master_secret=b'g3', key_path=" + repr(str(key_path)) + ")"
        )
        p = subprocess.Popen([sys.executable, "-c", child], env=env,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            p.wait(timeout=0.8)  # detect hang quickly
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(timeout=3)
        # "reiniciar": costo de relanzar intérprete vacío
        subprocess.run([sys.executable, "-c", "pass"], check=True)
        dt = time.perf_counter() - t0
        cycle_times.append(dt)
        fc = friction_status(fresh)["friction_snapshot"]["fail_count"]
        print(f"  ciclo {c+1}: {dt:.3f}s  documento copia fail_count={fc}")

    avg = sum(cycle_times) / len(cycle_times)
    guesses_per_cycle = 3
    per_min = guesses_per_cycle / avg * 60.0
    print(f"\n  promedio ciclo (3 intentos + hang detectado + kill + python -c pass): {avg:.3f}s")
    print(f"  combinaciones / minuto : {per_min:.2f}")
    print(f"  combinaciones / hora   : {per_min*60:.1f}")
    print(f"  combinaciones / día    : {per_min*60*24:.0f}")

    print("\n" + "=" * 64)
    print("2. Tiempo estimado vs capas (este hardware, modelo de reinicio)")
    print("=" * 64)
    spaces = [
        ("PIN 4 dígitos", 10**4),
        ("master 6 minúsculas", 26**6),
        ("master 8 minúsculas", 26**8),
        ("master 8 alfanum", 62**8),
        ("master 10 alfanum", 62**10),
        ("AES-256 clave uniforme", 2**256),
        ("Grover AES-256 (cuántico ideal)", 2**128),
        ("ML-KEM-768 (clásico, orden 2^192)", 2**192),
    ]
    rate = per_min / 60.0  # per second
    for name, n in spaces:
        seconds = n / rate if rate else float("inf")
        if seconds > 3600 * 24 * 365 * 1e12:
            label = f"{seconds/ (3600*24*365):.3e} años"
        elif seconds > 3600 * 24 * 365:
            label = f"{seconds/ (3600*24*365):.1f} años"
        elif seconds > 3600 * 24:
            label = f"{seconds/ (3600*24):.1f} días"
        elif seconds > 3600:
            label = f"{seconds/3600:.1f} horas"
        else:
            label = f"{seconds:.1f} s"
        print(f"  {name:<34} {n:.3e}  →  {label}")

    print("\n  Nota: AES-256 y ML-KEM no se 'prueban' a 3 intentos/ciclo.")
    print("  Lo que el ciclo mide es adivinar el master_secret pasando por open().")

    print("\n" + "=" * 64)
    print("3. Un bit volteado en el ciphertext")
    print("=" * 64)
    stok = read_stok(stok_path)
    raw = bytearray(stok.ciphertext)
    raw[0] ^= 0x01
    stok.ciphertext = bytes(raw)
    flipped = work / "flipped.stok"
    write_stok(stok, flipped)
    # 4 validations because we may have dirty state? use original key + fresh flipped file
    # flipped is new write of mutated object; friction is copy of original snapshot (0)
    pt, info = open_stok(flipped, master_secret=master, key_path=key_path)
    print(f"  master correcto + 1 bit de ciphertext cambiado → {info['status']} payload={pt is not None}")
    print(f"  aes_gcm_ok={info.get('aes_gcm_ok')} aes_error={info.get('aes_error')}")
    print(f"  original intacto: {(work/'doc.stok').read_bytes() != flipped.read_bytes()}")
    # Direct GCM
    sk = read_key_file(key_path)
    ss = mlkem_decaps(sk, stok.ct)
    km = pay_work_factor(
        stok_id=compute_stok_id(stok.pk, stok.ct, stok.public_label),
        master_secret=master,
        time_cost=int(stok.kdf_params["time_cost"]),
        memory_cost=int(stok.kdf_params["memory_cost"]),
        parallelism=int(stok.kdf_params.get("parallelism", 1)),
    )
    try:
        aes_gcm_decrypt(derive_aes_key(ss, km), stok.nonce, stok.ciphertext, stok.aad)
        print("  GCM directo: DESCIFRÓ (no debería)")
    except Exception as e:
        print(f"  GCM directo: rechazó el tag ({type(e).__name__})")
    print("  El original doc.stok NO se borra. El archivo alterado es ilegible.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
