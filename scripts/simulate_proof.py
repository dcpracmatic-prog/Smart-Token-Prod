#!/usr/bin/env python3
"""Sandbox proof: offline binding, opaque deny, validation ladder, brute/DoS rate."""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
# Hang off so the 15s brute window can finish after fail_count ≥ 3.
os.environ["SMART_TOKEN_PHASE3_HANG"] = "0"

from smart_token_prod.stok import protect_file, open_stok, read_stok, friction_status
from smart_token_prod.cli import main
from smart_token_prod.core import derive_aes_key, aes_gcm_decrypt, mlkem_decaps
from smart_token_prod.stok import read_key_file
from smart_token_prod.recovery import pay_work_factor, compute_stok_id, validations_required


def section(title: str) -> None:
    print("\n" + "=" * 64)
    print(title)
    print("=" * 64)


def main_sim(work: Path) -> int:
    work.mkdir(parents=True, exist_ok=True)
    sample = work / "doc.bin"
    sample.write_bytes(b"OFFLINE-PAYLOAD-PROOF")
    master = b"owner-master-9f3a"
    stok_path, key_path = protect_file(
        sample, master_secret=master, tarpit_mode="off", friction_backend="python"
    )
    stok = read_stok(stok_path)

    section("1. Offline / no oráculo")
    raw = stok_path.read_bytes()
    print(f"  .stok bytes          : {len(raw)}")
    print(f"  salt persistido      : {stok.salt!r}")
    print(f"  material persistido  : {stok.material!r}")
    print(f"  master en claro      : {master in raw}")
    print(f"  binding_version      : {stok.binding_version}")
    print(f"  friction_mac presente: {bool(stok.friction_mac)}")
    assert stok.salt == b"" and stok.material == b""
    assert master not in raw

    section("2. sk + master falso no descifra (bypass de API)")
    sk = read_key_file(key_path)
    ss = mlkem_decaps(sk, stok.ct)
    kp = stok.kdf_params
    sid = compute_stok_id(stok.pk, stok.ct, stok.public_label)
    bad_km = pay_work_factor(
        stok_id=sid, master_secret=b"guess",
        time_cost=int(kp["time_cost"]), memory_cost=int(kp["memory_cost"]),
        parallelism=int(kp.get("parallelism", 1)),
    )
    try:
        aes_gcm_decrypt(derive_aes_key(ss, bad_km), stok.nonce, stok.ciphertext, stok.aad)
        bypass = True
    except Exception:
        bypass = False
    print(f"  bypass AES con sk+guess: {bypass}")
    assert bypass is False

    section("3. Deny opaco (CLI no publica fase ni fail_count)")
    from io import StringIO
    import contextlib
    buf = StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main([
            "open", str(stok_path), "--master", "incorrecto",
            "--key", str(key_path), "--backend", "python", "--tarpit-mode", "off",
        ])
    out = buf.getvalue()
    leaks = [k for k in ("fail_count", "recovery_tier", "flag_fibonacci",
                          "validations_ok", "work_factor", "Coherencia") if k in out]
    print(f"  rc={rc}")
    print("  stdout:")
    print(out)
    print(f"  fugas: {leaks or 'ninguna'}")
    assert rc == 1 and "DENIED" in out and not leaks

    section("4. Escalera de validaciones (comprobable)")
    # reset by opening enough times with correct master after previous deny
    # Current fail_count is 1 from section 3. Need 2 correct.
    results = []
    for label, secret in [
        ("ok1-after-1fail", master),
        ("ok2-after-1fail", master),
    ]:
        pt, info = open_stok(stok_path, master_secret=secret, key_path=key_path)
        results.append((label, info["status"], pt is not None))
        print(f"  {label}: {info['status']} payload={pt is not None}")
    assert results[-1][1] == "OPEN"

    def n_wrong(n):
        for i in range(n):
            open_stok(stok_path, master_secret=b"x"+str(i).encode(), key_path=key_path)

    def n_ok(n):
        last = None
        for _ in range(n):
            last = open_stok(stok_path, master_secret=master, key_path=key_path)
        return last

    n_wrong(2)
    a = n_ok(2)
    b = n_ok(1)
    print(f"  2 fallos + 2 ok → {a[1]['status']}")
    print(f"  2 fallos + 3er ok → {b[1]['status']} payload={b[0]==sample.read_bytes()}")
    assert a[1]["status"] == "DENIED" and b[1]["status"] == "OPEN"

    n_wrong(3)
    c = n_ok(3)
    d = n_ok(1)
    print(f"  3 fallos + 3 ok → {c[1]['status']}")
    print(f"  3 fallos + 4o ok → {d[1]['status']}")
    assert c[1]["status"] == "DENIED" and d[1]["status"] == "OPEN"
    print("  validations_required(0,1,2,3)=",
          [validations_required(i) for i in range(4)])

    section("5. Fuerza bruta offline (rate)")
    # Fresh file so hang never engages; hang already off.
    sample2 = work / "brute.bin"
    sample2.write_bytes(b"BRUTE")
    p2, k2 = protect_file(
        sample2, output_path=work / "brute.stok",
        master_secret=b"never-guessed-zz", tarpit_mode="off", friction_backend="python",
    )
    budget = 15.0
    import resource
    ru0 = resource.getrusage(resource.RUSAGE_SELF)
    t0 = time.perf_counter()
    n = 0
    while time.perf_counter() - t0 < budget:
        open_stok(p2, master_secret=f"pw{n}".encode(), key_path=k2)
        n += 1
    elapsed = time.perf_counter() - t0
    ru1 = resource.getrusage(resource.RUSAGE_SELF)
    cpu = (ru1.ru_utime - ru0.ru_utime) + (ru1.ru_stime - ru0.ru_stime)
    maxrss_mb = ru1.ru_maxrss / 1024.0
    rate = n / elapsed
    print(f"  ventana              : {elapsed:.3f}s")
    print(f"  combinaciones probadas: {n}")
    print(f"  intentos / segundo   : {rate:.4f}")
    print(f"  combinaciones / hora : {rate * 3600:.2f}")
    print(f"  combinaciones / día  : {rate * 86400:.1f}")
    print(f"  CPU user+sys          : {cpu:.3f}s  ({100*cpu/elapsed:.1f}% de la ventana)")
    print(f"  RSS máximo            : {maxrss_mb:.1f} MiB")
    print("  (Argon2id real + 10k hashes; sin oráculo SHA barato)")

    section("6. DoS / ráfaga concurrente (secuencial medida + nota)")
    t0 = time.perf_counter()
    bursts = 8
    for i in range(bursts):
        open_stok(p2, master_secret=f"dos{i}".encode(), key_path=k2)
    dos_elapsed = time.perf_counter() - t0
    print(f"  {bursts} intentos fallidos en serie: {dos_elapsed:.3f}s")
    print(f"  media por intento: {dos_elapsed/bursts:.3f}s")
    print("  El hang de fase 3 (prod) convierte ráfagas largas en un proceso")
    print("  que no retorna: el atacante debe matar y reiniciar.")

    report = {
        "offline_no_salt": True,
        "sk_bypass": False,
        "opaque_leaks": leaks,
        "window_s": round(elapsed, 3),
        "combinations_tried": n,
        "brute_per_sec": round(rate, 4),
        "cpu_s": round(cpu, 3),
        "maxrss_mib": round(maxrss_mb, 1),
        "combos_per_day": round(rate * 86400, 1),
        "validation_ladder": "1f→2v, 2f→3v, 3f→4v",
    }
    (work / "simulation_report.json").write_text(json.dumps(report, indent=2))
    print("\nReporte:", work / "simulation_report.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main_sim(Path("/tmp/stp-sim")))
