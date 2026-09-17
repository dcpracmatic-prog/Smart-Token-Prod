#!/usr/bin/env python3
"""3 'hosts' (procesos) sin disco compartido: el broker une el fail_count."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main() -> int:
    work = Path("/tmp/stp-multihost")
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)

    broker = subprocess.Popen(
        [sys.executable, str(ROOT / "scripts/friction_broker.py"), "--port", "9379"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    time.sleep(0.3)
    if broker.poll() is not None:
        print("broker no arrancó", broker.stdout.read() if broker.stdout else "")
        return 1

    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    env["SMART_TOKEN_FRICTION_BROKER"] = "127.0.0.1:9379"
    env["SMART_TOKEN_PHASE3_HANG"] = "0"

    setup = r"""
import sys
from pathlib import Path
sys.path.insert(0, %r)
from smart_token_prod.stok import protect_file
p = Path("/tmp/stp-multihost/doc.bin"); p.write_bytes(b"MULTI")
protect_file(p, output_path=Path("/tmp/stp-multihost/master.stok"),
             key_path=Path("/tmp/stp-multihost/doc.key"),
             master_secret=b"m", tarpit_mode="off", friction_backend="python")
print("ready")
""" % str(ROOT)
    subprocess.check_call([sys.executable, "-c", setup], env=env)

    procs = []
    for i in range(3):
        host_dir = work / f"host{i}"
        host_dir.mkdir()
        shutil.copy(work / "master.stok", host_dir / "doc.stok")
        shutil.copy(work / "doc.key", host_dir / "doc.key")
        code = (
            "import os,sys; sys.path.insert(0,%r); "
            "os.environ['SMART_TOKEN_FRICTION_BROKER']='127.0.0.1:9379'; "
            "os.environ['SMART_TOKEN_PHASE3_HANG']='0'; "
            "from smart_token_prod.stok import open_stok; "
            "open_stok(%r, master_secret=b'bad-%d', key_path=%r)"
        ) % (str(ROOT), str(host_dir / "doc.stok"), i, str(host_dir / "doc.key"))
        procs.append(subprocess.Popen([sys.executable, "-c", code], env=env))
    rc = [p.wait() for p in procs]

    check = r"""
import os, sys
sys.path.insert(0, %r)
os.environ["SMART_TOKEN_FRICTION_BROKER"] = "127.0.0.1:9379"
from smart_token_prod.persistence import store_from_env
from smart_token_prod.stok import read_stok
from smart_token_prod.recovery import compute_stok_id
stok = read_stok("/tmp/stp-multihost/master.stok")
sid = compute_stok_id(stok.pk, stok.ct, stok.public_label)
store = store_from_env()
snap = store.load(sid)
print("store_fail_count", (snap or {}).get("fail_count"))
print("stok_id", sid)
""" % str(ROOT)
    out = subprocess.check_output([sys.executable, "-c", check], env=env, text=True)
    print("rc", rc)
    print(out.strip())
    broker.terminate()
    broker.wait(timeout=3)
    if "store_fail_count 3" not in out:
        print("FALLO: el broker no unificó los 3 hosts")
        return 1
    print("OK — 3 copias locales distintas, un solo fail_count=3 en el broker")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
