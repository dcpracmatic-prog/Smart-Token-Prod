"""
CLI de la capa de archivo .stok.

Uso:
  smart-token protect archivo.stl [--master SECRET] [--out archivo.stl.stok]
  smart-token open   archivo.stl.stok [--master SECRET] [--key archivo.stok.key] [-o out]
  smart-token status archivo.stl.stok
  smart-token demo   [archivo_muestra]
  smart-token version
  smart-token doctor
  smart-token print-dep [--editable PATH]
  smart-token integrate PROJECT_DIR [--bridge PATH] [--editable PATH] [--dry-run]
  smart-token repair-mac archivo.stl.stok [--key archivo.stok.key]

Contrato v0.10.5:
  - Denegaciones OPAQUE (sin tier / fail_count / work_factor en stdout).
  - Tras phase 3 (fail_count≥3) + master incorrecto: open entra en bucle que no retorna.
  - status inspecciona el snapshot (herramienta del dueño, no oráculo de deny).
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path


def _master_from_args(args, *, allow_demo_default: bool = False):
    if getattr(args, "master", None):
        return args.master.encode("utf-8")
    env = os.environ.get("SMART_TOKEN_MASTER")
    if env:
        return env.encode("utf-8")
    if allow_demo_default:
        print(
            "WARNING: using built-in demo-master-secret — "
            "NEVER use this for real data. Set --master or SMART_TOKEN_MASTER.",
            file=sys.stderr,
        )
        return b"demo-master-secret"
    print(
        "error: --master or SMART_TOKEN_MASTER is required "
        "(demo-master-secret is only for `smart-token demo`)",
        file=sys.stderr,
    )
    return None


def cmd_protect(args: argparse.Namespace) -> int:
    from .stok import protect_file

    master = _master_from_args(args)
    if master is None:
        return 2
    stok_path, key_path = protect_file(
        args.input,
        output_path=args.out,
        master_secret=master,
        tarpit_mode=args.tarpit_mode,
        tarpit_seconds=args.tarpit_seconds,
        friction_backend=args.backend,
        key_path=args.key,
    )
    print(f"Protegido: {args.input}")
    print(f"  .stok  : {stok_path}  ({stok_path.stat().st_size} bytes)")
    print(f"  clave  : {key_path}  ({key_path.stat().st_size} bytes)")
    print(f"  origen : {Path(args.input).stat().st_size} bytes")
    return 0


def cmd_open(args: argparse.Namespace) -> int:
    from .stok import open_stok

    master = _master_from_args(args)
    if master is None:
        return 2
    force = bool(args.force_failure)

    print(f"Abriendo: {args.input}")

    t0 = time.perf_counter()
    plaintext, info = open_stok(
        args.input,
        master_secret=master,
        key_path=args.key,
        force_failure=force,
        output_path=args.out,
        update_friction=True,
    )
    elapsed = time.perf_counter() - t0
    status = info.get("status")

    if status == "OPEN" and plaintext is not None:
        print(f"  Resultado       : OPEN — payload recuperado ({len(plaintext)} bytes)")
        if args.out:
            print(f"  Escrito en      : {args.out}")
        print(f"  Tiempo          : {elapsed:.3f}s")
        return 0

    # Opaque denial — no tier / fail_count / work_factor / rich reasons
    print("  Resultado       : DENIED")
    print(f"  Tiempo          : {elapsed:.3f}s")
    return 1


def cmd_status(args: argparse.Namespace) -> int:
    """Owner inspection of friction_snapshot (not printed on deny)."""
    from .stok import friction_status

    st = friction_status(args.input)
    snap = st["friction_snapshot"]
    print(f"Archivo : {st['path']}")
    print(f"Label   : {st['public_label']}")
    print(f"Coherencia objetivo : {st['target_coherence']:.6f}")
    print(f"sk embebida en .stok : {st.get('has_embedded_sk', False)}")
    print(f"Fricción (snapshot interno):")
    print(f"  fail_count       : {snap.get('fail_count', 0)}")
    print(f"  recovery_tier    : {snap.get('recovery_tier', 0)}")
    print(f"  work_factor      : {snap.get('work_factor', 1)}")
    print(f"  cumulative_iters : {snap.get('cumulative_iters', 0)}")
    print(f"  stok_id          : {snap.get('stok_id', '')}")
    print(f"  flag_fibonacci   : {snap.get('flag_fibonacci', False)}")
    print(f"  flag_persistencia: {snap.get('flag_persistencia', False)}")
    print(f"  tarpit_triggered : {snap.get('tarpit_triggered', False)}")
    return 0


def _make_sample_stl(path: Path) -> None:
    stl = """solid sample_tetrahedron
  facet normal 0 0 0
    outer loop
      vertex 0 0 0
      vertex 1 0 0
      vertex 0 1 0
    endloop
  endfacet
  facet normal 0 0 0
    outer loop
      vertex 0 0 0
      vertex 1 0 0
      vertex 0 0 1
    endloop
  endfacet
  facet normal 0 0 0
    outer loop
      vertex 0 0 0
      vertex 0 1 0
      vertex 0 0 1
    endloop
  endfacet
  facet normal 0 0 0
    outer loop
      vertex 1 0 0
      vertex 0 1 0
      vertex 0 0 1
    endloop
  endfacet
endsolid sample_tetrahedron
"""
    path.write_text(stl, encoding="utf-8")


def cmd_demo(args: argparse.Namespace) -> int:
    from .stok import protect_file, open_stok, friction_status

    sample = Path(args.sample) if args.sample else Path("sample_cad.stl")
    if not sample.exists():
        print(f"Creando archivo de muestra: {sample}")
        _make_sample_stl(sample)

    master = _master_from_args(args, allow_demo_default=True)
    stok_path = sample.with_suffix(sample.suffix + ".stok")
    key_path = Path(str(stok_path) + ".key")
    recovered = sample.with_name(sample.stem + "_recovered" + sample.suffix)

    print("=" * 60)
    print("1. PROTEGER archivo real")
    print("=" * 60)
    out, kout = protect_file(
        sample,
        output_path=stok_path,
        master_secret=master,
        tarpit_mode=args.tarpit_mode,
        tarpit_seconds=args.tarpit_seconds,
        friction_backend=args.backend,
        key_path=key_path,
    )
    print(f"   {sample} ({sample.stat().st_size} B)")
    print(f"   → {out} ({out.stat().st_size} B)  [sin sk]")
    print(f"   → {kout} ({kout.stat().st_size} B)  [sk fuera de banda]")

    print()
    print("=" * 60)
    print("2. APERTURA LEGÍTIMA (master + key correctos)")
    print("=" * 60)
    t0 = time.perf_counter()
    pt, info = open_stok(
        stok_path,
        master_secret=master,
        key_path=key_path,
        output_path=recovered,
        update_friction=True,
    )
    elapsed = time.perf_counter() - t0
    assert pt is not None and pt == sample.read_bytes()
    print(f"   OK — OPEN ({len(pt)} B) en {elapsed:.3f}s")
    print(f"   Escrito: {recovered}")

    print()
    print("=" * 60)
    print("3. INTENTOS ERRÓNEOS (denegación OPAQUE; trap silencioso)")
    print("=" * 60)
    print("   Cada intento paga Argon2id + trabajo de trampa.")
    print("   CLI no anuncia tier/fail_count. Use `status` para inspeccionar.")
    print("   Tras phase 3 (fail_count≥3), el siguiente wrong open NO RETORNA.")
    print("   Demo hace 3 fallos (aún < hang) y muestra status.")
    print()

    # Disable hang only so demo can finish after escalating toward phase 3.
    # Product default hang remains ON outside this demo helper attribute.
    prev_hang = getattr(open_stok, "_phase3_hang", None)
    open_stok._phase3_hang = False
    try:
        for i in range(1, 4):
            wrong = master + b"-wrong-" + str(i).encode()
            t0 = time.perf_counter()
            pt, info = open_stok(
                stok_path,
                master_secret=wrong,
                key_path=key_path,
                update_friction=True,
            )
            elapsed = time.perf_counter() - t0
            print(f"   Intento: DENIED — {elapsed:.3f}s")
            assert info.get("status") == "DENIED"
    finally:
        if prev_hang is None:
            if hasattr(open_stok, "_phase3_hang"):
                delattr(open_stok, "_phase3_hang")
        else:
            open_stok._phase3_hang = prev_hang

    st = friction_status(stok_path)
    print(f"   status (inspección): tier={st['recovery_tier']} "
          f"fail_count={st['friction_snapshot'].get('fail_count')} "
          f"cum={st['cumulative_iters']}")
    print("   (Un 4º wrong open con hang ON quedaría bloqueado hasta kill.)")

    print()
    print("=" * 60)
    print("4. Recuperación: 3 fallos exigen 4 validaciones correctas")
    print("=" * 60)
    last = None
    for i in range(4):
        t0 = time.perf_counter()
        pt, info = open_stok(
            stok_path,
            master_secret=master,
            key_path=key_path,
            output_path=recovered,
            update_friction=True,
        )
        elapsed = time.perf_counter() - t0
        last = (pt, info, elapsed)
        print(f"   Validación {i+1}/4 → {info.get('status')} ({elapsed:.3f}s)")
    pt, info, elapsed = last
    assert pt is not None and pt == sample.read_bytes()
    print(f"   status={info.get('status')} pt={len(pt)}B tiempo={elapsed:.3f}s")
    print(f"   Escrito: {recovered}")

    print()
    print("=" * 60)
    print("5. ESTADO FINAL")
    print("=" * 60)
    print(f"   {friction_status(stok_path)}")
    return 0




def cmd_repair_mac(args: argparse.Namespace) -> int:
    """Owner: re-MAC friction after tamper/bitrot. Does not clear trap debt."""
    from .stok import repair_friction_mac

    try:
        info = repair_friction_mac(args.input, key_path=args.key)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"Repaired friction_mac: {info['path']}")
    print(f"  fail_count       : {info['fail_count']}")
    print(f"  recovery_tier    : {info['recovery_tier']}")
    print(f"  cumulative_iters : {info['cumulative_iters']}")
    print("  (debt preserved — use open with correct master to recover)")
    return 0


def cmd_version(args: argparse.Namespace) -> int:
    from . import __version__

    print(__version__)
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    """Check imports and print sdk.status()."""
    checks = [
        ("pqcrypto", "pqcrypto"),
        ("cryptography", "cryptography"),
        ("argon2", "argon2"),
    ]
    print("Smart Token Prod — doctor")
    for label, modname in checks:
        try:
            __import__(modname)
            print(f"  {label:14s}: OK")
        except Exception as exc:
            print(f"  {label:14s}: FAIL ({exc})")
    try:
        from . import native as _native

        avail = _native.is_available()
        print(f"  {'native':14s}: {'OK (libfriction)' if avail else 'optional (not loaded)'}")
    except Exception as exc:
        print(f"  {'native':14s}: FAIL ({exc})")

    from .sdk import status as sdk_status

    st = sdk_status()
    print("status():")
    for k, v in st.items():
        print(f"  {k}: {v}")
    return 0 if st.get("available") else 1


def cmd_print_dep(args: argparse.Namespace) -> int:
    from .integrate import print_dep_lines

    editable = Path(args.editable) if getattr(args, "editable", None) else None
    for line in print_dep_lines(editable):
        print(line)
    return 0


def cmd_integrate(args: argparse.Namespace) -> int:
    from .integrate import run_integrate

    root = Path(args.project_dir)
    editable = Path(args.editable) if getattr(args, "editable", None) else None
    mode = "editable" if editable else "git"
    bridge = args.bridge if getattr(args, "bridge", None) else "smart_token_bridge.py"
    dry_run = bool(getattr(args, "dry_run", False))

    try:
        summary = run_integrate(
            root,
            bridge_path=bridge,
            mode=mode,
            editable_path=editable,
            dry_run=dry_run,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print("smart-token integrate" + (" (dry-run)" if dry_run else ""))
    print(f"  root     : {summary['root']}")
    print(f"  kind     : {summary['detect']['kind']}")
    print(f"  dep      : {summary['dependency']['action']} → {summary['dependency']['line']}")
    print(f"  bridge   : {summary['bridge']['path']}")
    print(f"  notes    : {summary['notes']['path']}")
    if summary.get("extra_note"):
        print(f"  extra    : {summary['extra_note']}")
    if summary.get("vendor_stp_path"):
        print(f"  vendor   : FOUND at {summary['vendor_stp_path']} — remove after migrating")
    print("  next:")
    for step in summary["next_steps"]:
        print(f"    - {step}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="smart-token",
        description="Smart Token Prod — trampa lógica persistente + Argon2 + PQ crypto",
    )

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--master", default=None, help="Secreto maestro requerido para protect/open (o SMART_TOKEN_MASTER); demo puede omitirlo con aviso")
    common.add_argument(
        "--backend",
        choices=["auto", "native", "python"],
        default="auto",
    )
    common.add_argument(
        "--tarpit-mode",
        choices=["cpu", "mutate", "block", "off"],
        default="off",
        dest="tarpit_mode",
    )
    common.add_argument(
        "--tarpit-seconds",
        type=float,
        default=0.0,
        dest="tarpit_seconds",
    )

    sub = p.add_subparsers(dest="command", required=True)

    p_protect = sub.add_parser("protect", parents=[common], help="Cifrar un archivo → .stok + .stok.key")
    p_protect.add_argument("input", help="Archivo a proteger")
    p_protect.add_argument("--out", "-o", default=None, help="Ruta del .stok")
    p_protect.add_argument("--key", default=None, help="Ruta del archivo de clave (default: <stok>.key)")
    p_protect.set_defaults(func=cmd_protect)

    p_open = sub.add_parser("open", parents=[common], help="Intentar abrir un .stok")
    p_open.add_argument("input", help="Archivo .stok")
    p_open.add_argument("--out", "-o", default=None, help="Escribir payload recuperado")
    p_open.add_argument("--key", default=None, help="Archivo de clave .stok.key")
    p_open.add_argument("--force-failure", action="store_true")
    p_open.set_defaults(func=cmd_open)

    p_status = sub.add_parser("status", parents=[common], help="Inspeccionar friction_snapshot del .stok")
    p_status.add_argument("input", help="Archivo .stok")
    p_status.set_defaults(func=cmd_status)

    p_demo = sub.add_parser("demo", parents=[common], help="Demo: protect + legítimo + trap opaco")
    p_demo.add_argument("sample", nargs="?", default=None)
    p_demo.set_defaults(func=cmd_demo)

    p_version = sub.add_parser("version", help="Print package version")
    p_version.set_defaults(func=cmd_version)

    p_doctor = sub.add_parser("doctor", help="Check imports and print sdk.status()")
    p_doctor.set_defaults(func=cmd_doctor)

    p_print_dep = sub.add_parser(
        "print-dep",
        help="Print pip install line(s) for this package",
    )
    p_print_dep.add_argument(
        "--editable",
        default=None,
        metavar="PATH",
        help="Print editable install line for PATH instead of git URL",
    )
    p_print_dep.set_defaults(func=cmd_print_dep)

    p_integrate = sub.add_parser(
        "integrate",
        help="Scaffold bridge + dep notes into a host project directory",
    )
    p_integrate.add_argument("project_dir", help="Target project root")
    p_integrate.add_argument(
        "--bridge",
        default="smart_token_bridge.py",
        metavar="PATH",
        help="Relative path for the bridge module (default: smart_token_bridge.py)",
    )
    p_integrate.add_argument(
        "--editable",
        default=None,
        metavar="PATH",
        help="Use editable dep pointing at PATH instead of git URL",
    )
    p_integrate.add_argument(
        "--dry-run",
        action="store_true",
        help="Print plan only; do not write files",
    )
    p_integrate.set_defaults(func=cmd_integrate)

    p_repair = sub.add_parser(
        "repair-mac",
        help="Owner: re-MAC friction_snapshot after tamper/bitrot (debt preserved)",
    )
    p_repair.add_argument("input", help="Archivo .stok")
    p_repair.add_argument("--key", default=None, help="Archivo de clave .stok.key")
    p_repair.set_defaults(func=cmd_repair_mac)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
