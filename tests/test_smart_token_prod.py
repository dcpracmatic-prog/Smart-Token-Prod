"""
Suite de pruebas — Smart Token Prod v0.10.3

Producto:
  - Differentiator = trampa lógica secuencial (fases 1→2→3) persistida en .stok
  - Argon2id endurece esa trampa (no la reemplaza)
  - Denegaciones opacas (sin anunciar tier en stdout de deny)
  - fail_count≥3 + wrong master → bucle bloqueante que no retorna
  - Master correcto a cualquier tier → OPEN + reset; archivo nunca destruido
"""

import hashlib
from pathlib import Path
import multiprocessing
import os
import time

import pytest

from smart_token_prod import SmartTokenProd
from smart_token_prod.core import coherence_metric, governance_fingerprint
from smart_token_prod.native import is_available as native_is_available, native_coherence_metric
from smart_token_prod.persistence import InMemoryFrictionStore, PersistentTarpit, FileFrictionStore
from smart_token_prod.keymgmt import InMemoryKeyProvider
from smart_token_prod import stok as stok_mod
from smart_token_prod.core import SmartTokenProd as STPClass


GOVERNANCE = [0, 0, 0, 1, 0, 1, 1, 1]


@pytest.fixture(autouse=True)
def _fast_argon2_and_no_hang():
    """Fast Argon2 for tests; disable phase-3 hang except hang-specific tests."""
    from smart_token_prod.recovery import reset_hang_backpressure_for_tests
    os.environ["SMART_TOKEN_ARGON2_TIME"] = "1"
    os.environ["SMART_TOKEN_ARGON2_MEM"] = str(8 * 1024)
    os.environ.pop("SMART_TOKEN_MAX_CONCURRENT_HANGS", None)
    reset_hang_backpressure_for_tests()
    stok_mod.open_stok._argon2_time_cost = 1
    stok_mod.open_stok._argon2_memory_cost = 8 * 1024
    stok_mod.open_stok._phase3_hang = False
    STPClass.open._argon2_time_cost = 1
    STPClass.open._argon2_memory_cost = 8 * 1024
    STPClass.open._phase3_hang = False
    STPClass._argon2_time_cost = 1
    STPClass._argon2_memory_cost = 8 * 1024
    yield
    os.environ.pop("SMART_TOKEN_ARGON2_TIME", None)
    os.environ.pop("SMART_TOKEN_ARGON2_MEM", None)
    os.environ.pop("SMART_TOKEN_MAX_CONCURRENT_HANGS", None)
    reset_hang_backpressure_for_tests()
    for obj in (stok_mod.open_stok, STPClass.open, STPClass):
        for attr in ("_argon2_time_cost", "_argon2_memory_cost", "_phase3_hang"):
            if obj is STPClass and attr == "_phase3_hang":
                continue
            if hasattr(obj, attr):
                delattr(obj, attr)


@pytest.mark.parametrize("backend", ["python", "native", "auto"])
def test_open_legitimate_returns_payload(backend):
    tok = SmartTokenProd(
        GOVERNANCE, b"payload-secreto", b"master",
        tarpit_mode="off", tarpit_seconds=0.0, friction_backend=backend,
    )
    pt, info = tok.open()
    assert pt == b"payload-secreto"
    assert info["aes_gcm_ok"] is True
    assert info.get("status") == "OPEN"


@pytest.mark.parametrize("backend", ["python", "native", "auto"])
def test_forced_failure_does_not_leak_payload(backend):
    tok = SmartTokenProd(
        GOVERNANCE, b"payload-secreto", b"master",
        tarpit_mode="off", tarpit_seconds=0.0, friction_backend=backend,
    )
    pt, info = tok.open(force_failure=True, reveal_friction=True)
    assert pt is None
    assert info["recoverable"] is False
    assert "payload" not in info
    assert info.get("status") == "DENIED"
    # First fail: cum=10000 < 11000 → tier 0 (phase 1 flags)
    assert info["friction_state"]["cumulative_iters"] == 10_000
    assert info["friction_state"]["recovery_tier"] == 0
    assert info["friction_state"]["flag_fibonacci"] is True


@pytest.mark.parametrize("backend", ["python", "native"])
def test_friction_phases_escalate_silently_in_snapshot(backend):
    """Phases 1→2→3 escalate in friction_snapshot (not via stdout)."""
    tok = SmartTokenProd(
        GOVERNANCE, b"x", b"master",
        tarpit_mode="off", tarpit_seconds=0.0, friction_backend=backend,
    )
    _, info1 = tok.open(force_failure=True, reveal_friction=True)
    assert info1["friction_state"]["fail_count"] == 1
    assert info1["friction_state"]["cumulative_iters"] == 10_000
    assert info1["friction_state"]["recovery_tier"] == 0
    assert info1["friction_state"]["flag_fibonacci"] is True

    _, info2 = tok.open(force_failure=True, reveal_friction=True)
    assert info2["friction_state"]["fail_count"] == 2
    assert info2["friction_state"]["cumulative_iters"] == 20_000
    assert info2["friction_state"]["recovery_tier"] == 1
    assert info2["friction_state"]["flag_persistencia"] is True

    _, info3 = tok.open(force_failure=True, reveal_friction=True)
    assert info3["friction_state"]["fail_count"] == 3
    assert info3["friction_state"]["cumulative_iters"] == 30_000
    assert info3["friction_state"]["recovery_tier"] == 2
    assert info3["friction_state"]["tarpit_triggered"] is True

    _, info4 = tok.open(force_failure=True, reveal_friction=True)
    assert info4["friction_state"]["cumulative_iters"] == 40_000
    assert info4["friction_state"]["recovery_tier"] == 3

    _, info5 = tok.open(force_failure=True, reveal_friction=True)
    assert info5["friction_state"]["cumulative_iters"] == 50_000
    assert info5["friction_state"]["recovery_tier"] == 3


def test_one_correct_open_after_tier3_works():
    """After ≥3 fails the trap reverts only after 4 consecutive correct validations."""
    tok = SmartTokenProd(
        GOVERNANCE, b"secret-payload", b"master",
        tarpit_mode="off", tarpit_seconds=0.0, friction_backend="python",
    )
    for _ in range(4):
        tok.open(force_failure=True)
    assert tok.friction_snapshot()["recovery_tier"] == 3
    assert tok.friction_snapshot()["cumulative_iters"] == 40_000

    for i in range(3):
        pt, info = tok.open()
        assert pt is None and info["status"] == "DENIED"
    pt, info = tok.open()
    assert pt == b"secret-payload"
    assert info["status"] == "OPEN"
    assert info.get("work_factor_paid") == 1
    assert info.get("hash_iters_paid") == 10_000
    assert tok.friction_snapshot()["fail_count"] == 0
    assert tok.friction_snapshot()["cumulative_iters"] == 0
    assert tok.friction_snapshot()["recovery_tier"] == 0


def test_tampered_ciphertext_fails_aes_gcm():
    tok = SmartTokenProd(GOVERNANCE, b"payload-secreto", b"master", friction_backend="python")
    tok.ciphertext = bytes([tok.ciphertext[0] ^ 0xFF]) + tok.ciphertext[1:]
    pt, info = tok.open(reveal_friction=True)
    assert pt is None
    assert info["aes_gcm_ok"] is False


@pytest.mark.skipif(not native_is_available(), reason="libfriction.so no compilado/disponible")
def test_native_coherence_matches_python_bit_for_bit():
    material = hashlib.sha256(b"material").digest()
    salt = hashlib.sha256(b"salt").digest()[:16]
    assert coherence_metric(material, salt) == pytest.approx(
        native_coherence_metric(material, salt), abs=1e-12
    )


@pytest.mark.skipif(not native_is_available(), reason="libfriction.so no compilado/disponible")
def test_native_and_python_tarpit_agree_on_fib_seed():
    from smart_token_prod.core import SequentialTarpit
    from smart_token_prod.native import NativeTarpit

    key = hashlib.sha256(b"same-base-key").digest()
    py_tarpit = SequentialTarpit(key, "cpu", 0.05)
    native_tarpit = NativeTarpit(key, "cpu", 0.05)
    py_tarpit.register_failure()
    native_tarpit.register_failure()
    assert py_tarpit.snapshot()["fib_seed"] == native_tarpit.snapshot()["fib_seed"]
    assert py_tarpit.snapshot()["fail_count"] == native_tarpit.snapshot()["fail_count"]


def test_inmemory_friction_store_roundtrip():
    store = InMemoryFrictionStore()
    assert store.load("user-1") is None
    store.save("user-1", {"fail_count": 2})
    assert store.load("user-1") == {"fail_count": 2}
    store.clear("user-1")
    assert store.load("user-1") is None


def test_persistent_tarpit_restores_fail_count_across_instances():
    from smart_token_prod.core import SequentialTarpit

    store = InMemoryFrictionStore()
    key = hashlib.sha256(b"identity-key").digest()
    tarpit_a = PersistentTarpit(SequentialTarpit(key, "off", 0.0), store, identity="user-1")
    tarpit_a.register_failure()
    tarpit_a.register_failure()
    assert tarpit_a.snapshot()["fail_count"] == 2
    tarpit_b = PersistentTarpit(SequentialTarpit(key, "off", 0.0), store, identity="user-1")
    assert tarpit_b.snapshot()["fail_count"] == 2


def test_file_store_serializes_failures(tmp_path):
    from smart_token_prod.core import SequentialTarpit
    from smart_token_prod.persistence import FileFrictionStore

    store = FileFrictionStore(tmp_path / "fric")
    key = hashlib.sha256(b"shared").digest()
    PersistentTarpit(SequentialTarpit(key, "off", 0.0), store, "id-x").register_failure()
    PersistentTarpit(SequentialTarpit(key, "off", 0.0), store, "id-x").register_failure()
    PersistentTarpit(SequentialTarpit(key, "off", 0.0), store, "id-x").register_failure()
    assert store.load("id-x")["fail_count"] == 3


def test_inmemory_key_provider_reuses_keypair_for_same_id():
    provider = InMemoryKeyProvider()
    pk1, sk1 = provider.get_or_create_keypair("token-A")
    pk2, sk2 = provider.get_or_create_keypair("token-A")
    assert pk1 == pk2 and sk1 == sk2


def test_inmemory_key_provider_rotate_changes_keys():
    provider = InMemoryKeyProvider()
    pk1, _ = provider.get_or_create_keypair("token-A")
    pk2, _ = provider.rotate("token-A")
    assert pk1 != pk2


def test_governance_fingerprint_shape():
    fp = governance_fingerprint(GOVERNANCE)
    assert set(fp.keys()) == {"const", "A", "B", "AB", "C", "AC", "BC", "ABC"}


def test_stok_protect_open_roundtrip(tmp_path):
    from smart_token_prod.stok import protect_file, open_stok, friction_status

    sample = tmp_path / "pieza.stl"
    sample.write_bytes(b"solid demo\nendsolid demo\n")
    master = b"test-master-key"
    stok_path, key_path = protect_file(
        sample, master_secret=master, tarpit_mode="off", tarpit_seconds=0.0, friction_backend="python"
    )
    assert friction_status(stok_path)["has_embedded_sk"] is False
    assert friction_status(stok_path)["cumulative_iters"] == 0

    out = tmp_path / "pieza_out.stl"
    pt, info = open_stok(
        stok_path, master_secret=master, key_path=key_path,
        output_path=out, update_friction=True,
    )
    assert pt == sample.read_bytes()
    assert info["status"] == "OPEN"
    assert out.read_bytes() == sample.read_bytes()


def test_stok_phases_escalate_silently_in_snapshot(tmp_path):
    from smart_token_prod.stok import protect_file, open_stok, friction_status

    sample = tmp_path / "b.stl"
    sample.write_bytes(b"payload")
    master = b"correct"
    stok_path, key_path = protect_file(
        sample, master_secret=master, tarpit_mode="off", tarpit_seconds=0.0, friction_backend="python"
    )

    _, info = open_stok(stok_path, master_secret=b"wrong", key_path=key_path, reveal_friction=True)
    assert info["status"] == "DENIED"
    assert info["work_factor_paid"] == 1
    assert info["hash_iters_paid"] == 10_000
    assert info["friction_state"]["cumulative_iters"] == 10_000
    assert info["friction_state"]["recovery_tier"] == 0
    assert info["friction_state"]["flag_fibonacci"] is True

    _, info = open_stok(stok_path, master_secret=b"wrong2", key_path=key_path, reveal_friction=True)
    assert info["status"] == "DENIED"
    assert info["friction_state"]["cumulative_iters"] == 20_000
    assert info["friction_state"]["recovery_tier"] == 1
    assert info["friction_state"]["flag_persistencia"] is True

    _, info = open_stok(stok_path, master_secret=b"wrong3", key_path=key_path, reveal_friction=True)
    assert info["status"] == "DENIED"
    assert info["friction_state"]["cumulative_iters"] == 30_000
    assert info["friction_state"]["recovery_tier"] == 2
    assert info["friction_state"]["fail_count"] == 3
    assert info["friction_state"]["tarpit_triggered"] is True
    assert friction_status(stok_path)["cumulative_iters"] == 30_000


def test_stok_one_correct_after_tier3_opens(tmp_path):
    from smart_token_prod.stok import protect_file, open_stok, friction_status

    sample = tmp_path / "c.stl"
    sample.write_bytes(b"secret-bytes-xyz")
    master = b"master-ok"
    stok_path, key_path = protect_file(
        sample, master_secret=master, tarpit_mode="off", tarpit_seconds=0.0, friction_backend="python"
    )
    out = tmp_path / "out.stl"

    for i in range(4):
        pt, info = open_stok(
            stok_path, master_secret=b"bad-" + str(i).encode(), key_path=key_path
        )
        assert pt is None and info["status"] == "DENIED"

    assert friction_status(stok_path)["recovery_tier"] == 3
    assert friction_status(stok_path)["cumulative_iters"] == 40_000
    assert stok_path.exists()  # never destroyed

    denied = 0
    pt, info = None, {}
    for _ in range(4):
        pt, info = open_stok(
            stok_path, master_secret=master, key_path=key_path,
            output_path=out, update_friction=True,
        )
        if info["status"] == "OPEN":
            break
        denied += 1
        assert pt is None
    assert denied == 3
    assert info["status"] == "OPEN"
    assert info["work_factor_paid"] == 1
    assert pt == sample.read_bytes()
    assert out.read_bytes() == sample.read_bytes()
    assert friction_status(stok_path)["recovery_tier"] == 0
    assert friction_status(stok_path)["cumulative_iters"] == 0
    assert friction_status(stok_path)["friction_snapshot"]["fail_count"] == 0


def test_stok_no_auth_partial_status(tmp_path):
    from smart_token_prod.stok import protect_file, open_stok

    sample = tmp_path / "d.stl"
    sample.write_bytes(b"payload-d")
    master = b"master-d"
    stok_path, key_path = protect_file(
        sample, master_secret=master, tarpit_mode="off", tarpit_seconds=0.0, friction_backend="python"
    )
    open_stok(stok_path, master_secret=b"w1", key_path=key_path)
    open_stok(stok_path, master_secret=b"w2", key_path=key_path)
    # 2 fails → 3 correct validations required
    for _ in range(2):
        pt, info = open_stok(stok_path, master_secret=master, key_path=key_path)
        assert info["status"] == "DENIED" and pt is None
    pt, info = open_stok(stok_path, master_secret=master, key_path=key_path)
    assert info["status"] == "OPEN"
    assert pt == b"payload-d"
    assert info["status"] != "AUTH_PARTIAL"


def test_stok_persistence_across_reopen(tmp_path):
    from smart_token_prod.stok import protect_file, open_stok, friction_status, read_stok

    sample = tmp_path / "e.stl"
    sample.write_bytes(b"persist-me")
    master = b"master-e"
    stok_path, key_path = protect_file(
        sample, master_secret=master, tarpit_mode="off", tarpit_seconds=0.0, friction_backend="python"
    )
    open_stok(stok_path, master_secret=b"bad", key_path=key_path)
    open_stok(stok_path, master_secret=b"bad2", key_path=key_path)
    open_stok(stok_path, master_secret=b"bad3", key_path=key_path)
    open_stok(stok_path, master_secret=b"bad4", key_path=key_path)

    stok = read_stok(stok_path)
    assert stok.friction_snapshot["cumulative_iters"] == 40_000
    assert stok.friction_snapshot["fail_count"] == 4
    assert stok.friction_snapshot["recovery_tier"] == 3
    assert friction_status(stok_path)["recovery_tier"] == 3

    for _ in range(3):
        pt, info = open_stok(stok_path, master_secret=master, key_path=key_path)
        assert info["status"] == "DENIED"
    pt, info = open_stok(stok_path, master_secret=master, key_path=key_path)
    assert info["status"] == "OPEN"
    assert info["work_factor_paid"] == 1
    assert pt == b"persist-me"


def test_stok_without_key_fails(tmp_path):
    from smart_token_prod.stok import protect_file, open_stok

    sample = tmp_path / "x.stl"
    sample.write_bytes(b"payload")
    stok_path, key_path = protect_file(
        sample, master_secret=b"m", tarpit_mode="off", tarpit_seconds=0.0, friction_backend="python"
    )
    key_path.unlink()
    pt, info = open_stok(stok_path, master_secret=b"m", update_friction=True)
    assert pt is None
    assert info["status"] == "DENIED"
    # Opaque by default — no mlkem_error / friction_state oracle
    assert "mlkem_error" not in info
    assert "friction_state" not in info
    pt2, info2 = open_stok(
        stok_path, master_secret=b"m", update_friction=True, reveal_friction=True
    )
    assert pt2 is None and info2["status"] == "DENIED"
    assert "sk no disponible" in (info2.get("mlkem_error") or "")


def test_stok_no_wall_tarpit_before_phase3_hang(tmp_path):
    """Before fail_count≥3 hang, fail at fc=2 must not burn ~1.5s wall fib."""
    from smart_token_prod.stok import protect_file, open_stok

    sample = tmp_path / "fast.stl"
    sample.write_bytes(b"payload-fast")
    master = b"master-fast"
    stok_path, key_path = protect_file(
        sample, master_secret=master, tarpit_mode="off", tarpit_seconds=0.0, friction_backend="python"
    )
    for i in range(2):
        open_stok(stok_path, master_secret=b"bad-" + str(i).encode(), key_path=key_path)
    t0 = time.perf_counter()
    open_stok(stok_path, master_secret=b"bad-phase3-entry", key_path=key_path)
    elapsed = time.perf_counter() - t0
    # Fast Argon2 + 10k SHA; hang disabled by fixture; no ~1.5s fib wall
    assert elapsed < 1.0


def _hang_worker(stok_path: str, key_path: str, master_wrong: bytes, ready_q):
    """Child process: enable hang, wrong open at fail_count≥3 — must not return."""
    os.environ["SMART_TOKEN_PHASE3_HANG"] = "1"
    from smart_token_prod import stok as sm
    # Clear test overrides if any; force hang ON and fast argon2
    sm.open_stok._argon2_time_cost = 1
    sm.open_stok._argon2_memory_cost = 8 * 1024
    sm.open_stok._phase3_hang = True
    ready_q.put("starting")
    sm.open_stok(
        stok_path,
        master_secret=master_wrong,
        key_path=key_path,
        update_friction=True,
    )
    ready_q.put("RETURNED")  # must never happen


def test_wrong_open_at_tier3_hangs_in_subprocess(tmp_path):
    """
    Wrong open at fail_count≥3: process stays alive/busy and does not return
    success within ~2–3s (assert hang).
    """
    from smart_token_prod.stok import protect_file, open_stok, friction_status, read_stok

    sample = tmp_path / "hang.stl"
    sample.write_bytes(b"hang-payload")
    master = b"master-hang"
    stok_path, key_path = protect_file(
        sample, master_secret=master, tarpit_mode="off", tarpit_seconds=0.0, friction_backend="python"
    )
    # Two fails in parent (hang off). Third fail in child engages ∞ trap.
    for i in range(2):
        open_stok(stok_path, master_secret=b"bad-" + str(i).encode(), key_path=key_path)
    assert friction_status(stok_path)["friction_snapshot"]["fail_count"] == 2
    assert stok_path.exists()

    ready = multiprocessing.Queue()
    proc = multiprocessing.Process(
        target=_hang_worker,
        args=(str(stok_path), str(key_path), b"still-wrong", ready),
    )
    proc.start()
    try:
        assert ready.get(timeout=10) == "starting"
        proc.join(timeout=2.5)
        assert proc.is_alive(), "expected phase-3 hang: process should still be busy"
        # Must not have returned successfully
        assert ready.empty() or ready.get_nowait() != "RETURNED"
    finally:
        if proc.is_alive():
            proc.terminate()
            proc.join(timeout=5)
        if proc.is_alive():
            proc.kill()
            proc.join(timeout=2)

    # Castigated .stok still present after kill
    assert stok_path.exists()
    snap = read_stok(stok_path).friction_snapshot
    assert int(snap.get("fail_count", 0)) == 3


def test_cli_denied_is_opaque(tmp_path, capsys):
    """CLI open on wrong master must not print tier/fail_count/work_factor."""
    from smart_token_prod.stok import protect_file
    from smart_token_prod.cli import main

    sample = tmp_path / "cli.stl"
    sample.write_bytes(b"cli-payload")
    master = b"cli-master"
    stok_path, key_path = protect_file(
        sample, master_secret=master, tarpit_mode="off", tarpit_seconds=0.0, friction_backend="python"
    )
    rc = main([
        "open", str(stok_path),
        "--master", "wrong-password",
        "--key", str(key_path),
        "--backend", "python",
        "--tarpit-mode", "off",
    ])
    assert rc == 1
    out = capsys.readouterr().out
    assert "DENIED" in out
    assert "recovery_tier" not in out
    assert "fail_count" not in out
    assert "work_factor" not in out
    assert "flag_fibonacci" not in out
    assert "Coherencia" not in out


def test_work_factor_helpers_unit():
    from smart_token_prod.recovery import (
        apply_failure_to_snapshot,
        work_factor_for_tier,
        tier_for_fail_count,
        tier_for_cumulative_iters,
        pay_work_factor,
        ITERS_PER_ATTEMPT,
        JUMP_EVERY,
        MAX_TIER,
        phase3_hang_enabled,
    )

    assert ITERS_PER_ATTEMPT == 10_000
    assert JUMP_EVERY == 11_000
    assert MAX_TIER == 3
    assert tier_for_cumulative_iters(10_000) == 0
    assert tier_for_cumulative_iters(11_000) == 1
    assert tier_for_cumulative_iters(20_000) == 1
    assert tier_for_cumulative_iters(22_000) == 2
    assert tier_for_cumulative_iters(33_000) == 3
    assert tier_for_cumulative_iters(99_000) == 3
    assert tier_for_fail_count(1) == 0
    assert tier_for_fail_count(2) == 1
    assert work_factor_for_tier(3) == 1
    assert phase3_hang_enabled() is True  # default product ON (env not set to 0)

    s = apply_failure_to_snapshot({"fail_count": 1})
    assert s["cumulative_iters"] == 10_000 and s["recovery_tier"] == 0
    s = apply_failure_to_snapshot({"fail_count": 2, "cumulative_iters": 10_000})
    assert s["cumulative_iters"] == 20_000 and s["recovery_tier"] == 1
    s2 = apply_failure_to_snapshot(dict(s))
    assert s2["cumulative_iters"] == 20_000

    t0 = time.perf_counter()
    out = pay_work_factor(
        stok_id="abc", master_secret=b"m", work_factor=1,
        time_cost=1, memory_cost=8 * 1024, hash_iters=100,
    )
    elapsed = time.perf_counter() - t0
    assert isinstance(out, bytes) and len(out) == 32
    assert elapsed >= 0.0


def test_off_mode_skips_cpu_burn():
    from smart_token_prod.core import SequentialTarpit

    key = hashlib.sha256(b"k").digest()
    t = SequentialTarpit(key, "off", 0.0)
    t.register_failure()
    t.register_failure()
    t0 = time.perf_counter()
    info = t.register_failure()
    assert time.perf_counter() - t0 < 0.2
    assert info["action"] == "tarpit_labels_only"
    assert t.snapshot()["tarpit_triggered"] is True


def test_sk_alone_cannot_derive_aes_key():
    """Binding v2: ss without master_km must not yield the payload key."""
    from smart_token_prod.core import derive_aes_key
    with pytest.raises(ValueError):
        derive_aes_key(b"\x00" * 32, b"")


def test_wrong_master_cannot_decrypt_even_with_sk(tmp_path):
    from smart_token_prod.stok import protect_file, open_stok, read_stok
    from smart_token_prod.core import derive_aes_key, aes_gcm_decrypt, mlkem_decaps
    from smart_token_prod.recovery import pay_work_factor, compute_stok_id

    sample = tmp_path / "bind.stl"
    sample.write_bytes(b"bound-payload")
    master = b"correct-master"
    stok_path, key_path = protect_file(
        sample, master_secret=master, tarpit_mode="off", tarpit_seconds=0.0, friction_backend="python"
    )
    stok = read_stok(stok_path)
    assert stok.binding_version >= 2
    assert not stok.salt and not stok.material
    assert stok.kdf_params.get("time_cost")
    assert stok.friction_mac

    sk = stok_mod.read_key_file(key_path) if hasattr(stok_mod, "read_key_file") else None
    from smart_token_prod.stok import read_key_file
    sk = read_key_file(key_path)
    ss = mlkem_decaps(sk, stok.ct)
    kp = stok.kdf_params
    wrong_km = pay_work_factor(
        stok_id=compute_stok_id(stok.pk, stok.ct, stok.public_label),
        master_secret=b"wrong-master",
        time_cost=int(kp["time_cost"]),
        memory_cost=int(kp["memory_cost"]),
        parallelism=int(kp.get("parallelism", 1)),
        hash_iters=10_000,
    )
    wrong_key = derive_aes_key(ss, wrong_km)
    with pytest.raises(Exception):
        aes_gcm_decrypt(wrong_key, stok.nonce, stok.ciphertext, stok.aad)

    pt, info = open_stok(stok_path, master_secret=b"wrong-master", key_path=key_path)
    assert pt is None and info["status"] == "DENIED"
    pt, info = open_stok(stok_path, master_secret=master, key_path=key_path)
    assert pt is None and info["status"] == "DENIED"
    pt, info = open_stok(stok_path, master_secret=master, key_path=key_path)
    assert pt == b"bound-payload" and info["status"] == "OPEN"


def test_v2_stok_has_no_offline_master_oracle(tmp_path):
    from smart_token_prod.stok import protect_file, read_stok

    sample = tmp_path / "oracle.stl"
    sample.write_bytes(b"x")
    stok_path, _ = protect_file(
        sample, master_secret=b"secret-human", tarpit_mode="off", friction_backend="python"
    )
    raw = read_stok(stok_path)
    assert raw.salt == b""
    assert raw.material == b""
    body = stok_path.read_bytes()
    assert b"secret-human" not in body


def test_validation_ladder_1_2_3_fails(tmp_path):
    """1 fail→2 oks; 2 fails→3 oks; 3 fails→4 oks. Deny stays opaque."""
    from smart_token_prod.stok import protect_file, open_stok
    from smart_token_prod.cli import main

    sample = tmp_path / "ladder.stl"
    sample.write_bytes(b"ladder-payload")
    master = b"ladder-master"
    stok_path, key_path = protect_file(
        sample, master_secret=master, tarpit_mode="off", friction_backend="python"
    )

    def deny_wrong():
        pt, info = open_stok(stok_path, master_secret=b"nope", key_path=key_path)
        assert pt is None and info["status"] == "DENIED"

    def try_ok():
        return open_stok(stok_path, master_secret=master, key_path=key_path)

    deny_wrong()
    pt, info = try_ok()
    assert info["status"] == "DENIED" and pt is None
    pt, info = try_ok()
    assert info["status"] == "OPEN" and pt == b"ladder-payload"

    deny_wrong()
    deny_wrong()
    assert try_ok()[1]["status"] == "DENIED"
    assert try_ok()[1]["status"] == "DENIED"
    pt, info = try_ok()
    assert info["status"] == "OPEN" and pt == b"ladder-payload"

    for _ in range(3):
        deny_wrong()
    for _ in range(3):
        assert try_ok()[1]["status"] == "DENIED"
    pt, info = try_ok()
    assert info["status"] == "OPEN" and pt == b"ladder-payload"

    rc = main([
        "open", str(stok_path), "--master", "wrong", "--key", str(key_path),
        "--backend", "python", "--tarpit-mode", "off",
    ])
    assert rc == 1


# ---------------------------------------------------------------------------
# v0.10.0 — A1 fail-closed friction MAC + A2 opaque API deny + D1 CLI master
# ---------------------------------------------------------------------------


def _bitflip_friction_mac(stok_path):
    """Flip one bit in friction_mac inside the on-disk .stok JSON body."""
    from smart_token_prod.stok import read_stok, write_stok
    import base64

    stok = read_stok(stok_path)
    assert stok.friction_mac and len(stok.friction_mac) >= 1
    b = bytearray(stok.friction_mac)
    b[0] ^= 0x01
    stok.friction_mac = bytes(b)
    write_stok(stok, stok_path)
    return stok


def test_a1_mac_tamper_does_not_grant_free_open(tmp_path):
    """After N wrong opens, bit-flip friction_mac → correct master must NOT free OPEN."""
    from smart_token_prod.stok import protect_file, open_stok, friction_status, read_stok

    sample = tmp_path / "a1.stl"
    sample.write_bytes(b"a1-payload-secret")
    master = b"a1-master"
    stok_path, key_path = protect_file(
        sample, master_secret=master, tarpit_mode="off", friction_backend="python"
    )
    for i in range(3):
        pt, info = open_stok(
            stok_path, master_secret=b"bad-" + str(i).encode(), key_path=key_path,
            reveal_friction=True,
        )
        assert pt is None and info["status"] == "DENIED"

    before = friction_status(stok_path)["friction_snapshot"]
    assert int(before["fail_count"]) == 3
    debt_fc = int(before["fail_count"])
    debt_cum = int(before["cumulative_iters"])

    _bitflip_friction_mac(stok_path)
    # Correct master must NOT wipe trap / free OPEN
    for _ in range(5):
        pt, info = open_stok(
            stok_path, master_secret=master, key_path=key_path, reveal_friction=True
        )
        assert pt is None
        assert info["status"] == "DENIED"
        assert info.get("friction_mac_ok") is False

    after = read_stok(stok_path)
    # Disk bytes for friction debt must remain (not cleared to {})
    assert int(after.friction_snapshot.get("fail_count", 0)) == debt_fc
    assert int(after.friction_snapshot.get("cumulative_iters", 0)) == debt_cum
    assert after.friction_snapshot != {}


def test_a1_open_without_key_does_not_erase_trap(tmp_path):
    """open without sk must not mutate friction / strip punishment for later keyed open."""
    from smart_token_prod.stok import protect_file, open_stok, friction_status, read_stok

    sample = tmp_path / "nokey.stl"
    sample.write_bytes(b"trap-payload")
    master = b"nokey-master"
    stok_path, key_path = protect_file(
        sample, master_secret=master, tarpit_mode="off", friction_backend="python"
    )
    for i in range(2):
        open_stok(stok_path, master_secret=b"w" + str(i).encode(), key_path=key_path)
    snap_before = dict(read_stok(stok_path).friction_snapshot)
    mac_before = read_stok(stok_path).friction_mac
    assert int(snap_before["fail_count"]) == 2

    # Move key away and open without sk
    relocated = tmp_path / "hidden.key"
    relocated.write_bytes(key_path.read_bytes())
    key_path.unlink()
    pt, info = open_stok(stok_path, master_secret=master, update_friction=True)
    assert pt is None and info["status"] == "DENIED"

    stok_mid = read_stok(stok_path)
    assert stok_mid.friction_snapshot == snap_before
    assert stok_mid.friction_mac == mac_before

    # Restore key — ladder still requires 3 correct validations (2 fails → need 3)
    key_path.write_bytes(relocated.read_bytes())
    assert friction_status(stok_path)["friction_snapshot"]["fail_count"] == 2
    statuses = []
    for _ in range(3):
        pt, info = open_stok(stok_path, master_secret=master, key_path=key_path)
        statuses.append(info["status"])
    assert statuses == ["DENIED", "DENIED", "OPEN"]
    assert pt == b"trap-payload"


def test_api_denied_is_opaque_by_default(tmp_path):
    """API DENIED must not leak fail_count / tier / work_factor / friction_state."""
    from smart_token_prod.stok import protect_file, open_stok
    from smart_token_prod.sdk import open_artifact

    sample = tmp_path / "opaque.stl"
    sample.write_bytes(b"opaque-payload")
    master = b"opaque-master"
    stok_path, key_path = protect_file(
        sample, master_secret=master, tarpit_mode="off", friction_backend="python"
    )
    pt, info = open_stok(stok_path, master_secret=b"wrong", key_path=key_path)
    assert pt is None and info["status"] == "DENIED"
    for k in (
        "fail_count", "recovery_tier", "work_factor", "cumulative_iters",
        "friction_state", "friction_before", "friction",
    ):
        assert k not in info, f"opaque leak: {k}"

    pt2, info2 = open_artifact(stok_path, master_secret=b"wrong", key_path=key_path)
    assert pt2 is None and info2["status"] == "DENIED"
    assert "friction_state" not in info2
    assert "recovery_tier" not in info2

    # Owner opt-in
    _, rich = open_stok(
        stok_path, master_secret=b"wrong2", key_path=key_path, reveal_friction=True
    )
    assert rich["status"] == "DENIED"
    assert "friction_state" in rich
    assert rich["friction_state"]["fail_count"] >= 1


def test_cli_protect_open_require_master(tmp_path, capsys):
    """D1: protect/open require --master or SMART_TOKEN_MASTER (no silent demo default)."""
    import os
    from smart_token_prod.cli import main

    sample = tmp_path / "need.stl"
    sample.write_bytes(b"x")
    os.environ.pop("SMART_TOKEN_MASTER", None)
    rc = main(["protect", str(sample), "--backend", "python", "--tarpit-mode", "off"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "SMART_TOKEN_MASTER" in err or "--master" in err


# ---------------------------------------------------------------------------
# v0.10.1 — cycle-1 adversarial: store≻disk MAC, lock unlink, repair-mac
# ---------------------------------------------------------------------------


def test_store_harsher_than_disk_does_not_break_mac(tmp_path):
    """MAC must be checked on disk snapshot; harsher store must not fail-closed DoS."""
    import os
    from smart_token_prod.stok import protect_file, open_stok, read_stok
    from smart_token_prod.persistence import FileFrictionStore
    from smart_token_prod.recovery import compute_stok_id

    sample = tmp_path / "storemac.stl"
    sample.write_bytes(b"store-mac-payload")
    master = b"store-mac-master"
    stok_path, key_path = protect_file(
        sample, master_secret=master, tarpit_mode="off", friction_backend="python"
    )
    fric = tmp_path / "fric"
    fric.mkdir()
    os.environ["SMART_TOKEN_FRICTION_DIR"] = str(fric)
    try:
        open_stok(stok_path, master_secret=b"wrong", key_path=key_path)
        st = read_stok(stok_path)
        assert int(st.friction_snapshot["fail_count"]) == 1
        sid = compute_stok_id(st.pk, st.ct, st.public_label)
        poison = dict(st.friction_snapshot)
        poison["fail_count"] = 5
        poison["cumulative_iters"] = 50_000
        poison["recovery_tier"] = 3
        FileFrictionStore(fric).save(sid, poison)

        # Correct master must NOT be blocked by friction_mac_invalid
        statuses = []
        last_pt = None
        for _ in range(4):  # fc=5 → need 4 validations
            pt, info = open_stok(
                stok_path, master_secret=master, key_path=key_path, reveal_friction=True
            )
            assert info.get("friction_mac_ok") is not False
            assert info.get("integrity_error") != "friction_mac_invalid"
            statuses.append(info["status"])
            last_pt = pt
        assert statuses[-1] == "OPEN"
        assert last_pt == b"store-mac-payload"
    finally:
        os.environ.pop("SMART_TOKEN_FRICTION_DIR", None)


def test_exclusive_stok_survives_sidecar_unlink(tmp_path):
    """Unlinking a legacy sidecar .lock must not bypass inode flock."""
    import threading
    import time
    from smart_token_prod.stok import protect_file, exclusive_stok

    sample = tmp_path / "lock.stl"
    sample.write_bytes(b"lock")
    stok_path, _ = protect_file(
        sample, master_secret=b"m", tarpit_mode="off", friction_backend="python"
    )
    # Create legacy sidecar to prove unlink is irrelevant
    sidecar = Path(str(stok_path) + ".lock")
    sidecar.write_bytes(b"x")
    events = []

    def holder():
        with exclusive_stok(stok_path):
            events.append("held")
            time.sleep(0.5)
            events.append("released")

    def attacker():
        time.sleep(0.05)
        if sidecar.exists():
            sidecar.unlink()
            events.append("unlinked")
        t0 = time.time()
        with exclusive_stok(stok_path):
            waited = time.time() - t0
            events.append(("entered", round(waited, 3), "released" in events))

    th = threading.Thread(target=holder)
    ta = threading.Thread(target=attacker)
    th.start(); ta.start(); th.join(); ta.join()
    entered = [e for e in events if isinstance(e, tuple) and e[0] == "entered"][0]
    assert entered[1] >= 0.3, f"expected wait for inode lock, got {events}"
    assert entered[2] is True, f"entered before holder released: {events}"


def test_repair_mac_restores_open_without_clearing_debt(tmp_path):
    """After MAC bit-flip, repair-mac re-signs; ladder debt remains; OPEN needs validations."""
    from smart_token_prod.stok import (
        protect_file, open_stok, friction_status, repair_friction_mac, read_stok,
    )

    sample = tmp_path / "repair.stl"
    sample.write_bytes(b"repair-payload")
    master = b"repair-master"
    stok_path, key_path = protect_file(
        sample, master_secret=master, tarpit_mode="off", friction_backend="python"
    )
    for i in range(2):
        open_stok(stok_path, master_secret=b"bad" + bytes([i]), key_path=key_path)
    assert friction_status(stok_path)["friction_snapshot"]["fail_count"] == 2

    # Tamper MAC → fail-closed
    st = read_stok(stok_path)
    b = bytearray(st.friction_mac); b[0] ^= 0x01; st.friction_mac = bytes(b)
    from smart_token_prod.stok import write_stok
    write_stok(st, stok_path)
    pt, info = open_stok(stok_path, master_secret=master, key_path=key_path, reveal_friction=True)
    assert pt is None and info.get("friction_mac_ok") is False

    info_r = repair_friction_mac(stok_path, key_path=key_path)
    assert info_r["status"] == "REPAIRED"
    assert info_r["fail_count"] == 2

    statuses = []
    for _ in range(3):
        pt, info = open_stok(stok_path, master_secret=master, key_path=key_path)
        statuses.append(info["status"])
    assert statuses == ["DENIED", "DENIED", "OPEN"]
    assert pt == b"repair-payload"


def test_opaque_deny_has_no_oracle_channels(tmp_path):
    """DENIED opaque surface must not leak integrity/mlkem/aes oracles either."""
    from smart_token_prod.stok import protect_file, open_stok, _OPAQUE_DENY_KEYS

    sample = tmp_path / "oracle.stl"
    sample.write_bytes(b"o")
    master = b"oracle-m"
    stok_path, key_path = protect_file(
        sample, master_secret=master, tarpit_mode="off", friction_backend="python"
    )
    _, info = open_stok(stok_path, master_secret=b"wrong", key_path=key_path)
    assert set(info.keys()) <= set(_OPAQUE_DENY_KEYS)
    for banned in (
        "mlkem_ok", "mlkem_error", "aes_error", "integrity_error",
        "friction_mac_ok", "friction_before", "recoverable",
    ):
        assert banned not in info


# ---------------------------------------------------------------------------
# v0.10.2 — cycle-2 adversarial: R1 inode replace, R2 in-memory opaque, R3 hang BP
# ---------------------------------------------------------------------------


def test_r1_stok_unlink_recreate_fails_closed_under_lock(tmp_path):
    """Unlink+recreate .stok under exclusive_stok → new inode → fail-closed on write."""
    import os
    import threading
    import time
    from smart_token_prod.stok import protect_file, exclusive_stok, read_stok, write_stok

    sample = tmp_path / "r1.stl"
    sample.write_bytes(b"r1-payload")
    stok_path, _ = protect_file(
        sample, master_secret=b"r1-m", tarpit_mode="off", friction_backend="python"
    )
    st0 = os.stat(stok_path)
    events = []

    def holder():
        with exclusive_stok(stok_path) as lock:
            events.append(("held", lock.inode_tuple()))
            time.sleep(0.35)
            try:
                s = read_stok(stok_path, lock=lock)
                s.friction_snapshot = dict(s.friction_snapshot or {})
                s.friction_snapshot["fail_count"] = 99
                write_stok(s, stok_path, lock=lock)
                events.append("write_ok_unexpected")
            except RuntimeError as e:
                msg = str(e).lower()
                events.append(("write_fail", ("inode" in msg or "replaced" in msg or "unlinked" in msg)))

    def attacker():
        time.sleep(0.05)
        raw = stok_path.read_bytes()
        stok_path.unlink()
        stok_path.write_bytes(raw)  # new inode at same path
        st1 = os.stat(stok_path)
        events.append(("replaced", (st0.st_dev, st0.st_ino) != (st1.st_dev, st1.st_ino)))

    th = threading.Thread(target=holder)
    ta = threading.Thread(target=attacker)
    th.start(); ta.start(); th.join(); ta.join()
    assert any(isinstance(e, tuple) and e[0] == "replaced" and e[1] for e in events), events
    assert any(isinstance(e, tuple) and e[0] == "write_fail" and e[1] for e in events), events
    assert "write_ok_unexpected" not in events


def test_r1_concurrent_open_stok_still_serialized(tmp_path):
    """Without unlink, two open_stok writers serialize on the same inode."""
    import threading
    import time
    from smart_token_prod.stok import protect_file, open_stok, friction_status

    sample = tmp_path / "ser.stl"
    sample.write_bytes(b"ser")
    master = b"ser-m"
    stok_path, key_path = protect_file(
        sample, master_secret=master, tarpit_mode="off", friction_backend="python"
    )
    barrier = threading.Barrier(2)
    order = []

    def worker(tag):
        barrier.wait()
        open_stok(stok_path, master_secret=b"bad-" + tag.encode(), key_path=key_path)
        order.append(tag)

    t1 = threading.Thread(target=worker, args=("a",))
    t2 = threading.Thread(target=worker, args=("b",))
    t1.start(); t2.start(); t1.join(); t2.join()
    assert len(order) == 2
    assert friction_status(stok_path)["friction_snapshot"]["fail_count"] == 2


def test_r2_smarttokenprod_open_denied_opaque_by_default():
    """In-memory SmartTokenProd.open must not oracle ladder details on DENIED."""
    tok = SmartTokenProd(
        GOVERNANCE, b"opaque-mem", b"master",
        tarpit_mode="off", friction_backend="python",
    )
    pt, info = tok.open(force_failure=True)
    assert pt is None and info["status"] == "DENIED"
    for k in (
        "fail_count", "recovery_tier", "work_factor", "cumulative_iters",
        "friction_state", "friction", "recoverable", "mlkem_ok", "aes_gcm_ok",
    ):
        assert k not in info, f"in-memory opaque leak: {k}"
    assert set(info.keys()) <= {
        "path", "status", "binding_version", "work_factor_paid", "hash_iters_paid",
    }

    _, rich = tok.open(force_failure=True, reveal_friction=True)
    assert "friction_state" in rich
    assert rich["friction_state"]["fail_count"] >= 1


def test_r3_hang_backpressure_skips_extra_grind(tmp_path):
    """When process-local hang slots are full, open_stok DENIED returns without hanging."""
    import time
    from smart_token_prod.stok import protect_file, open_stok
    from smart_token_prod.recovery import (
        try_acquire_hang_slot,
        release_hang_slot,
        reset_hang_backpressure_for_tests,
        hang_slots_available,
    )

    os.environ["SMART_TOKEN_MAX_CONCURRENT_HANGS"] = "1"
    reset_hang_backpressure_for_tests()
    assert try_acquire_hang_slot() is True
    assert hang_slots_available() == 0
    assert try_acquire_hang_slot() is False

    sample = tmp_path / "hangbp.stl"
    sample.write_bytes(b"hangbp")
    master = b"hangbp-m"
    stok_path, key_path = protect_file(
        sample, master_secret=master, tarpit_mode="off", friction_backend="python"
    )
    # Two fails with hang off (fixture); third wrong with hang ON should try hang then skip
    open_stok(stok_path, master_secret=b"w1", key_path=key_path)
    open_stok(stok_path, master_secret=b"w2", key_path=key_path)
    stok_mod.open_stok._phase3_hang = True
    t0 = time.time()
    pt, info = open_stok(stok_path, master_secret=b"w3", key_path=key_path)
    elapsed = time.time() - t0
    assert pt is None and info["status"] == "DENIED"
    assert elapsed < 1.5, f"expected skip hang under backpressure, took {elapsed:.2f}s"
    release_hang_slot()
    reset_hang_backpressure_for_tests()


def test_version_is_0103():
    from smart_token_prod import __version__
    assert __version__ == "0.10.3"


def test_r1_open_stok_inode_race_returns_opaque_denied(tmp_path):
    """Path replace mid-open must not crash the API — opaque DENIED fail-closed."""
    import os
    import threading
    import time
    from smart_token_prod.stok import protect_file, open_stok, exclusive_stok

    sample = tmp_path / "race.stl"
    sample.write_bytes(b"race")
    master = b"race-m"
    stok_path, key_path = protect_file(
        sample, master_secret=master, tarpit_mode="off", friction_backend="python"
    )
    results = []

    def slow_holder():
        # Hold lock so open_stok blocks, then replace path before release
        with exclusive_stok(stok_path) as lock:
            time.sleep(0.05)
            raw = lock.read_all()
            # Replace path while we still hold old inode
            stok_path.unlink()
            stok_path.write_bytes(raw)
            time.sleep(0.2)

    def opener():
        time.sleep(0.02)
        try:
            pt, info = open_stok(stok_path, master_secret=b"wrong", key_path=key_path)
            results.append((pt, info))
        except Exception as e:
            results.append(("EXC", type(e).__name__, str(e)))

    th = threading.Thread(target=slow_holder)
    to = threading.Thread(target=opener)
    th.start(); to.start(); th.join(); to.join()
    assert results, "opener produced no result"
    # Either waited and opened the NEW inode (DENIED normal) or hit race → DENIED
    r = results[0]
    assert r[0] != "EXC", f"API must not crash on inode race: {r}"
    pt, info = r
    assert pt is None and info.get("status") == "DENIED"
    assert "friction_state" not in info
