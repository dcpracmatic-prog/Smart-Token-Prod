"""Regression tests for v0.10.3: the AAD is rebound to the on-disk public_label.

Before this fix the AEAD associated data was derived from ``public_label`` at
protect time but read back verbatim from the ``.stok`` at open time. Both fields
live in the same untrusted header, so rewriting ``public_label`` while leaving
``aad`` alone produced an artifact that opened with ``status=OPEN`` and no
integrity signal whatsoever.
"""
from __future__ import annotations

import pytest

# NB: deliberately no SMART_TOKEN_PHASE3_HANG override here. Setting it at import
# time leaks into the whole pytest process and breaks
# test_work_factor_helpers_unit, which asserts the grind is ON by default. Every
# open below passes update_friction=False, so fail_count never reaches the
# threshold and the non-returning grind is never entered.

from smart_token_prod import protect_file, open_stok, read_stok, write_stok
from smart_token_prod.core import AAD_SUFFIX, expected_aad

MASTER = b"master-secret-with-plenty-of-entropy"
PAYLOAD = b"payload-that-must-not-leak"


@pytest.fixture()
def artifact(tmp_path):
    src = tmp_path / "plain.bin"
    src.write_bytes(PAYLOAD)
    stok_path, key_path = protect_file(
        src,
        output_path=tmp_path / "plain.stok",
        master_secret=MASTER,
        key_path=tmp_path / "plain.key",
    )
    return stok_path, key_path


def _open(stok_path, key_path):
    return open_stok(
        stok_path,
        master_secret=MASTER,
        key_path=key_path,
        update_friction=False,
    )


def test_expected_aad_is_deterministic_and_label_bound():
    assert expected_aad(b"LABEL") == b"LABEL" + AAD_SUFFIX
    assert expected_aad(b"LABEL") != expected_aad(b"LABEr")
    with pytest.raises(TypeError):
        expected_aad("not-bytes")  # type: ignore[arg-type]


def test_legitimate_open_still_works(artifact):
    """Guard against the fix breaking the happy path."""
    plaintext, info = _open(*artifact)
    assert plaintext == PAYLOAD
    assert info.get("aes_gcm_ok") is True
    # Untampered artifact: stored and recomputed AAD agree, so no rebind flag.
    assert info.get("aad_rebound") is not True


def test_stored_aad_matches_the_derivation(artifact):
    """The persisted aad is descriptive, but it should still be the real value."""
    stok_path, _ = artifact
    stok = read_stok(stok_path)
    assert stok.aad == expected_aad(stok.public_label)


def test_forged_public_label_fails_closed(artifact):
    """The regression itself: forging the label must not yield plaintext."""
    stok_path, key_path = artifact
    stok = read_stok(stok_path)
    stok.public_label = b"FORGED-LABEL"
    write_stok(stok, stok_path)

    plaintext, info = _open(stok_path, key_path)

    assert plaintext is None, "forged public_label must not decrypt"
    # DENIED is opaque by contract since v0.10.2, so aes_gcm_ok / aad_rebound are
    # stripped from the caller-visible info. The absence of plaintext plus the
    # DENIED status is the whole observable, and that is the point.
    assert info.get("status") == "DENIED"


def test_forged_label_and_matching_aad_still_fails_closed(artifact):
    """An attacker who also rewrites `aad` to stay self-consistent gains nothing.

    This is the case that proves the binding is cryptographic rather than a
    consistency check between two attacker-controlled fields.
    """
    stok_path, key_path = artifact
    stok = read_stok(stok_path)
    stok.public_label = b"FORGED-LABEL"
    stok.aad = expected_aad(b"FORGED-LABEL")
    write_stok(stok, stok_path)

    plaintext, info = _open(stok_path, key_path)

    assert plaintext is None, "self-consistent forgery must not decrypt either"
    assert info.get("status") == "DENIED"


def test_tampering_stored_aad_alone_is_ignored(artifact):
    """The stored aad is no longer trusted, so garbage in it must not matter."""
    stok_path, key_path = artifact
    stok = read_stok(stok_path)
    stok.aad = b"garbage-aad-value"
    write_stok(stok, stok_path)

    plaintext, info = _open(stok_path, key_path)

    assert plaintext == PAYLOAD, "a bogus stored aad must not break a valid artifact"
    assert info.get("aad_rebound") is True
