"""
Cross-backend parity between the C++ friction core and the reference Python
implementation.

The README and the integration docs claim the two backends agree on friction
state and on `working_key` after the second failure (the mutation path). Until
v0.10.4 nothing tested it, and it was false whenever `libfriction.so` was
loaded: `SequentialTarpit::mutate_key` encoded fib(n) as 16 big-endian bytes
with `f >> (8 * (15 - i))` over a `uint64_t`, so for the top 8 bytes the shift
exponent reached 120. That is undefined behaviour (UBSan: "shift exponent 120
is too large for 64-bit type"); on x86 with gcc the count wraps modulo 64 and
the high 8 bytes came out as a duplicate of the low 8 instead of zero. Python's
`fib(n).to_bytes(16, "big")` zero-pads, so the two backends derived different
key material from the same inputs.

These tests pin the encoding itself and the end-to-end agreement, so the claim
cannot silently rot again. They skip rather than fail when the native library is
absent: a pure-Python host has nothing to compare against, and an honest skip is
more useful than a green tick that proves nothing.
"""

import hashlib

import pytest

from smart_token_prod.core import SequentialTarpit as PySequentialTarpit

native = pytest.importorskip("smart_token_prod.native")

pytestmark = pytest.mark.skipif(
    not native.is_available(),
    reason="libfriction.so not built — no native backend to compare against",
)

BASE_KEY = bytes(range(32))


def _fib(n: int) -> int:
    if n <= 1:
        return n
    a, b = 0, 1
    for _ in range(2, n + 1):
        a, b = b, a + b
    return b


def _expected_mutation(key: bytes, n: int) -> bytes:
    """The contract: sha256(key || fib(n) as 16 big-endian bytes || b"|FRICTION")."""
    return hashlib.sha256(key + _fib(n).to_bytes(16, "big") + b"|FRICTION").digest()


def _seed_for(base_key: bytes) -> int:
    """Mirrors register_failure()'s first-failure seed derivation."""
    return 20 + (((base_key[0] << 8) | base_key[1]) % 10)


def test_fib_encoding_zero_pads_the_high_eight_bytes():
    """
    Guards the exact regression: with the wrapped shift the high 8 bytes equal
    the low 8, so this asserts they are zero instead.
    """
    n = _seed_for(BASE_KEY) + 5
    encoded = _fib(n).to_bytes(16, "big")
    assert encoded[:8] == b"\x00" * 8
    assert encoded[8:] != b"\x00" * 8, "fib(n) should be non-zero for this n"
    # The buggy encoding duplicated the low half into the high half.
    assert encoded[:8] != encoded[8:]


@pytest.mark.parametrize("mode", ["mutate", "cpu"])
def test_working_key_matches_after_second_failure(mode):
    """
    Two failures put both backends on the mutation path. The resulting
    working_key is key material, so a mismatch is not cosmetic.
    """
    py = PySequentialTarpit(BASE_KEY, tarpit_mode=mode, tarpit_seconds=0.0)
    nt = native.NativeTarpit(BASE_KEY, tarpit_mode=mode, tarpit_seconds=0.0)

    for _ in range(2):
        py.register_failure()
        nt.register_failure()

    py_key = py.state.working_key_material
    nt_key = nt.current_key()

    assert len(py_key) == 32
    assert nt_key == py_key, "native and Python working_key diverged"
    assert nt_key == _expected_mutation(BASE_KEY, _seed_for(BASE_KEY) + 5)
    assert nt_key != BASE_KEY, "the key should actually have been mutated"


def test_fib_seed_matches_on_first_failure():
    py = PySequentialTarpit(BASE_KEY, tarpit_mode="mutate", tarpit_seconds=0.0)
    nt = native.NativeTarpit(BASE_KEY, tarpit_mode="mutate", tarpit_seconds=0.0)
    py.register_failure()
    nt.register_failure()

    snap_py = py.snapshot()
    snap_nt = nt.snapshot()
    assert int(snap_nt["fib_seed"]) == int(snap_py["fib_seed"]) == _seed_for(BASE_KEY)
    assert int(snap_nt["fail_count"]) == int(snap_py["fail_count"]) == 1


@pytest.mark.parametrize("base", [bytes(32), bytes([0xFF] * 32), bytes(range(32))])
def test_parity_across_several_base_keys(base):
    """
    The seed depends on base_key[0..1], so vary it to exercise several fib(n)
    magnitudes rather than a single lucky value.
    """
    py = PySequentialTarpit(base, tarpit_mode="mutate", tarpit_seconds=0.0)
    nt = native.NativeTarpit(base, tarpit_mode="mutate", tarpit_seconds=0.0)
    for _ in range(2):
        py.register_failure()
        nt.register_failure()
    assert nt.current_key() == py.state.working_key_material
