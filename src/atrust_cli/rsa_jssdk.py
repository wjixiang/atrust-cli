"""jsbn-compatible RSA PKCS#1 v1.5 encryption for aTrust password login.

The login page (web/old/jssdk/common.js and the current bundle's data_utils)
encrypts the password as::

    ciphertext = RSA(pubKey, pubKeyExp).encrypt(password + "_" + antiReplayRand)

with jsbn's RSAKey — PKCS#1 v1.5 type-2 padding, output as concatenated
lowercase-hex blocks, chunk size = keybytes - 11 (245 bytes for 2048-bit).
The CSU controller uses a 2048-bit key, so a normal ``password_rand``
payload is a single 512-hex-char block.
"""

from __future__ import annotations

import os


def encrypt_to_hex(plaintext: str, pub_key_hex: str, pub_key_exp: int | str = 65537) -> str:
    """Encrypt plaintext with RSA public key, jsbn-style hex output."""
    n = int(pub_key_hex, 16)
    e = int(pub_key_exp)
    key_len = (n.bit_length() + 7) // 8
    chunk_size = key_len - 11
    data = plaintext.encode("utf-8")
    out: list[str] = []
    for off in range(0, len(data), chunk_size):
        block = data[off:off + chunk_size]
        m = int.from_bytes(_pkcs1_v15_pad(block, key_len), "big")
        c = pow(m, e, n)
        # The current shipped SDK pads each RSA ciphertext to the modulus
        # width. Dropping leading zeroes can produce odd-length hex strings.
        out.append(format(c, f"0{key_len * 2}x"))
    return "".join(out)


def _pkcs1_v15_pad(block: bytes, key_len: int) -> bytes:
    """EME-PKCS1-v1_5 type 2: 0x00 0x02 PS 0x00 D."""
    pad_len = key_len - len(block) - 3
    ps = bytearray()
    while len(ps) < pad_len:
        b = os.urandom(pad_len * 2)[:pad_len - len(ps)]
        ps += bytes(x for x in b if x != 0)
    return b"\x00\x02" + bytes(ps) + b"\x00" + block


# ---- self-test ------------------------------------------------------------+
def _selftest() -> None:  # pragma: no cover
    # padding structure and length invariants
    key_hex = "A" * 512  # dummy 2048-bit modulus (odd, non-prime: fine for shape test)
    out = encrypt_to_hex("hello_world_0123456789abcdef", key_hex, 65537)
    assert len(out) == 512, len(out)
    padded = _pkcs1_v15_pad(b"secret", 128)
    assert padded[0] == 0 and padded[1] == 2 and padded[-8:] == b"\x00" + b"secret"
    assert all(b != 0 for b in padded[2:-8])
