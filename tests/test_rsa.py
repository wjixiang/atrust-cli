from atrust_cli.rsa_jssdk import _pkcs1_v15_pad, encrypt_to_hex


def test_padding_structure():
    padded = _pkcs1_v15_pad(b"secret", 128)
    assert len(padded) == 128
    assert padded[0:2] == b"\x00\x02"
    assert padded[-7:] == b"\x00" + b"secret"
    assert all(b != 0 for b in padded[2:-7])


def test_hex_shape_2048():
    # dummy 2048-bit modulus: shape and determinism of length
    key = "A" * 512
    out = encrypt_to_hex("pwd_0123456789abcdef", key, 65537)
    assert 0 < len(out) <= 512
    assert all(c in "0123456789abcdef" for c in out)


def test_multi_block():
    key = "B" * 512
    long_pw = "x" * 500  # > 245 bytes -> two blocks
    out = encrypt_to_hex(long_pw, key, 65537)
    assert len(out) > 512  # two blocks concatenated
