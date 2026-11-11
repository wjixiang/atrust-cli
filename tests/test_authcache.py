import json

import atrust_cli.authcache as ac


# ------------------------------------------------------------- chacha20 ---
# RFC 8439 §2.3.2 block-function vector (key 00..1f, nonce
# 00000009 0000004a 00000000, counter=1); also re-verified byte-for-byte
# against `openssl enc -chacha20` with iv = counter||nonce.
_RFC_KEY = bytes(range(32))
_RFC_NONCE = bytes.fromhex("000000090000004a00000000")
_RFC_KEYSTREAM_1 = bytes.fromhex(
    "10f1e7e4d13b5915500fdd1fa32071c4"
    "c7d1f4c733c068030422aa9ac3d46c4e"
    "d2826446079faa0914c2d705d98b02a2"
    "b5129cd1de164eb9cbd083e8a2503c4e"
)
_RFC_KEYSTREAM_2 = bytes.fromhex(
    "0a88837739d7bf4ef8ccacb0ea2bb9d6"
    "9d56c394aa351dfda5bf459f0a2e9fe8"
    "e721f89255f9c486bf21679c683d4f9c"
    "5cf2fa27865526005b06ca374c86af3b"
)


def test_chacha20_rfc8439_block():
    assert ac._chacha20_block(_RFC_KEY, 1, _RFC_NONCE) == _RFC_KEYSTREAM_1
    assert ac._chacha20_block(_RFC_KEY, 2, _RFC_NONCE) == _RFC_KEYSTREAM_2


def test_chacha20_xor_multiblock():
    import os

    pt = os.urandom(150)  # spans three blocks
    ct = ac._chacha20_xor(_RFC_KEY, _RFC_NONCE, pt)
    expect = bytes(a ^ b for a, b in
                   zip(pt, _RFC_KEYSTREAM_1 + _RFC_KEYSTREAM_2))
    assert ct[:128] == expect
    assert len(ct) == len(pt)
    # decrypt is the same operation
    assert ac._chacha20_xor(_RFC_KEY, _RFC_NONCE, ct) == pt


# ----------------------------------------------------------------- cache ---
def _isolate(tmp_path, monkeypatch, secret=b"test-machine-secret"):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    monkeypatch.setattr(ac, "_machine_secret", lambda: secret)


def test_roundtrip(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    path = ac.save("https://vpn.example.com", "alice", "s3cret-pw", "AB" * 128)
    cred = ac.load()
    assert cred is not None
    assert cred.url == "https://vpn.example.com"
    assert cred.username == "alice"
    assert cred.password == "s3cret-pw"
    assert cred.pub_key == "AB" * 128
    assert cred.saved_at
    # permissions and no plaintext leak
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert "s3cret-pw" not in path.read_text()


def test_tampered_file_rejected(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    ac.save("https://vpn.example.com", "alice", "s3cret")
    path = ac.cache_path()
    doc = json.loads(path.read_text())
    ct = bytearray(bytes.fromhex(doc["ct"]))
    ct[0] ^= 0xFF  # flip one ciphertext byte
    doc["ct"] = bytes(ct).hex()
    path.write_text(json.dumps(doc))
    assert ac.load() is None


def test_other_machine_rejected(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch, secret=b"machine-A")
    ac.save("https://vpn.example.com", "alice", "s3cret")
    monkeypatch.setattr(ac, "_machine_secret", lambda: b"machine-B")
    assert ac.load() is None


def test_missing_and_clear(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    assert ac.load() is None          # nothing stored yet
    assert ac.clear() is False
    ac.save("https://vpn.example.com", "alice", "s3cret")
    assert ac.clear() is True
    assert ac.load() is None
    assert ac.clear() is False


def test_corrupt_json_is_no_cache(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    p = ac.cache_path()
    p.parent.mkdir(parents=True)
    p.write_text("not json at all")
    assert ac.load() is None
