"""Encrypted on-disk credential cache for automatic re-login.

Why: the passport API offers no renewable ticket we could reuse, so the
only way to survive a dropped session without re-typing the password is
to store the credentials and silently replay ``auth/psw``.

Honest threat model (also documented in the README):

- The key is derived from machine-id + uid + user name. These are not
  cryptographic secrets: someone with that material can decrypt a copied
  cache. Ciphertext is authenticated (ChaCha20 plus HMAC-SHA256).
- What it does NOT protect: anyone who can already run code as you (or
  as root) on this machine can decrypt it — they could keylog the
  password anyway. This is the unavoidable price of "no re-typing".

Construction (stdlib only, no dependencies):

    machine secret --PBKDF2-HMAC-SHA256--> 64B base key
    base key --HMAC(label)--> enc key (32B) + mac key (32B)
    plaintext JSON --ChaCha20(enc key, nonce)--> ct
    MAC = HMAC-SHA256(mac key, nonce || ct)
"""

from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import socket
import struct
import time
from dataclasses import dataclass
from pathlib import Path

MACHINE_ID_FILES = ("/etc/machine-id", "/var/lib/dbus/machine-id")
_PBKDF2_ITERS = 120_000
_ENC_LABEL = b"atrust-cli/enc/v1"
_MAC_LABEL = b"atrust-cli/mac/v1"


@dataclass
class StoredCredential:
    url: str
    username: str
    password: str
    pub_key: str | None = None
    saved_at: str = ""


def cache_path() -> Path:
    state = os.environ.get("XDG_STATE_HOME") or "~/.local/state"
    return Path(state).expanduser() / "atrust-cli" / "credentials.json"


# ------------------------------------------------------------- machine key ---
def _machine_secret() -> bytes:
    """Key material bound to this machine and this OS user.

    monkeypatched in tests; deliberately not secret against local root.
    """
    mid = ""
    for candidate in MACHINE_ID_FILES:
        try:
            mid = Path(candidate).read_text(encoding="ascii").strip()
        except OSError:
            continue
        if mid:
            break
    if not mid:
        mid = socket.gethostname()
    return f"{mid};uid={os.getuid()};user={getpass.getuser()}".encode()


def _derive_keys(salt: bytes) -> tuple[bytes, bytes]:
    base = hashlib.pbkdf2_hmac("sha256", _machine_secret(), salt,
                               _PBKDF2_ITERS, dklen=64)
    return (hmac.digest(base, _ENC_LABEL, "sha256"),
            hmac.digest(base, _MAC_LABEL, "sha256"))


# ----------------------------------------------------------------- chacha20 ---
def _rotl(v: int, n: int) -> int:
    return ((v << n) & 0xFFFFFFFF) | (v >> (32 - n))


def _quarter(s: list[int], a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 7)


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    state = ([0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
             + list(struct.unpack("<8I", key))
             + [counter]
             + list(struct.unpack("<3I", nonce)))
    w = state[:]
    for _ in range(10):
        _quarter(w, 0, 4, 8, 12)
        _quarter(w, 1, 5, 9, 13)
        _quarter(w, 2, 6, 10, 14)
        _quarter(w, 3, 7, 11, 15)
        _quarter(w, 0, 5, 10, 15)
        _quarter(w, 1, 6, 11, 12)
        _quarter(w, 2, 7, 8, 13)
        _quarter(w, 3, 4, 9, 14)
    return struct.pack("<16I", *((x + y) & 0xFFFFFFFF
                                  for x, y in zip(w, state)))


def _chacha20_xor(key: bytes, nonce: bytes, data: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = _chacha20_block(key, 1 + i // 64, nonce)
        out += bytes(a ^ b for a, b in zip(data[i:i + 64], ks))
    return bytes(out)


# ------------------------------------------------------------------- store ---
def save(url: str, username: str, password: str,
         pub_key: str | None = None) -> Path:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    enc_key, mac_key = _derive_keys(salt)
    plaintext = json.dumps({"password": password}).encode("utf-8")
    ct = _chacha20_xor(enc_key, nonce, plaintext)
    mac = hmac.new(mac_key, nonce + ct, hashlib.sha256).hexdigest()
    doc = {
        "v": 1,
        "kdf": f"pbkdf2-sha256/{_PBKDF2_ITERS}",
        "cipher": "chacha20-etag-hmac-sha256",
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ct": ct.hex(),
        "mac": mac,
        "meta": {
            "url": url,
            "username": username,
            "pub_key": pub_key,
            "saved_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        },
    }
    path = cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
    os.chmod(path, 0o600)  # enforce even if the file pre-existed wider
    return path


def load() -> StoredCredential | None:
    """Return the cached credential, or None if absent/corrupt/moved.

    A wrong machine secret or a tampered file fails the MAC and is
    treated as 'no cache' rather than raising.
    """
    try:
        doc = json.loads(cache_path().read_text(encoding="utf-8"))
        salt = bytes.fromhex(doc["salt"])
        nonce = bytes.fromhex(doc["nonce"])
        ct = bytes.fromhex(doc["ct"])
        enc_key, mac_key = _derive_keys(salt)
        expect = hmac.new(mac_key, nonce + ct, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expect, doc["mac"]):
            return None
        password = json.loads(_chacha20_xor(enc_key, nonce, ct))["password"]
        meta = doc.get("meta") or {}
        return StoredCredential(
            url=meta.get("url") or "",
            username=meta.get("username") or "",
            password=password,
            pub_key=meta.get("pub_key"),
            saved_at=meta.get("saved_at") or "",
        )
    except (OSError, ValueError, KeyError, TypeError):
        return None


def clear() -> bool:
    try:
        cache_path().unlink()
    except FileNotFoundError:
        return False
    return True
