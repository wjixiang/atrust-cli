"""Encrypted session capture, separate from the optional password cache.

All session metadata is encrypted and authenticated. A random local key is
stored beside the cache (both 0600); copying both permits decryption.
"""

from __future__ import annotations

import hmac
import json
import os
import tempfile
import time
from pathlib import Path

from . import authcache


def cache_path() -> Path:
    return authcache.cache_path().with_name("session.json")


def _key(create: bool = False) -> bytes:
    path = cache_path().with_name("session.key")
    if create:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "wb") as f:
                f.write(os.urandom(64))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as f:
        key = f.read(65)
    if len(key) != 64:
        raise ValueError("invalid session key")
    return key


def save(session: dict) -> Path:
    path = cache_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    key = _key(create=True)
    nonce = os.urandom(12)
    payload = {**session, "saved_at": time.time()}
    ct = authcache._chacha20_xor(key[:32], nonce, json.dumps(payload).encode())
    mac = hmac.digest(key[32:], b"atrust-session-v1" + nonce + ct, "sha256")
    doc = {"v": 1, "nonce": nonce.hex(), "ct": ct.hex(), "mac": mac.hex()}
    fd, tmp = tempfile.mkstemp(prefix=".session-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(doc, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return path


def load() -> dict | None:
    try:
        key = _key()
        doc = json.loads(cache_path().read_text())
        if doc["v"] != 1:
            return None
        nonce, ct = bytes.fromhex(doc["nonce"]), bytes.fromhex(doc["ct"])
        mac = hmac.digest(key[32:], b"atrust-session-v1" + nonce + ct, "sha256")
        if len(nonce) != 12 or not hmac.compare_digest(mac.hex(), doc["mac"]):
            return None
        result = json.loads(authcache._chacha20_xor(key[:32], nonce, ct))
        return result if isinstance(result, dict) else None
    except (OSError, ValueError, KeyError, TypeError):
        return None


def clear() -> bool:
    removed = False
    for path in (cache_path(), cache_path().with_name("session.key")):
        try:
            path.unlink()
            removed = True
        except FileNotFoundError:
            pass
    return removed
