"""End-to-end credential-login flow against a mock passport server.

Pins the caching behaviour: a pre-seeded authcache is used without any
password prompt, the login round-trips authConfig/psw, and the refreshed
credential lands back in the cache.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import atrust_cli.authcache as ac
import atrust_cli.cli as cli

# throwaway 2048-bit modulus (openssl genrsa); only shape matters —
# the client encrypts against it, the mock never decrypts.
MODULUS = ("aaab3584187dd302eebaa516252e6e368910789720054faf8309254019efd957"
           "6d388673f47b5ff50d2608595eeb87cc8acd59f156821d613691ff7d72b3a2c41"
           "c0f9130982722d26086b509c88b9c18fc89610ecc44f7e8d010192efbc28410cc"
           "822d39b24f0d1e54c6cd201ac043c9f0b5ef0307900e4d42533d5b85d38daaca7"
           "4f0fe7237d9a6b86f7a60fafda189eaa1620e37f4efa79b8a62c42647f9c05df7"
           "2de57f5b1fa0e26fb9fcb81e48f5608fef2c5763b1ea0a88ded1c156c38ddc1a"
           "1019f7c5cbce39d4567300e60803dfe4cda4e65ba895144f6d33808066d4276f2"
           "4c3897c61692852f155e3c584e1e636cd9507ee6145909a4d7cff53b59b")


class MockPassport(BaseHTTPRequestHandler):
    psw_bodies: list[dict] = []

    def log_message(self, format, *args):  # noqa: A002 - silence
        pass

    def _send(self, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        assert self.headers["Content-Type"].startswith("application/json")
        req = json.loads(self.rfile.read(length))
        if self.path.startswith("/passport/v1/public/authConfig"):
            self._send({"code": 0, "data": {
                "pubKey": MODULUS, "pubKeyExp": "65537",
                "antiReplayRand": "0123456789abcdef"}})
        elif self.path.startswith("/passport/v1/auth/psw"):
            type(self).psw_bodies.append(req)
            self._send({"code": 0, "data": {"sidTicket": "TICKET-1234"}})
        else:
            self._send({"code": 0, "data": {}})

    def do_GET(self) -> None:
        self._send({"code": 0, "data": {
            "pubKey": MODULUS, "pubKeyExp": "65537",
            "antiReplayRand": "0123456789abcdef"}})


@pytest.fixture()
def mock_server(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    monkeypatch.setattr(ac, "_machine_secret", lambda: b"test-machine")
    MockPassport.psw_bodies = []
    server = HTTPServer(("127.0.0.1", 0), MockPassport)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.fixture()
def no_handoff(monkeypatch):
    """Stub the tray handoff (needs the real aTrust client)."""
    calls = []
    import atrust_cli.sessionflow as sf
    monkeypatch.setattr(sf, "connect",
                        lambda client, resp, args: calls.append(1) or 0)
    return calls


def _no_prompt(monkeypatch):
    def fail(*a, **k):
        raise AssertionError("password prompt must not happen")
    monkeypatch.setattr("getpass.getpass", fail)


def test_cached_relogin_no_prompt(mock_server, no_handoff, monkeypatch, capsys):
    ac.save(mock_server, "alice", "cached-pw")
    _no_prompt(monkeypatch)
    rc = cli.main(["login", mock_server, "-u", "alice"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "using cached password" in out
    assert "credentials cached" in out
    # exactly one psw call, password was RSA(rand-bound), not plaintext
    assert len(MockPassport.psw_bodies) == 1
    assert "cached-pw" not in json.dumps(MockPassport.psw_bodies)
    assert MockPassport.psw_bodies[0]["username"] == "alice"
    # handoff (browser-start) was reached
    assert no_handoff == [1]
    # cache was refreshed with the server pubKey
    cred = ac.load()
    assert cred is not None
    assert cred.password == "cached-pw"
    assert cred.pub_key == MODULUS


def test_forget_clears_cache(mock_server, no_handoff, monkeypatch, capsys):
    ac.save(mock_server, "alice", "cached-pw")
    rc = cli.main(["login", "--forget"])
    assert rc == 0
    assert ac.load() is None
