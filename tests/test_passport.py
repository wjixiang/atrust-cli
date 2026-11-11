import io
import json

import pytest

from atrust_cli import cli, sessioncache
from atrust_cli.passport import PassportClient, PassportError, is_rand_error


class Controller:
    def __init__(self, message="authentication rejected", initial_rand="first",
                 repeat_rand=False):
        self.message = message
        self.initial_rand = initial_rand
        self.repeat_rand = repeat_rand
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append(request)
        assert request.get_header("Content-type") == "application/json;charset=utf-8"
        assert request.get_header("X-sdp-traceid")
        if request.method == "GET":
            data = {"pubKey": "a" * 512, "pubKeyExp": "65537",
                    "antiReplayRand": self.initial_rand,
                    "security": {"csrfToken": "CSRF-SECRET"}}
            result = {"code": 0, "data": data}
        else:
            data = json.loads(request.data)
            assert isinstance(data["username"], str)
            assert request.get_header("X-csrf-token") == "CSRF-SECRET"
            assert "plaintext-password" not in request.data.decode()
            rand = self.initial_rand if self.repeat_rand else f"fresh-{len(self.requests)}"
            result = {"code": 75500000, "message": self.message,
                      "data": {"antiReplayRand": rand}}
        return io.BytesIO(json.dumps(result).encode())


def test_json_wire_and_redacted_controller_diagnostics():
    client = PassportClient("https://vpn.example.com:8443")
    client.opener = controller = Controller(
        "invalid password plaintext-password for alice; CSRF-SECRET fresh-2")
    client.auth_config()
    with pytest.raises(PassportError) as error:
        client.psw_login("alice", "plaintext-password")
    message = str(error.value)
    assert "invalid password" in message
    for secret in ("plaintext-password", "alice", "CSRF-SECRET", "fresh-2"):
        assert secret not in message
    assert not is_rand_error(error.value)
    assert len(json.loads(controller.requests[-1].data)["password"]) == 512


@pytest.mark.parametrize("message,repeat_rand,expected", [
    ("authentication rejected", False, 1),
    ("antiReplayRand expired", False, 2),
    ("antiReplayRand expired", True, 1),
])
def test_generic_failure_is_not_inferred_from_new_rand(
        tmp_path, monkeypatch, capsys, message, repeat_rand, expected):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    client = PassportClient("https://vpn.example.com")
    client.opener = controller = Controller(message, repeat_rand=repeat_rand)
    monkeypatch.setattr("atrust_cli.passport.PassportClient", lambda *a, **kw: client)
    monkeypatch.setattr("getpass.getpass", lambda *a: "plaintext-password")
    def forbidden(*a, **kw):
        raise AssertionError("failed authentication must never start local agent")
    monkeypatch.setattr("atrust_cli.sessionflow.AgentClient", forbidden)
    assert cli.main(["login", client.base, "-u", "alice", "--auth-only", "--no-cache"]) == 1
    assert sum(req.method == "POST" for req in controller.requests) == expected
    assert sessioncache.load() is None
    output = capsys.readouterr().out
    assert message in output
    assert "plaintext-password" not in output


def test_missing_challenge_submits_no_password(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    client = PassportClient("https://vpn.example.com")
    client.opener = controller = Controller(initial_rand="")
    monkeypatch.setattr("atrust_cli.passport.PassportClient", lambda *a, **kw: client)
    def forbidden(*a, **kw):
        raise AssertionError("must not request password without a challenge")
    monkeypatch.setattr("getpass.getpass", forbidden)
    assert cli.main(["login", client.base, "-u", "alice", "--auth-only", "--no-cache"]) == 1
    assert all(req.method == "GET" for req in controller.requests)


def test_expired_captcha_message_prompts_and_keeps_auth_only(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    client = PassportClient("https://vpn.example.com")
    class CaptchaController(Controller):
        def open(self, request, timeout=None):
            if request.method == "POST" and sum(r.method == "POST" for r in self.requests) == 1:
                self.requests.append(request)
                assert json.loads(request.data)["graphCheckCode"] == "AB12"
                return io.BytesIO(json.dumps({"code": 0, "data": {"sidTicket": "TICKET"}}).encode())
            return super().open(request, timeout)
    client.opener = CaptchaController(message="图形验证码已超时，请重试")
    monkeypatch.setattr("atrust_cli.passport.PassportClient", lambda *a, **kw: client)
    image = tmp_path / "captcha.jpg"
    image.write_bytes(b"\xff\xd8\xff")
    monkeypatch.setattr(client, "fetch_captcha", lambda: image)
    monkeypatch.setattr("getpass.getpass", lambda *a: "plaintext-password")
    monkeypatch.setattr("builtins.input", lambda *a: "AB12")
    def forbidden(*a, **kw):
        raise AssertionError("auth-only captcha must not initialize agent")
    monkeypatch.setattr("atrust_cli.sessionflow.AgentClient", forbidden)
    assert cli.main(["login", client.base, "-u", "alice", "--auth-only", "--no-cache"]) == 0
    assert sessioncache.load()["sid_ticket"] == "TICKET"


@pytest.mark.parametrize("blob,valid", [(b"\xff\xd8\xffIMAGE", True), (b'{"code":404}', False)])
def test_captcha_endpoint_and_private_image_file(monkeypatch, blob, valid):
    client = PassportClient("https://vpn.example.com")
    class ImageController:
        def open(self, request, timeout=None):
            assert "/passport/v1/public/checkCode?" in request.full_url
            assert request.get_header("Cache-control") == "no-cache"
            return io.BytesIO(blob)
    client.opener = ImageController()
    path = client.fetch_captcha()
    if valid:
        try:
            assert path.read_bytes() == blob
            assert path.stat().st_mode & 0o777 == 0o600
        finally:
            path.unlink()
    else:
        assert path is None
