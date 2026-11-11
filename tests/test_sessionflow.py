import json
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from atrust_cli import cli, sessioncache, sessionflow
from atrust_cli.agent import AgentClient, is_online
from atrust_cli.passport import PassportClient, PassportError


@pytest.fixture
def service(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    state = SimpleNamespace(online=False, requests=[], reject=False,
                            issue=True, pending=False)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, data, code=0, cookie=False):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            if cookie:
                self.send_header("Set-Cookie", "sid=COOKIE-SECRET; Path=/; HttpOnly")
            self.end_headers()
            self.wfile.write(json.dumps({"code": code, "data": data}).encode())

        def do_GET(self):
            state.requests.append((self.path, None, dict(self.headers)))
            self.reply({"pubKey": "abcd", "clientVerifyCode": "VERIFY-SECRET",
                        "guid": "controller-guid", "security": {"csrfToken": "CSRF"}})

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            local = self.path.startswith("/v1/")
            data = json.loads(raw)
            state.requests.append((self.path, data, dict(self.headers)))
            if self.path == "/v1/service/init":
                assert data["type"] == "web"
                assert data["guid"] == "controller-guid"
                assert data["data"]["verifyCode"] == "VERIFY-SECRET"
                self.reply({"sidTicket": "AGENT-TICKET"} if state.issue else {})
            elif self.path == "/v1/service/start":
                assert data["data"]["sidTicket"]
                state.online = True
                self.reply({})
            elif self.path == "/v1/service/status":
                self.reply({"status": "online" if state.online else "logout"})
            elif urllib.parse.urlsplit(self.path).path.endswith("/ticketExchange"):
                self.reply({"sidTicket": "FRESH-TICKET"} if state.issue else {},
                           code=0 if state.issue else 123)
            elif state.reject:
                self.reply({"antiReplayRand": "NEW-RAND"}, code=75500000)
            else:
                self.reply({"sidTicket": "LOGIN-TICKET",
                            **({"nextService": "auth/sms"} if state.pending else {})},
                           cookie=True)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    state.url = f"http://127.0.0.1:{server.server_port}"

    class TestAgent(AgentClient):
        def __init__(self, url, timeout=2):
            super().__init__(url, timeout)
            self.base = state.url

    monkeypatch.setattr(sessionflow, "AgentClient", TestAgent)
    yield state
    server.shutdown()
    server.server_close()
    thread.join()


def args(service, **extra):
    return SimpleNamespace(url=service.url, user="alice", timeout=2,
                           wait=0, insecure=False, capture=True, pub_key=None, **extra)


def authenticate(service):
    client = PassportClient(service.url)
    client.auth_config()
    response = client._request("POST", "/passport/v1/auth/psw", {"username": "alice"})
    return client, response


def test_capture_handoff_and_resume_without_display(service, monkeypatch, capsys):
    monkeypatch.delenv("DISPLAY", raising=False)
    # Neither normal handoff nor resume may start an Electron process.
    def no_tray(*a, **kw):
        raise AssertionError("must not launch tray")
    monkeypatch.setattr("subprocess.Popen", no_tray)
    client, response = authenticate(service)
    assert sessionflow.connect(client, response, args(service)) == 0
    assert service.online
    saved = sessioncache.load()
    assert saved["sid_ticket"] == "LOGIN-TICKET"
    assert saved["cookies"][0]["value"] == "COOKIE-SECRET"
    path = sessioncache.cache_path()
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.with_name("session.key").stat().st_mode & 0o777 == 0o600
    assert "LOGIN-TICKET" not in path.read_text()
    assert "COOKIE-SECRET" not in path.read_text()
    service.online = False
    service.requests.clear()
    assert cli.main(["login", "--resume", "--headless", "--wait", "0"]) == 0
    assert service.online
    assert not any("/auth/psw" in path for path, _, _ in service.requests)
    assert "COOKIE-SECRET" in service.requests[0][2].get("Cookie", "")
    assert cli.main(["login", "--session-info"]) == 0
    output = capsys.readouterr().out
    for secret in ("LOGIN-TICKET", "COOKIE-SECRET", "VERIFY-SECRET", "AGENT-TICKET"):
        assert secret not in output


def test_failed_auth_is_not_success(service):
    service.reject = True
    client = PassportClient(service.url)
    client.auth_config()
    with pytest.raises(PassportError) as exc:
        client._request("POST", "/passport/v1/auth/psw", {})
    assert exc.value.code == 75500000
    assert client.anti_replay_rand == "NEW-RAND"
    assert sessioncache.load() is None


def test_pending_auth_does_not_start_tunnel(service):
    service.pending = True
    client, response = authenticate(service)
    assert sessionflow.connect(client, response, args(service)) == 1
    assert not service.online
    assert sessioncache.load() is None


def test_capture_survives_handoff_failure(service, monkeypatch):
    client, response = authenticate(service)
    client.config.pop("clientVerifyCode")
    assert sessionflow.connect(client, response, args(service)) == 1
    assert sessioncache.load()["sid_ticket"] == "LOGIN-TICKET"
    assert not service.online


def test_capture_existing_gui_session(service):
    service.online = True
    assert sessionflow.capture_existing(args(service)) == 0
    assert sessioncache.load()["sid_ticket"] == "FRESH-TICKET"
    assert sessioncache.load()["cookies"][0]["value"] == "COOKIE-SECRET"
    assert not any(path == "/v1/service/start" for path, _, _ in service.requests)


def test_no_ticket_does_not_create_empty_capture(service):
    service.online = True
    service.issue = False
    assert sessionflow.capture_existing(args(service)) == 1
    assert sessioncache.load() is None


def test_expired_session_fails_without_password_fallback(service, capsys):
    sessioncache.save({"url": service.url, "sid_ticket": "OLD-TICKET",
                       "ticket_saved_at": time.time() - 100, "cookies": []})
    service.issue = False
    assert sessionflow.resume(args(service)) == 1
    assert not service.online
    assert not any(path == "/v1/service/start" for path, _, _ in service.requests)
    assert "interactive authentication is required" in capsys.readouterr().out


def test_tamper_and_forget(service):
    sessioncache.save({"url": service.url, "sid_ticket": "SECRET"})
    path = sessioncache.cache_path()
    doc = json.loads(path.read_text())
    doc["nonce"] = "00" * 12
    path.write_text(json.dumps(doc))
    assert sessioncache.load() is None
    assert cli.main(["login", "--forget"]) == 0
    assert not path.exists()
    assert not path.with_name("session.key").exists()


def test_offline_nonempty_status_is_not_online():
    assert not is_online({"status": "0"})
    assert not is_online({"status": "logout", "data": {"username": "alice"}})
    assert not is_online({"controller-guid": 0})
    assert is_online({"controller-guid": 3})
    assert is_online({"status": "online"})


def test_auth_only_cli_never_touches_agent_or_desktop(service, monkeypatch, capsys):
    def forbidden(*a, **kw):
        raise AssertionError("auth-only must never touch the local agent or tray")
    monkeypatch.setattr(sessionflow, "AgentClient", forbidden)
    monkeypatch.setattr(cli, "_login_session_reuse", forbidden)
    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("getpass.getpass", lambda *a: "TEST-PASSWORD")
    monkeypatch.setattr(PassportClient, "encrypt_password", lambda *a: "RSA-CIPHERTEXT")
    monkeypatch.delenv("DISPLAY", raising=False)
    # Supply the challenge omitted by this minimal fixture's config response.
    original = PassportClient.auth_config
    def config(client):
        result = original(client)
        client.anti_replay_rand = "fresh-rand"
        return result
    monkeypatch.setattr(PassportClient, "auth_config", config)
    assert cli.main(["login", service.url, "-u", "alice", "--auth-only", "--no-cache"]) == 0
    assert not service.online
    assert not any(path.startswith("/v1/") for path, _, _ in service.requests)
    saved = sessioncache.load()
    assert saved["sid_ticket"] == "LOGIN-TICKET"
    assert saved["cookies"][0]["value"] == "COOKIE-SECRET"
    assert "TEST-PASSWORD" not in json.dumps(saved)
    output = capsys.readouterr().out
    assert "tunnel start skipped" in output
    assert "handing session" not in output


@pytest.mark.parametrize("options", [[], ["--resume", "-u", "alice"]])
def test_auth_only_rejects_gui_and_resume(options, monkeypatch):
    def forbidden(*a, **kw):
        raise AssertionError("must reject before any login attempt")
    monkeypatch.setattr(cli, "_login_session_reuse", forbidden)
    monkeypatch.setattr(sessionflow, "resume", forbidden)
    assert cli.main(["login", "https://vpn.example.com", "--auth-only", *options]) == 2


def test_auth_only_defers_access_check(service, monkeypatch, capsys):
    client, response = authenticate(service)
    response["data"]["nextService"] = "auth/accessCheck"
    def forbidden(*a, **kw):
        raise AssertionError("must not initialize agent for pending access check")
    monkeypatch.setattr(sessionflow, "AgentClient", forbidden)
    assert sessionflow.connect(client, response, args(service, auth_only=True)) == 0
    assert not service.online
    assert sessioncache.load()["auth_response"]["data"]["nextService"] == "auth/accessCheck"
    assert "full access is not established" in capsys.readouterr().out


@pytest.mark.parametrize("valid", [True, False])
def test_resume_auth_only_cookies_never_calls_agent(service, monkeypatch, valid):
    client, _ = authenticate(service)
    sessioncache.save({"url": service.url, "cookies": client.export_cookies(),
                       "sid_ticket": "ORIGINAL-TICKET"})
    before = sessioncache.cache_path().read_bytes()
    service.requests.clear()
    service.issue = valid
    def forbidden(*a, **kw):
        raise AssertionError("cookie-only reuse must not touch native agent or password")
    monkeypatch.setattr(sessionflow, "AgentClient", forbidden)
    monkeypatch.setattr("getpass.getpass", forbidden)
    assert cli.main(["login", "--resume", "--auth-only"]) == (0 if valid else 1)
    assert not service.online
    assert not any(path.startswith("/v1/") or "/auth/psw" in path
                   for path, _, _ in service.requests)
    config_path, _, headers = service.requests[0]
    assert "mod" not in urllib.parse.parse_qs(urllib.parse.urlsplit(config_path).query)
    assert "COOKIE-SECRET" in headers.get("Cookie", "")
    if valid:
        assert sessioncache.load()["sid_ticket"] == "FRESH-TICKET"
    else:
        assert sessioncache.cache_path().read_bytes() == before
