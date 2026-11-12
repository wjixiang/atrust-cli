import json
import threading
import urllib.error
import urllib.request

import pytest

from atrust_cli import sessioncache, web
from atrust_cli.passport import PassportError


class Passport:
    def __init__(self, server, **kw):
        self.client_type = kw.get("client_type", "SDPBrowserClient")
        self.user_agent = kw.get("user_agent", web.BROWSER_UA)
        self.base = server
        self.config = {"guid": "guid", "pubKey": "key", "antiReplayRand": "rand"}
        self.pub_key, self.anti_replay_rand = "key", "rand"
        self.device_id = "DEVICE-SECRET"
        self.calls = []

    def auth_config(self, **kw):
        self.calls.append(("config", kw))

    def psw_login(self, username, password, graph=None):
        if graph is None:
            raise PassportError(75500000, "图形验证码已超时，请重试")
        assert len(json.loads(graph)["coordinates"]) == 3
        return {"code": 0, "data": {"nextService": "auth/authCheck",
                "ticket": "ENV-SECRET", "env": {"need": True}}}

    def fetch_captcha(self):
        path = self.directory / "captcha.jpg"
        path.write_bytes(b"\xff\xd8\xffIMAGE")
        return path

    def report_browser_env(self, ticket):
        self.calls.append(("env", ticket))

    def _request(self, method, path, body=None, query=None, **kw):
        self.calls.append((method, path, body, query))
        if path.endswith("authCheck"):
            return {"code": 0, "data": {"nextService": "auth/sms"}}
        if query.get("action") == "sendsms":
            return {"code": 0, "data": {"interval": "60"}}
        if query.get("action") == "checkcode":
            assert body["code"] == "012345"
            return {"code": 0, "data": {}}
        raise AssertionError(path)

    def ticket_exchange(self):
        return {"code": 0, "data": {"sidTicket": "TICKET-SECRET"}}

    def export_cookies(self):
        return [{"name": "sid", "value": "COOKIE-SECRET"}]

    def import_cookies(self, cookies):
        self.calls.append(("cookies", len(cookies)))


@pytest.fixture
def manager(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    Passport.directory = tmp_path
    monkeypatch.setattr(web, "PassportClient", Passport)
    def forbidden(*a, **kw):
        raise AssertionError("authentication must not invoke the native agent")
    monkeypatch.setattr(web, "AgentClient", forbidden)
    return web.Management("https://vpn.example.com")


def test_full_click_captcha_sms_flow_without_tunnel(manager):
    state = manager.action("/api/auth/begin", {"username": "alice", "password": "PASSWORD-SECRET"})
    assert state["stage"] == "captcha"
    assert manager.captcha.startswith(b"\xff\xd8\xff")
    state = manager.action("/api/auth/captcha", {
        "coordinates": [[50, 50], [150, 100], [250, 10]], "width": 272, "height": 192})
    assert state["stage"] == "sms"
    assert manager.password is None
    assert not manager.captcha
    state = manager.action("/api/auth/sms/send", {})
    assert state["sms_retry_after"] > 0
    with pytest.raises(ValueError, match="倒计时"):
        manager.action("/api/auth/sms/send", {})
    state = manager.action("/api/auth/sms/verify", {"code": "012345"})
    assert state["stage"] == "authenticated"
    assert sessioncache.load()["sid_ticket"] == "TICKET-SECRET"
    serialized = json.dumps(state)
    for secret in ("PASSWORD-SECRET", "COOKIE-SECRET", "TICKET-SECRET", "012345", "ENV-SECRET"):
        assert secret not in serialized
    assert "PASSWORD-SECRET" not in json.dumps(sessioncache.load())
    with pytest.raises(ValueError, match="隔离"):
        manager.action("/api/tunnel/connect", {})


def test_captcha_expiry_and_invalid_coordinates(manager):
    manager.begin({"username": "alice", "password": "PASSWORD-SECRET"})
    with pytest.raises(ValueError):
        manager.submit_captcha({"width": 272, "height": 192, "coordinates": [[10, 180]] * 3})
    manager.password_deadline = 0
    assert manager.state()["stage"] == "error"
    assert manager.password is None
    assert not manager.captcha


def test_password_expiry_does_not_require_browser_polling(manager):
    manager.begin({"username": "alice", "password": "PASSWORD-SECRET"})
    manager.password_timer.cancel()
    manager.password_timer.function()
    assert manager.password is None
    assert manager.stage == "error"
    assert not manager.captcha


def test_restore_and_forget(manager):
    manager.begin({"username": "alice", "password": "PASSWORD-SECRET"})
    manager.advance({"code": 0, "data": {}})
    manager.client = None
    assert manager.action("/api/auth/restore", {})["stage"] == "authenticated"
    assert manager.action("/api/session/forget", {})["stage"] == "idle"
    assert sessioncache.load() is None


def test_explicit_connect_uses_only_isolated_agent(manager, monkeypatch):
    manager.client = Passport(manager.server)
    manager.username = "alice"
    manager.stage = "authenticated"
    manager.isolated = True
    calls = []
    class Agent:
        def __init__(self, *a, **kw):
            self.started = False
        def init(self, config):
            calls.append("init")
        def status(self):
            return {"status": "online" if self.started else "logout"}
        def start(self, ticket):
            assert ticket == "TICKET-SECRET"
            self.started = True
            calls.append("start")
    monkeypatch.setattr(web, "AgentClient", Agent)
    state = manager.action("/api/tunnel/connect", {})
    assert calls == ["init", "start"]
    assert state["tunnel"] == "online"
    assert "TICKET-SECRET" not in json.dumps(state)
    class Core:
        def __init__(self, **kw):
            pass
        def offline(self):
            calls.append("offline")
            return False
    monkeypatch.setattr(web, "SdpCoreClient", Core)
    with pytest.raises(ValueError, match="未确认"):
        manager.action("/api/tunnel/disconnect", {})
    assert calls[-1] == "offline"


def test_http_csrf_origin_host_and_assets(manager):
    server = web.Server(("127.0.0.1", 0), manager)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    def post(headers):
        return urllib.request.urlopen(urllib.request.Request(
            base + "/api/session/forget", data=b"{}", headers=headers))
    try:
        with urllib.request.urlopen(base) as response:
            assert response.status == 200
            assert b"captcha-image" in response.read()
            assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
        with urllib.request.urlopen(base + "/api/state") as response:
            state = json.load(response)
        with pytest.raises(urllib.error.HTTPError) as error:
            post({})
        assert error.value.code == 403
        with pytest.raises(urllib.error.HTTPError) as error:
            post({"X-CSRF-Token": state["csrf"], "Origin": "https://evil.example"})
        assert error.value.code == 403
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(urllib.request.Request(base, headers={"Host": "evil.example"}))
        assert error.value.code == 403
        with post({"X-CSRF-Token": state["csrf"], "Origin": base}) as response:
            assert response.status == 200
        with urllib.request.urlopen(base + "/app.js") as response:
            assert response.status == 200
        with urllib.request.urlopen(base + "/style.css") as response:
            assert response.status == 200
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_web_profile_is_saved_and_restored(manager):
    manager.browser_user_agent = 'Mozilla/5.0 test-browser'
    manager.begin({'username': 'alice', 'password': 'password'})
    assert manager.client.client_type == 'SDPBrowserClient'
    assert manager.client.user_agent == manager.browser_user_agent
    manager.advance({'code': 0, 'data': {}})
    saved = sessioncache.load()
    assert saved['client_type'] == 'SDPBrowserClient'
    manager.restore()
    assert manager.client.user_agent == saved['user_agent']
    saved.pop('client_type')
    sessioncache.save(saved)
    with pytest.raises(ValueError, match='重新登录'):
        manager.restore()


def test_connection_revoked_during_start_is_not_success(manager, monkeypatch):
    manager.client = Passport(manager.server)
    manager.stage = 'authenticated'
    manager.isolated = True
    class Agent:
        def __init__(self, *a, **kw): pass
        def init(self, config): pass
        def status(self): return {'status': 'logout'}
        def start(self, ticket): pass
    monkeypatch.setattr(web, 'AgentClient', Agent)
    def revoked(agent):
        raise web.AgentError('offline')
    monkeypatch.setattr(web, 'wait_for_stable_online', revoked)
    monkeypatch.setattr(web, 'recent_logout_reason', lambda since: 'cookieHijacking')
    with pytest.raises(ValueError, match='cookieHijacking'):
        manager.connect()
    assert manager.stage == 'error'
    assert manager.tunnel == 'offline'


def test_public_access_keeps_origin_and_csrf_checks(manager):
    server = web.Server(('127.0.0.1', 0), manager, allow_remote=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f'http://127.0.0.1:{server.server_port}'
    public_host = 'vpn.example.com:8788'
    try:
        with urllib.request.urlopen(urllib.request.Request(base+'/api/state', headers={'Host':public_host})) as r:
            state=json.load(r)
        for scheme in ('http','https'):
            req=urllib.request.Request(base+'/api/session/forget',data=b'{}',headers={
                'Host':public_host,'Origin':scheme+'://'+public_host,'X-CSRF-Token':state['csrf']})
            with urllib.request.urlopen(req) as r:assert r.status==200
        for headers in ({'Host':public_host},
                        {'Host':public_host,'Origin':'https://evil.example','X-CSRF-Token':state['csrf']},
                        {'Host':'vpn.example.com/path','X-CSRF-Token':state['csrf']},
                        {'Host':'user@vpn.example.com','X-CSRF-Token':state['csrf']}):
            with pytest.raises(urllib.error.HTTPError) as exc:
                urllib.request.urlopen(urllib.request.Request(base+'/api/session/forget',data=b'{}',headers=headers))
            assert exc.value.code==403
    finally:
        server.shutdown();server.server_close();thread.join()
