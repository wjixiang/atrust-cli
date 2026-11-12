"""Local management UI for the aTrust VM appliance; no framework dependencies."""
from __future__ import annotations

import argparse
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import threading
import time
from urllib.parse import urlsplit

from . import sessioncache
from .agent import AgentClient, AgentError, is_online, wait_for_stable_online, recent_logout_reason
from .passport import PassportClient, PassportError, is_captcha_error, BROWSER_UA
from .rpc import SdpCoreClient

ASSETS = Path(__file__).with_name("webui")


class Management:
    def __init__(self, server: str, allow_tunnel: bool = False):
        self.server = server.rstrip("/")
        self.isolated = allow_tunnel and any(Path(p).is_file() for p in
            ("/etc/atrust-vm-isolated", "/etc/atrust-runtime-isolated"))
        self.lock = threading.RLock()
        self.csrf = secrets.token_urlsafe(32)
        self.stage = "idle"
        self.message = "填写账号开始认证，或恢复已保存的会话。"
        self.username = ""
        self.client = None
        self.password = None
        self.password_deadline = 0.0
        self.password_timer = None
        self.response = {}
        self.captcha = b""
        self.captcha_version = 0
        self.sms_deadline = 0.0
        self.events = deque(maxlen=50)
        self.tunnel = "unavailable"
        self.tunnel_checked = 0.0
        self.connection_started = time.time()
        self.disconnect_reason = ""
        self.browser_user_agent = BROWSER_UA
        self.event("管理服务已启动；认证不会自动建立隧道。")

    def event(self, message):
        self.message = message
        self.events.append({"time": time.strftime("%H:%M:%S"), "message": message})

    def check_tunnel(self):
        if not self.isolated:
            self.tunnel = "unavailable"
            return
        if time.monotonic() - self.tunnel_checked < 3:
            return
        previous = self.tunnel
        try:
            self.tunnel = "online" if is_online(AgentClient(self.server, timeout=2).status()) else "offline"
        except AgentError:
            self.tunnel = "unavailable"
        self.tunnel_checked = time.monotonic()
        if previous == "online" and self.tunnel == "offline":
            self.connection_lost()

    def connection_lost(self):
        reason = recent_logout_reason(self.connection_started)
        self.disconnect_reason = ("服务器撤销了会话（cookieHijacking，会话一致性检查失败），请重新登录。"
                                  if reason == "cookieHijacking" else
                                  "VPN 连接已断开，请重新认证后再连接。")
        self.stage = "error"
        self.event(self.disconnect_reason)

    def state(self):
        if self.password is not None and time.monotonic() > self.password_deadline:
            self.password = None
            self.captcha = b""
            self.stage = "error"
            self.event("本次验证码操作已超时，请重新输入密码。")
        self.check_tunnel()
        saved = sessioncache.load()
        return {"stage": self.stage, "message": self.message,
                "username": self.username, "server": self.server,
                "session_available": bool(saved), "cookie_count": len((saved or {}).get("cookies") or []),
                "proxy_address": os.environ.get("ATRUST_SOCKS_ADDRESS", "127.0.0.1:10808"),
                "disconnect_reason": self.disconnect_reason, "tunnel": self.tunnel, "isolated": self.isolated, "csrf": self.csrf,
                "events": list(self.events), "captcha_version": self.captcha_version,
                "sms_retry_after": max(0, int(self.sms_deadline - time.monotonic()) + 1)}

    def persist(self, response):
        self.response = response
        if not self.client:
            return
        cookies = self.client.export_cookies()
        data = response.get("data") or {}
        if not cookies and not data.get("sidTicket"):
            return
        sessioncache.save({"url": self.server, "username": self.username,
                           "cookies": cookies, "config": self.client.config,
                           "device_id": self.client.device_id, "auth_response": response,
                           "sid_ticket": data.get("sidTicket"), "ticket_saved_at": time.time(),
                           "auth_stage": self.stage,
                           "client_type": self.client.client_type, "user_agent": self.client.user_agent})

    def fetch_captcha(self):
        if time.monotonic() > self.password_deadline:
            self.password = None
            self.captcha = b""
            self.stage = "error"
            raise ValueError("验证码会话已超时，请重新登录。")
        if not self.client or not self.password:
            raise ValueError("请先输入账号和密码。")
        image = self.client.fetch_captcha()
        if not image:
            raise ValueError("无法获取验证码，请检查虚拟机网络后重试。")
        try:
            self.captcha = image.read_bytes()
        finally:
            image.unlink(missing_ok=True)
        self.captcha_version += 1
        self.stage = "captcha"
        self.event("请按图片底部提示的顺序点击三个字符。")

    def advance(self, response):
        """Complete only remote authentication steps, never auto-start a tunnel."""
        self.password = None
        self.captcha = b""
        self.stage = "idle"
        for _ in range(5):
            self.persist(response)
            data = response.get("data") or {}
            if (data.get("env") or {}).get("need") and data.get("ticket"):
                self.client.report_browser_env(data["ticket"])
            step = data.get("nextService") or ""
            if step == "auth/authCheck":
                response = self.client._request("GET", "/passport/v1/auth/authCheck")
            elif step == "auth/accessCheck":
                response = self.client._request("POST", "/passport/v1/auth/accessCheck", {},
                                                query={"rnd": time.time_ns()})
            elif step == "auth/sms":
                self.stage = "sms"
                self.persist(response)
                self.event("密码验证已通过，请发送并填写绑定手机收到的短信验证码。")
                return
            elif not step:
                ticket = self.client.ticket_exchange()
                if not (ticket.get("data") or {}).get("sidTicket"):
                    raise ValueError("控制器未签发票据，尚不能确认认证成功。")
                self.stage = "authenticated"
                self.persist(ticket)
                self.event("认证成功，会话已加密保存；隧道尚未自动连接。")
                return
            else:
                self.stage = "error"
                self.event("服务器要求此界面尚不支持的额外认证步骤。")
                return
        raise ValueError("认证步骤过多，请检查服务器策略。")

    def begin(self, payload):
        username, password = payload.get("username"), payload.get("password")
        if not isinstance(username, str) or not username.strip() or not isinstance(password, str) or not password:
            raise ValueError("请填写账号和密码。")
        if len(username) > 256 or len(password) > 1024:
            raise ValueError("账号或密码过长。")
        self.disconnect_reason = ""
        self.username = username.strip()
        self.stage = "idle"
        self.password = password
        self.password_deadline = time.monotonic() + 300
        if self.password_timer:
            self.password_timer.cancel()
        deadline = self.password_deadline
        def expire():
            with self.lock:
                if self.password is not None and self.password_deadline == deadline:
                    self.password = None
                    self.captcha = b""
                    self.stage = "error"
                    self.event("本次验证码操作已超时，请重新输入密码。")
        self.password_timer = threading.Timer(300, expire)
        self.password_timer.daemon = True
        self.password_timer.start()
        self.client = PassportClient(self.server, timeout=15,
                                     client_type="SDPBrowserClient", user_agent=self.browser_user_agent)
        self.response = {}
        self.captcha = b""
        self.sms_deadline = 0
        self.client.auth_config()
        if not self.client.pub_key or not self.client.anti_replay_rand:
            raise ValueError("控制器没有提供完整认证配置。")
        try:
            response = self.client.psw_login(self.username, password)
        except PassportError as exc:
            if is_captcha_error(exc):
                self.fetch_captcha()
                return
            raise
        self.advance(response)

    def submit_captcha(self, payload):
        self.state()  # enforce the in-memory password lifetime
        if self.stage != "captcha" or not self.password:
            raise ValueError("验证码会话已失效，请重新登录。")
        coordinates = payload.get("coordinates")
        if payload.get("width") != 272 or payload.get("height") != 192:
            raise ValueError("验证码图片尺寸不匹配，请刷新验证码。")
        if not isinstance(coordinates, list) or len(coordinates) != 3:
            raise ValueError("请按顺序点击三个字符。")
        for point in coordinates:
            if (not isinstance(point, list) or len(point) != 2
                    or any(type(v) not in (int, float) for v in point)
                    or not 0 <= point[0] < 272 or not 0 <= point[1] < 160):
                raise ValueError("点击位置必须位于验证码图像内。")
        encoded = json.dumps({"coordinates": coordinates, "width": 272, "height": 192}, separators=(",", ":"))
        try:
            response = self.client.psw_login(self.username, self.password, encoded)
        except PassportError as exc:
            if is_captcha_error(exc):
                self.fetch_captcha()
                self.event("验证码未通过，已刷新，请重新点击。")
                return
            raise
        self.advance(response)

    def send_sms(self):
        if self.stage != "sms" or not self.client:
            raise ValueError("当前不处于短信验证步骤。")
        if time.monotonic() < self.sms_deadline:
            raise ValueError("请等待倒计时结束后再发送短信。")
        data = (self.response.get("data") or {})
        response = self.client._request("GET", "/passport/v1/auth/sms", query={
            "action": "sendsms", "isPrevEffect": "0", "taskId": data.get("taskId") or ""})
        interval = (response.get("data") or {}).get("interval") or 60
        self.sms_deadline = time.monotonic() + min(300, max(1, int(interval)))
        self.persist(self.response)
        self.event("短信发送请求已被服务器接受，请填写验证码。")

    def verify_sms(self, payload):
        code = payload.get("code")
        if self.stage != "sms" or not self.client:
            raise ValueError("当前不处于短信验证步骤。")
        if not isinstance(code, str) or not code.isdigit() or not 4 <= len(code) <= 10:
            raise ValueError("请填写有效的短信验证码。")
        data = self.response.get("data") or {}
        response = self.client._request("POST", "/passport/v1/auth/sms", {
            "isPrevEffect": "0", "code": code, "skipSecondaryAuth": "0",
            "taskId": data.get("taskId") or ""}, query={"action": "checkcode"}, redact=(code,))
        self.advance(response)

    def restore(self):
        saved = sessioncache.load()
        if not saved or saved.get("url") != self.server:
            raise ValueError("没有可用于此服务器的已保存会话。")
        if saved.get("client_type") != "SDPBrowserClient":
            raise ValueError("旧会话使用不同的客户端身份，请重新登录。")
        self.disconnect_reason = ""
        self.password = None
        self.username = saved.get("username") or ""
        self.client = PassportClient(self.server, timeout=15,
                                     client_type="SDPBrowserClient",
                                     user_agent=saved.get("user_agent") or BROWSER_UA)
        self.client.import_cookies(saved.get("cookies") or [])
        self.client.device_id = saved.get("device_id") or self.client.device_id
        self.client.auth_config(with_session=True)
        pending = saved.get("auth_response") or {}
        if (pending.get("data") or {}).get("nextService") == "auth/sms":
            self.stage = "sms"
            self.response = pending
            self.event("已恢复待完成的短信验证，请发送或填写验证码。")
            return
        self.advance(self.client.ticket_exchange())

    def connect(self):
        if not self.isolated:
            raise ValueError("只允许在已配置的隔离隔离环境内建立隧道。")
        if self.stage != "authenticated" or not self.client:
            raise ValueError("请先完成认证。")
        self.client.auth_config(with_session=True)
        agent = AgentClient(self.server, timeout=10)
        agent.init(self.client.config)
        self.connection_started = time.time()
        self.disconnect_reason = ""
        if not is_online(agent.status()):
            response = self.client.ticket_exchange()
            ticket = (response.get("data") or {}).get("sidTicket")
            if not ticket:
                raise ValueError("无法取得建立隧道所需的票据。")
            self.persist(response)
            agent.start(ticket)
        try:
            wait_for_stable_online(agent)
        except AgentError as exc:
            self.tunnel = "offline"
            self.tunnel_checked = 0
            self.connection_lost()
            raise ValueError(self.message) from exc
        self.tunnel = "online"
        self.tunnel_checked = time.monotonic()
        self.event("VPN 已在隔离环境内持续在线，宿主机网络保持隔离。")

    def disconnect(self):
        if not self.isolated:
            raise ValueError("当前服务不允许管理宿主机连接。")
        if not SdpCoreClient(timeout=5).offline():
            raise ValueError("后台未确认断开请求，请检查连接状态。")
        self.tunnel = "offline"
        self.tunnel_checked = 0
        self.check_tunnel()
        self.event("已向隔离环境内的 aTrust 发送离线请求。")

    def action(self, path, payload):
        actions = {"/api/auth/begin": lambda: self.begin(payload),
                   "/api/auth/captcha": lambda: self.submit_captcha(payload),
                   "/api/auth/captcha/refresh": self.fetch_captcha,
                   "/api/auth/sms/send": self.send_sms,
                   "/api/auth/sms/verify": lambda: self.verify_sms(payload),
                   "/api/auth/restore": self.restore,
                   "/api/tunnel/connect": self.connect,
                   "/api/tunnel/disconnect": self.disconnect,
                   "/api/session/forget": self.forget}
        if path not in actions:
            raise ValueError("未知操作。")
        try:
            actions[path]()
        except PassportError as exc:
            # Keep a pending SMS/captcha screen usable after a rejected answer.
            if self.stage not in ("captcha", "sms"):
                self.stage = "error"
                self.password = None
            self.event(str(exc))
            raise ValueError(str(exc)) from exc
        except (AgentError, OSError) as exc:
            self.password = None
            self.event("后台请求失败，请检查虚拟机网络和 aTrust 服务。")
            raise ValueError(self.message) from exc
        return self.state()

    def forget(self):
        self.check_tunnel()
        if self.tunnel == "online":
            raise ValueError("请先断开隧道，再清除会话。")
        sessioncache.clear()
        self.client = None
        self.password = None
        self.response = {}
        self.captcha = b""
        self.stage = "idle"
        self.event("本地会话已清除。")


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, manager, allow_remote=False):
        self.manager = manager
        self.allow_remote = allow_remote
        super().__init__(address, Handler)


class Handler(BaseHTTPRequestHandler):
    server_version = "aTrust-Manager"

    def log_message(self, *args):
        pass  # never log authentication bodies, query strings or headers

    def safe_host(self):
        hosts = self.headers.get_all("Host", [])
        if len(hosts) != 1:
            return False
        host = hosts[0]
        try:
            parsed = urlsplit("//" + host)
            if (not parsed.hostname or parsed.netloc != host or parsed.path
                    or parsed.query or parsed.fragment or parsed.username is not None
                    or parsed.password is not None or any(c.isspace() for c in host)):
                return False
            if parsed.port is not None and not 1 <= parsed.port <= 65535:
                return False
            return self.server.allow_remote or parsed.hostname in ("127.0.0.1", "localhost", "::1")
        except ValueError:
            return False

    def safe_origin(self):
        origin = self.headers.get("Origin")
        if origin is None:
            return True
        host = self.headers.get("Host", "")
        schemes = ("http", "https") if self.server.allow_remote else ("http",)
        return origin in {scheme + "://" + host for scheme in schemes}

    def reply(self, code, body, content_type="application/json; charset=utf-8"):
        if not isinstance(body, bytes):
            body = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self.safe_host():
            return self.reply(403, {"error": "仅允许通过本机地址访问管理界面。"})
        path = urlsplit(self.path).path
        manager = self.server.manager
        with manager.lock:
            if path == "/api/state":
                return self.reply(200, manager.state())
            if path == "/api/captcha":
                if not manager.captcha:
                    return self.reply(404, {"error": "没有待显示的验证码。"})
                return self.reply(200, manager.captcha, "image/jpeg")
        files = {"/": ("index.html", "text/html; charset=utf-8"),
                 "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                 "/style.css": ("style.css", "text/css; charset=utf-8")}
        if path in files:
            filename, content_type = files[path]
            return self.reply(200, (ASSETS / filename).read_bytes(), content_type)
        return self.reply(404, {"error": "Not found"})

    def do_POST(self):
        manager = self.server.manager
        if (not self.safe_host()
                or not self.safe_origin()
                or not secrets.compare_digest(self.headers.get("X-CSRF-Token", ""), manager.csrf)):
            return self.reply(403, {"error": "请求校验失败，请刷新页面。"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 16384:
                return self.reply(413, {"error": "请求内容过大或为空。"})
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                raise ValueError("请求格式错误。")
            with manager.lock:
                if urlsplit(self.path).path == "/api/auth/begin":
                    manager.browser_user_agent = self.headers.get("User-Agent") or BROWSER_UA
                result = manager.action(urlsplit(self.path).path, payload)
            return self.reply(200, result)
        except (ValueError, TypeError) as exc:
            with manager.lock:
                return self.reply(400, {"error": str(exc), "state": manager.state()})
        except Exception:
            return self.reply(500, {"error": "操作失败，请检查虚拟机服务日志。"})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--server", default="https://vpn.csu.edu.cn")
    parser.add_argument("--allow-tunnel", action="store_true")
    parser.add_argument("--allow-remote", action="store_true", help="allow remote Host headers for public/reverse-proxy access")
    args = parser.parse_args(argv)
    server = Server((args.listen, args.port), Management(args.server, args.allow_tunnel), allow_remote=args.allow_remote)
    print(f"aTrust management: http://{args.listen}:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
