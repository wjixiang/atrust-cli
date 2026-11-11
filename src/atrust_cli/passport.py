"""aTrust controller "passport" API client (credential login).

Protocol recovered from the shipped login web bundle
(resources/app/web) and validated against the live tray logs:

- GET /passport/v1/public/authConfig?needTicket=1&mod=1 -> pubKey,
  pubKeyExp, antiReplayRand, csrfToken, authServerList
  (may return empty data for non-client callers)
- POST JSON /passport/v1/auth/psw {username, password(RSA hex),
  rememberPwd, graphCheckCode?} -> session or {graphCheckCodeEnable,
  antiReplayRand, currentService, nextService} state machine
- POST /passport/v1/public/sendSms / POST /passport/v1/auth/smsCheckCode -> SMS MFA
- password = RSA(password + "_" + antiReplayRand)  (see rsa_jssdk)

Every error response observed carries a fresh ``antiReplayRand`` which
can be used for the next attempt.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import tempfile
import ssl
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import Cookie, CookieJar
from pathlib import Path

from .rsa_jssdk import encrypt_to_hex

TRAY_UA = ("Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36 "
           "aTrustTray-Linux SPCClientType")
BROWSER_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")

ERR_PASSPORT_FAILED = 75500000


def is_rand_error(exc: PassportError) -> bool:
    """A fresh challenge alone does not identify a replay error.

    The official SDK calls 75500000 PASSPORT_FAILED (generic authentication
    failure). Only an explicit controller explanation warrants a retry.
    """
    return exc.code == ERR_PASSPORT_FAILED and bool(re.search(
        r"anti.?replay|antiReplayRand|随机数|防重放|"
        r"\brand\b.*(?:expir|invalid|error)|random.*(?:expir|invalid)",
        exc.message, re.I))


def is_captcha_error(exc: PassportError) -> bool:
    return (exc.data.get("graphCheckCodeEnable") in (True, 1, "1")
            or bool(re.search(r"图形验证码|图形校验码|captcha|graph.?check.?code",
                              exc.message, re.I)))


class PassportError(Exception):
    def __init__(self, code: int, message: str, data: dict | None = None) -> None:
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message
        self.data = data or {}


class PassportClient:
    def __init__(self, base_url: str, proxy: str | None = None,
                 timeout: float = 10.0, insecure: bool = False,
                 client_type: str = "SDPClient", user_agent: str = TRAY_UA) -> None:
        self.base = base_url.rstrip("/")
        parsed = urllib.parse.urlsplit(self.base)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username:
            raise ValueError("controller URL must be http(s)://host[:port], without userinfo")
        self.host = parsed.hostname
        self.authority = parsed.netloc
        self.timeout = timeout
        if client_type not in ("SDPClient", "SDPBrowserClient"):
            raise ValueError("unsupported authentication client type")
        if any(ord(c) < 32 for c in user_agent) or len(user_agent) > 512:
            raise ValueError("invalid authentication user agent")
        self.client_type = client_type
        self.user_agent = user_agent
        self.jar = CookieJar()
        handlers: list = [urllib.request.HTTPCookieProcessor(self.jar)]
        if proxy:
            handlers.append(urllib.request.ProxyHandler(
                {"http": proxy, "https": proxy}))
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
        self.opener = urllib.request.build_opener(*handlers)
        # anti-replay material, refreshed from every response that carries it
        self.anti_replay_rand: str | None = None
        self.pub_key: str | None = None
        self.pub_key_exp: int = 65537
        self.config: dict = {}
        self.csrf_token = ""
        self.device_id = secrets.token_hex(32)

    # ------------------------------------------------------------- plumbing
    def _request(self, method: str, path: str, body: dict | None = None,
                 query: dict | None = None,
                 redact: tuple[str, ...] = ()) -> dict:
        url = self.base + path
        query = {"clientType": self.client_type, "platform": "Linux", "lang": "zh-CN",
                 **(query or {})}
        url += "?" + urllib.parse.urlencode(query)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json;charset=utf-8")
        req.add_header("x-sdp-traceid", secrets.token_hex(4))
        req.add_header("User-Agent", self.user_agent)
        req.add_header("x-sdp-rid", base64.b64encode(self.authority.encode()).decode())
        req.add_header("Referer", self.base + "/portal/")
        if self.csrf_token:
            req.add_header("x-csrf-token", self.csrf_token)
        http_error = None
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            http_error = exc.code
            try:
                payload = json.loads(exc.read() or b"{}")
            except ValueError:
                raise PassportError(exc.code, str(exc)) from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise PassportError(-1, str(exc)) from exc
        if not isinstance(payload, dict):
            raise PassportError(-1, "invalid API response")
        self._absorb(payload.get("data") or {})
        code = payload.get("code")
        if code not in (0, "0") or http_error:
            try:
                code = int(code) if code is not None else http_error or -1
            except (ValueError, TypeError):
                code = -1
            # Preserve useful controller diagnostics, but never dump response data
            # or reflect passwords, challenges, cookies or session material.
            message = self._error_message(payload, body, redact)
            raise PassportError(code, message or "controller rejected " + path,
                                payload.get("data") or {})
        return payload

    def _error_message(self, payload: dict, body: dict | None,
                       redact: tuple[str, ...]) -> str:
        message = payload.get("message")
        if not isinstance(message, str):
            return ""
        hidden = [*redact, self.anti_replay_rand, self.csrf_token,
                  *(cookie.value for cookie in self.jar)]
        hidden.extend(value for value in (body or {}).values() if isinstance(value, str))
        def collect(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if re.search(r"password|ticket|token|cookie|rand|username|session|^sid", key, re.I):
                        if isinstance(item, str):
                            hidden.append(item)
                    collect(item)
            elif isinstance(value, list):
                for item in value:
                    collect(item)
        collect(payload.get("data"))
        collect(self.config)
        for value in sorted({v for v in hidden if v}, key=len, reverse=True):
            message = message.replace(value, "[redacted]")
        return " ".join(message.split())[:300]

    def _absorb(self, data: dict) -> None:
        if not isinstance(data, dict):
            return
        if data.get("antiReplayRand"):
            self.anti_replay_rand = data["antiReplayRand"]
        if data.get("pubKey"):
            self.pub_key = data["pubKey"]
            if data.get("pubKeyExp"):
                self.pub_key_exp = int(data["pubKeyExp"])
        security = data.get("security") or {}
        if security.get("csrfToken") or data.get("csrfToken"):
            self.csrf_token = security.get("csrfToken") or data["csrfToken"]

    # ---------------------------------------------------------------- APIs
    def auth_config(self, with_session: bool = False) -> dict:
        resp = self._request("GET", "/passport/v1/public/authConfig",
                             query={"needTicket": 1, **({} if with_session else {"mod": 1})})
        self.config = resp.get("data") or {}
        return resp

    def ticket_exchange(self) -> dict:
        return self._request("POST", "/passport/v1/public/ticketExchange", {})

    def session_id_exchange(self, ticket: str) -> dict:
        return self._request("POST", "/passport/v1/public/sessionIdExchange",
                             {"sidTicket": ticket})

    def report_browser_env(self, ticket: str) -> dict:
        """The SDK's non-native fallback; no endpoint trust claims are made."""
        return self._request("POST", "/controller/v1/public/reportEnv", {
            "ticket": ticket, "deviceId": self.device_id,
            "env": {"endpoint": {"device_id": self.device_id,
                                  "device": {"type": "browser"}}}})

    def export_cookies(self) -> list[dict]:
        fields = ("version", "name", "value", "port", "port_specified",
                  "domain", "domain_specified", "domain_initial_dot", "path",
                  "path_specified", "secure", "expires", "discard", "comment",
                  "comment_url", "rfc2109")
        return [{**{k: getattr(c, k) for k in fields}, "rest": c._rest}
                for c in self.jar]

    def import_cookies(self, cookies: list[dict]) -> None:
        for cookie in cookies:
            self.jar.set_cookie(Cookie(**cookie))

    def encrypt_password(self, password: str) -> str:
        if not self.pub_key:
            raise PassportError(-2, "no pubKey known — pass --pub-key or a "
                                    "working authConfig")
        if not self.anti_replay_rand:
            raise PassportError(-2, "no antiReplayRand supplied by authConfig")
        return encrypt_to_hex(f"{password}_{self.anti_replay_rand}",
                              self.pub_key, self.pub_key_exp)

    def psw_login(self, username: str, password: str,
                  graph_check_code: str | None = None,
                  remember: bool = False) -> dict:
        body: dict = {
            "username": username,
            "password": self.encrypt_password(password),
            "rememberPwd": "1" if remember else "0",
        }
        if graph_check_code:
            body["graphCheckCode"] = graph_check_code
        return self._request("POST", "/passport/v1/auth/psw", body,
                             redact=(password, username))

    def send_sms(self, username: str) -> dict:
        return self._request("POST", "/passport/v1/public/sendSms",
                             {"username": username})

    def check_sms_code(self, username: str, code: str) -> dict:
        return self._request("POST", "/passport/v1/auth/smsCheckCode",
                             {"username": username, "checkCode": code})

    def fetch_captcha(self, path: str = "/passport/v1/public/checkCode",
                      out: Path | None = None) -> Path | None:
        """Download the graph captcha image to a file for manual reading."""
        url = self.base + path + "?" + urllib.parse.urlencode({
            "clientType": self.client_type, "platform": "Linux", "lang": "zh-CN",
            "rnd": secrets.token_hex(8)})
        req = urllib.request.Request(url, headers={"User-Agent": self.user_agent,
                                     "Referer": self.base + "/portal/",
                                     "Cache-Control": "no-cache"})
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                blob = resp.read(1 << 20)
        except OSError:
            return None
        if not blob.startswith((b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n", b"GIF8")):
            return None
        if out is None:
            import os
            suffix = ".jpg" if blob.startswith(b"\xff\xd8") else ".png" if blob.startswith(b"\x89PNG") else ".gif"
            fd, name = tempfile.mkstemp(prefix="atrust-captcha-", suffix=suffix)
            with os.fdopen(fd, "wb") as f:
                f.write(blob)
            out = Path(name)
        else:
            out.write_bytes(blob)
        return out
