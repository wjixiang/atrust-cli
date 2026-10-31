"""aTrust controller "passport" API client (credential login).

Protocol recovered from the shipped login web bundle
(resources/app/web) and validated against the live tray logs:

- POST /passport/v1/public/authConfig {needTicket, mod}  -> pubKey,
  pubKeyExp, antiReplayRand, csrfToken, authServerList
  (may return empty data for non-client callers)
- POST /passport/v1/auth/psw {username, password(RSA hex),
  rememberPwd, graphCheckCode?} -> session or {graphCheckCodeEnable,
  antiReplayRand, currentService, nextService} state machine
- GET  /passport/v1/auth/sms / POST /passport/v1/auth/smsCheckCode  -> SMS MFA
- password = RSA(password + "_" + antiReplayRand)  (see rsa_jssdk)

Every error response observed carries a fresh ``antiReplayRand`` which
can be used for the next attempt.
"""

from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from pathlib import Path

from .rsa_jssdk import encrypt_to_hex

TRAY_UA = ("Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36 "
           "aTrustTray-Linux SPCClientType")

ERR_RAND_EXPIRED = 75500000


class PassportError(Exception):
    def __init__(self, code: int, message: str, data: dict | None = None) -> None:
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message
        self.data = data or {}


class PassportClient:
    def __init__(self, base_url: str, proxy: str | None = None,
                 timeout: float = 10.0, insecure: bool = False) -> None:
        self.base = base_url.rstrip("/")
        self.host = urllib.parse.urlparse(self.base).hostname or ""
        self.timeout = timeout
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

    # ------------------------------------------------------------- plumbing
    def _request(self, method: str, path: str, body: dict | None = None,
                 query: dict | None = None) -> dict:
        url = self.base + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", TRAY_UA)
        req.add_header("x-sdp-rid", base64.b64encode(self.host.encode()).decode())
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            try:
                payload = json.loads(exc.read() or b"{}")
            except ValueError:
                raise PassportError(exc.code, str(exc)) from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise PassportError(-1, str(exc)) from exc
        self._absorb(payload.get("data") or {})
        return payload

    def _absorb(self, data: dict) -> None:
        if not isinstance(data, dict):
            return
        if data.get("antiReplayRand"):
            self.anti_replay_rand = data["antiReplayRand"]
        if data.get("pubKey"):
            self.pub_key = data["pubKey"]
            if data.get("pubKeyExp"):
                self.pub_key_exp = int(data["pubKeyExp"])

    # ---------------------------------------------------------------- APIs
    def auth_config(self) -> dict:
        return self._request("POST", "/passport/v1/public/authConfig",
                             {"needTicket": 1, "mod": 1},
                             query={"clientType": "SDPClient",
                                    "platform": "Linux", "lang": "zh-CN"})

    def encrypt_password(self, password: str) -> str:
        if not self.pub_key:
            raise PassportError(-2, "no pubKey known — pass --pub-key or a "
                                    "working authConfig")
        if not self.anti_replay_rand:
            raise PassportError(-2, "no antiReplayRand yet — bootstrap needed")
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
                             query={"clientType": "SDPClient",
                                    "platform": "Linux", "lang": "zh-CN"})

    def send_sms(self, username: str) -> dict:
        return self._request("GET", "/passport/v1/auth/sms",
                             query={"username": username, "clientType": "SDPClient",
                                    "platform": "Linux", "lang": "zh-CN"})

    def check_sms_code(self, username: str, code: str) -> dict:
        return self._request("POST", "/passport/v1/auth/smsCheckCode",
                             {"username": username, "checkCode": code})

    def fetch_captcha(self, path: str = "/passport/v1/public/graphCheckCodePath",
                      out: Path | None = None) -> Path | None:
        """Download the graph captcha image to a file for manual reading."""
        url = self.base + path
        req = urllib.request.Request(url, headers={"User-Agent": TRAY_UA})
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                blob = resp.read(1 << 20)
        except OSError:
            return None
        out = out or Path(f"/tmp/atrust-captcha.png")
        out.write_bytes(blob)
        return out
