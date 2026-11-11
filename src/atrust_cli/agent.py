"""Local HTTPS API used by the shipped aTrust web SDK (2.5.16.30).

The agent has a local certificate; certificate verification is disabled ONLY
for this fixed loopback endpoint. Environment HTTP proxies are never used.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
import re
import secrets
import ssl
import urllib.error
import urllib.request
import urllib.parse
import time

from . import paths
from .passport import TRAY_UA


class AgentError(Exception):
    pass


def wait_for_stable_online(agent, timeout=30, stable_seconds=5,
                           clock=time.monotonic, sleep=time.sleep):
    """A core login pulse is not proof of a working, retained connection."""
    end = clock() + timeout
    since = None
    while clock() < end:
        status = agent.status()
        now = clock()
        if is_online(status):
            if since is None:
                since = now
            if now - since >= stable_seconds:
                return status
        elif since is not None:
            raise AgentError("connection returned offline before stabilization")
        sleep(0.5)
    raise AgentError("connection did not remain online within the timeout")


def recent_logout_reason(since: float) -> str | None:
    """Read only an allowlisted enum, never expose native log payloads."""
    path = Path.home() / ".aTrust/logs/aTrustAgent_plugins_aTrustCore_h_e.log"
    allowed = {"cookieHijacking", "relogin", "timeout", "SessionExpiration",
               "passportTokenOffline", "passportTokenLogout", "passportTokenTimeout",
               "passportTokenInvalid", "self", "admin", "clientexit"}
    try:
        with path.open("rb") as f:
            f.seek(max(0, path.stat().st_size - 262144))
            lines = f.read().decode(errors="replace").splitlines()
        for line in reversed(lines):
            match = re.search(r"^\[([\d -]+[\d:.]+)\].*Set logout type to '([A-Za-z]+)' success", line)
            if match and match[2] in allowed:
                stamp = datetime.strptime(match[1], "%Y-%m-%d %H:%M:%S.%f").timestamp()
                if stamp >= since:
                    return match[2]
    except (OSError, ValueError):
        pass
    return None


def is_online(status: object) -> bool:
    if not isinstance(status, dict):
        return False
    if "status" in status:
        return str(status["status"]).lower() in ("online", "3")
    # GetAllStatus is a map<controller-guid, numeric-state> on this build.
    return any(type(value) in (str, int) and str(value) == "3"
               for value in status.values())


class AgentClient:
    def __init__(self, url: str, timeout: float = 10.0):
        self.url = url.rstrip("/")
        self.timeout = timeout
        try:
            port = int((paths.RPC_DIR / "httpserver").read_text().strip())
        except (OSError, ValueError):
            port = 54630
        if not 1 <= port <= 65535:
            raise AgentError("invalid local agent port")
        self.base = f"https://127.0.0.1:{port}"
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ctx), _NoRedirect())
        self.guid = ""

    def request(self, path: str, data: dict) -> dict:
        envelope = {"addr": self.url, "type": "web", "guid": self.guid,
                    "lang": "zh-CN", "token": "", "data": data,
                    "sdpTraceId": secrets.token_hex(4)}
        req = urllib.request.Request(
            self.base + path, json.dumps(envelope).encode(),
            {"Content-Type": "application/json", "User-Agent": TRAY_UA,
             "Referer": self.url + "/portal/"}, method="POST")
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                result = json.load(resp)
        except (OSError, ValueError, urllib.error.URLError) as exc:
            raise AgentError(f"local agent request failed: {path} "
                             f"({type(exc).__name__})") from exc
        if not isinstance(result, dict) or result.get("code") not in (0, "0"):
            code = result.get("code") if isinstance(result, dict) else "invalid"
            raise AgentError(f"local agent rejected {path} (code {code})")
        return result

    def init(self, config: dict) -> dict:
        self.guid = config.get("guid") or ""
        if not config.get("pubKey") or not config.get("clientVerifyCode"):
            raise AgentError("authConfig missing pubKey/clientVerifyCode; "
                             "cannot initialize the official agent")
        result = self.request("/v1/service/init", {
            "verifyCode": config["clientVerifyCode"],
            "pubKey": config["pubKey"], "disAllowSecurityRiskPopup": 1})
        security = result.get("security") or {}
        if security.get("riskType") in ("phishing-attack", "suspected-phishing-attack"):
            raise AgentError("agent requires interactive server verification")
        data = result.get("data") or {}
        if data.get("addr"):
            actual = urllib.parse.urlsplit(data["addr"])
            expected = urllib.parse.urlsplit(self.url)
            if (actual.scheme, actual.hostname, actual.port) != (
                    expected.scheme, expected.hostname, expected.port):
                raise AgentError("agent session belongs to a different controller")
        return data

    def start(self, ticket: str) -> None:
        if not ticket:
            raise AgentError("no sidTicket available; tunnel was not started")
        self.request("/v1/service/start", {"sidTicket": ticket})

    def status(self) -> dict:
        result = self.request("/v1/service/status", {})
        return result.get("data") or {}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Tickets must never follow redirects away from loopback.
        return None
