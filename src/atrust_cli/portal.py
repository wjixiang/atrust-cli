"""Controller (SDPC portal) probing — mirrors onSdpcConnDetect in the tray.

The tray's first step after a user types the VPN address is a plain GET to
``/public/manifest`` (see sdpc_request.js / SUBPATH_MANIFEST).
"""

from __future__ import annotations

import json
import ssl
import urllib.request
from dataclasses import dataclass, field

MANIFEST_PATH = "/public/manifest"
TIMEOUT = 5.0


@dataclass
class ManifestResult:
    url: str
    real_url: str = ""
    connect_ok: bool = False
    error: str = ""
    server: str = ""
    is_atrust: bool = False
    capacities: dict = field(default_factory=dict)
    options: dict = field(default_factory=dict)

    def summary_lines(self) -> list[tuple[str, str]]:
        out = [
            ("address", self.url),
            ("real address", self.real_url or self.url),
            ("reachable", "yes" if self.connect_ok else "no"),
        ]
        if self.error:
            out.append(("error", self.error))
        if self.server:
            out.append(("server", self.server))
            out.append(("aTrust controller", "yes" if self.is_atrust else "no"))
        keys = ("spaSeed", "quickSocks5", "antiMITMAttack", "adaptiveAuth",
                "standaloneClient", "linuxWorkSpace", "weakPwd", "forgetPassword")
        caps = self.capacities or {}
        supported = [k for k in keys if k in caps]
        if supported:
            out.append(("capabilities", ", ".join(supported)))
        return out


def probe_manifest(url: str, timeout: float = TIMEOUT,
                   insecure: bool = False) -> ManifestResult:
    """GET {url}/public/manifest and classify the controller."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    result = ManifestResult(url=url)
    target = url.rstrip("/") + MANIFEST_PATH
    req = urllib.request.Request(target, headers={"User-Agent": "atrust-cli/0.1"})
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(1 << 20)
            result.real_url = resp.geturl().rsplit(MANIFEST_PATH, 1)[0]
    except Exception as exc:  # noqa: BLE001 — surface any network error
        result.error = str(exc)
        return result
    try:
        data = json.loads(body)
    except ValueError:
        result.error = "manifest is not JSON"
        return result
    result.connect_ok = True
    if data.get("code") != 0:
        result.error = f"controller error code {data.get('code')}: {data.get('message')}"
        return result
    payload = data.get("data") or {}
    result.server = str(payload.get("server", ""))
    result.is_atrust = "aTrust" in result.server
    result.capacities = payload.get("capacities") or {}
    result.options = payload.get("options") or {}
    return result
