"""Filesystem layout of the installed Sangfor aTrust client (Linux/UOS build).

Recovered from atrust-2.5.16.30.deb (package cn.com.sangfor.atrust).
"""

from __future__ import annotations

import json
from pathlib import Path

INSTALL_ROOT = Path("/usr/share/sangfor/aTrust")
RESOURCES = INSTALL_ROOT / "resources"
BIN = RESOURCES / "bin"
SHELL = RESOURCES / "shell"
AGENT_DIR = Path("/usr/share/sangfor/.aTrust")          # shared state, chmod 777
RPC_DIR = AGENT_DIR / "var" / "run"                     # thrift named pipes
PROXY_SERVER_FILE = AGENT_DIR / "var" / "run" / "proxyServer"

SYSTEM_UNITS = ["aTrustDaemon.service"]
USER_UNITS = ["aTrustTray.service", "aTrustShell.service"]

LOG_DIRS = [
    Path.home() / ".aTrust" / "logs",
    Path("/root/.aTrust/logs"),
]

# Named pipes (Thrift servers) discovered in
# resources/app/src/service/util/rpc_client.js
PIPES = {
    "core": "aTrustCore-fcd60898-3ef4-423f-acc9-3b28dc0e9e22",
    "daemon": "aTrustDaemon-8ec18c00-3768-4a5c-b2d7-da2a0f1b2167",
    "tunnel": "aTrustTunnel-c46a26c5-2cd4-4c20-9352-8efbb6358ea0",
    "qttray": "aTrustQtTray-8c34c862-7858-4775-b3d4-071a26b77bfe",
    "diagnosis": "aTrustDiagnosisTool-d7c5f5c5-7c5d-4c5e-9c5f-5c5d7c5e9c5f",
}


def pipe_path(name: str) -> Path:
    return RPC_DIR / PIPES[name]


def client_version() -> str | None:
    """aTrust client version from resources/version (JSON)."""
    try:
        data = json.loads((RESOURCES / "version").read_text(encoding="utf-8"))
        return data.get("main", {}).get("version")
    except (OSError, ValueError):
        return None


def electron_version() -> str | None:
    try:
        return (INSTALL_ROOT / "version").read_text(encoding="utf-8").strip()
    except OSError:
        return None
