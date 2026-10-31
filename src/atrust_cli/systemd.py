"""systemd unit and process helpers for the aTrust services."""

from __future__ import annotations

import shutil
import subprocess

DAEMON_UNIT = "aTrustDaemon.service"
TRAY_UNIT = "aTrustTray.service"          # user unit
TRAY_START_SH = "/usr/share/sangfor/aTrust/resources/shell/aTrustTrayStart.sh"
DAEMON_SH = "/usr/share/sangfor/aTrust/resources/shell/aTrustDaemon.sh"


def _systemctl(*args: str, user: bool = False) -> subprocess.CompletedProcess:
    cmd = ["systemctl"]
    if user:
        cmd.append("--user")
    cmd += list(args)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30)


def unit_state(unit: str, user: bool = False) -> str:
    """Active state of a unit: active/inactive/failed/not-found/..."""
    proc = _systemctl("show", unit, "--property=ActiveState,SubState,UnitFileState",
                      user=user)
    if proc.returncode != 0:
        return "not-found"
    state: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            state[k] = v
    active = state.get("ActiveState", "unknown")
    sub = state.get("SubState", "")
    enabled = state.get("UnitFileState", "")
    return f"{active}({sub}){f' [{enabled}]' if enabled else ''}"


def daemon_alive() -> bool:
    return "active" == _show_state(DAEMON_UNIT).get("ActiveState")


def _show_state(unit: str, user: bool = False) -> dict[str, str]:
    proc = _systemctl("show", unit, "--property=ActiveState,SubState", user=user)
    out: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k] = v
    return out


def start_daemon() -> subprocess.CompletedProcess:
    return _systemctl("start", DAEMON_UNIT)


def stop_daemon() -> subprocess.CompletedProcess:
    return _systemctl("stop", DAEMON_UNIT)


def restart_daemon() -> subprocess.CompletedProcess:
    return _systemctl("restart", DAEMON_UNIT)


def daemon_processes() -> list[str]:
    """Names of running aTrust processes present on this machine.

    Uses ``pgrep -f`` with path anchors: pgrep matches the 15-char comm,
    which truncates names like aTrustXtunnel-64 (16 chars).
    """
    patterns = {
        "aTrustAgent": "bin/aTrustAgent",
        "aTrustTray": "aTrust/aTrustTray",
        "aTrustTray2": "bin/aTrustTray2",
        "aTrustXtunnel-64": "bin/aTrustXtunnel-64",
        "aTrustDaemon": "bin/aTrustAgent",
    }
    pgrep = shutil.which("pgrep")
    found: list[str] = []
    for name, pattern in patterns.items():
        if pgrep and subprocess.run([pgrep, "-f", pattern],
                                    capture_output=True).returncode == 0:
            if name not in found:
                found.append(name)
    return found
