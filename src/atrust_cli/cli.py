"""atrust command line interface."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from . import __version__
from . import paths, systemd
from .rpc import SdpCoreClient
from .thrift import ThriftError

STATUS_NAMES = {0: "OFFLINE", 1: "BINDING", 2: "RECOVERING", 3: "ONLINE"}


# ---------------------------------------------------------------- output ---
def _c(code: str, text: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


def ok(text: str) -> str:
    return _c("32", text)


def warn(text: str) -> str:
    return _c("33", text)


def err(text: str) -> str:
    return _c("31", text)


def bold(text: str) -> str:
    return _c("1", text)


def emit_map(data: dict | None, title: str, as_json: bool) -> None:
    if as_json:
        print(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True))
        return
    print(bold(f"{title}:"))
    if not data:
        print(f"  {warn('(empty response)')}")
        return
    for key in sorted(data):
        value = data[key]
        if key.lower() in ("status", "state", "tunnelstatus") and str(value).isdigit():
            value = f"{value} ({STATUS_NAMES.get(int(value), '?')})"
        print(f"  {key:<32} {value}")


# --------------------------------------------------------------- commands ---
def cmd_status(args: Any) -> int:
    as_json = args.json
    core = SdpCoreClient(timeout=args.timeout)

    if not paths.RPC_DIR.is_dir() or not paths.pipe_path("core").exists():
        print(err("aTrust RPC pipe not found — is the aTrust client installed "
                  "and the daemon running?"))
        print(f"  expected: {paths.pipe_path('core')}")
        return 2

    status: dict | None = None
    try:
        status = core.get_all_status() if args.all else core.get_status()
    except ThriftError as exc:
        print(err(f"RPC failed: {exc}"))
        if not systemd.daemon_alive():
            print(warn("aTrustDaemon is not active — try: atrust service start"))
        return 1

    emit_map(status, "aTrust status" + (" (all)" if args.all else ""), as_json)
    if not as_json:
        print()
        print(f"{bold('daemon')}: {systemd.unit_state(systemd.DAEMON_UNIT)}")
        procs = systemd.daemon_processes()
        print(f"{bold('processes')}: "
              f"{', '.join(ok(p) for p in procs) if procs else warn('none')}")
        ver = paths.client_version()
        if ver:
            print(f"{bold('client')}: {ver} (electron {paths.electron_version()})")
    return 0


def cmd_logout(args: Any) -> int:
    core = SdpCoreClient(timeout=args.timeout)
    try:
        result = core.logout(type_=args.type)
    except ThriftError as exc:
        print(err(f"RPC failed: {exc}"))
        return 1
    if result:
        print(ok("logged out"))
        return 0
    print(warn("logout returned false (maybe already offline)"))
    return 0


def cmd_spa(args: Any) -> int:
    core = SdpCoreClient(timeout=args.timeout)
    try:
        has_seed = core.query_spa_seed_exist(args.url)
        info = core.get_spa_info(args.url)
    except ThriftError as exc:
        print(err(f"RPC failed: {exc}"))
        return 1
    print(f"{bold('SPA seed present')}: {ok('yes') if has_seed else warn('no')}")
    emit_map(info, "SPA info", args.json)
    return 0


def cmd_config(args: Any) -> int:
    core = SdpCoreClient(timeout=args.timeout)
    try:
        cfg = core.get_sdp_config()
    except ThriftError as exc:
        print(err(f"RPC failed: {exc}"))
        return 1
    emit_map(cfg, "SDP config", args.json)
    return 0


def cmd_service(args: Any) -> int:
    action = args.action
    if action == "status":
        print(f"{bold('aTrustDaemon')}: {systemd.unit_state(systemd.DAEMON_UNIT)}")
        print(f"{bold('aTrustTray (user)')}: "
              f"{systemd.unit_state(systemd.TRAY_UNIT, user=True)}")
        return 0
    fn = {"start": systemd.start_daemon,
          "stop": systemd.stop_daemon,
          "restart": systemd.restart_daemon}[action]
    proc = fn()
    if proc.returncode == 0:
        print(ok(f"aTrustDaemon {action}ed"))
        return 0
    print(err(f"systemctl {action} failed ({proc.returncode}):"))
    print((proc.stderr or proc.stdout).strip())
    print(warn("root privileges are required — retry with sudo."))
    return 1


def cmd_doctor(args: Any) -> int:
    checks: list[tuple[str, bool, str]] = []

    checks.append(("install dir", paths.INSTALL_ROOT.is_dir(),
                   str(paths.INSTALL_ROOT)))
    checks.append(("resources/bin", paths.BIN.is_dir(), str(paths.BIN)))
    ver = paths.client_version()
    checks.append(("client version", ver is not None, ver or "missing"))
    checks.append(("electron version", paths.electron_version() is not None,
                   paths.electron_version() or "missing"))
    checks.append(("shared state dir", paths.AGENT_DIR.is_dir(),
                   str(paths.AGENT_DIR)))
    checks.append(("RPC pipe dir", paths.RPC_DIR.is_dir(), str(paths.RPC_DIR)))
    for name in paths.PIPES:
        p = paths.pipe_path(name)
        checks.append((f"pipe [{name}]", p.exists(), str(p)))

    checks.append(("aTrustDaemon active", systemd.daemon_alive(),
                   systemd.unit_state(systemd.DAEMON_UNIT)))
    procs = systemd.daemon_processes()
    checks.append(("processes", True, ", ".join(procs) if procs else "none running"))

    core = SdpCoreClient(timeout=2.0)
    try:
        normal = core.is_rpc_status_normal()
    except ThriftError as exc:
        normal = None
        msg = str(exc)
    else:
        msg = ""
    checks.append(("core RPC", normal is True, msg or str(normal)))

    failed = 0
    print(bold("aTrust environment doctor"))
    for name, good, detail in checks:
        mark = ok("✔") if good else err("✘")
        if not good:
            failed += 1
        print(f" {mark} {name:<22} {detail}")
    if failed:
        print(f"\n{warn(f'{failed} check(s) failed')}")
    else:
        print(f"\n{ok('all checks passed')}")
    return 1 if failed else 0


def cmd_logs(args: Any) -> int:
    import subprocess

    candidates: list[paths.Path] = []
    for d in paths.LOG_DIRS:
        if d.is_dir():
            candidates += sorted(p for p in d.iterdir() if p.is_file())
    if not candidates:
        print(err("no log files found under " +
                  ", ".join(str(d) for d in paths.LOG_DIRS)))
        return 1
    if args.list:
        for p in candidates:
            print(p)
        return 0
    target = candidates[-1]
    for p in candidates:
        if args.log and args.log in p.name:
            target = p
            break
    print(bold(f"==> {target} <=="))
    if args.follow:
        try:
            subprocess.run(["tail", "-n", str(args.lines), "-f", str(target)])
        except KeyboardInterrupt:
            pass
        return 0
    proc = subprocess.run(["tail", "-n", str(args.lines), str(target)],
                          capture_output=True, text=True)
    print(proc.stdout, end="")
    return 0


def cmd_server(args: Any) -> int:
    from .portal import probe_manifest

    result = probe_manifest(args.url, timeout=args.timeout, insecure=args.insecure)
    if args.json:
        print(json.dumps(result.__dict__, indent=2, ensure_ascii=False))
        return 0 if result.connect_ok and result.is_atrust else 1
    print(bold("server probe"))
    for name, value in result.summary_lines():
        mark = ""
        if name == "reachable":
            mark = ok("✔") if value == "yes" else err("✘")
        if name == "aTrust controller":
            mark = ok("✔") if value == "yes" else err("✘")
        print(f" {mark} {name:<18} {value}")
    return 0 if result.connect_ok and result.is_atrust else 1


def cmd_login(args: Any) -> int:
    """Orchestrate a login using the official client's session machinery.

    Never handles credentials: if a saved session exists the tray
    auto-reconnects with it; otherwise it opens the interactive login
    page (captcha/MFA are completed there, by design).
    """
    import os
    import subprocess
    import time

    core = SdpCoreClient(timeout=3.0)
    try:
        status = core.get_all_status()
    except ThriftError:
        status = None
    if status:
        print(ok("session already present in core:"))
        emit_map(status, "status", False)
        print("already logged in — nothing to do")
        return 0

    if not systemd.daemon_alive():
        proc = systemd.start_daemon()
        if proc.returncode != 0:
            print(err("aTrustDaemon is not running and could not be started"
                      " (needs root):"))
            print((proc.stderr or "").strip())
            print(warn("run: sudo systemctl start aTrustDaemon"))
            return 1
        time.sleep(2)

    display = os.environ.get("DISPLAY")
    if not display:
        print(err("no DISPLAY — login needs a desktop session for the "
                  "one-time interactive authentication"))
        return 1

    cmd = ["/usr/bin/atrust"]
    if args.url:
        cmd.append(args.url)
    print(bold("launching aTrust tray…"))
    subprocess.Popen(
        cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )

    print("waiting for session (complete the login window if it appears)…")
    deadline = time.time() + args.wait
    while time.time() < deadline:
        time.sleep(3)
        try:
            status = SdpCoreClient(timeout=2.0).get_all_status()
        except ThriftError:
            status = None
        procs = systemd.daemon_processes()
        if status:
            emit_map(status, "status", False)
            print(ok("session established"))
            return 0
        if args.verbose:
            print(f"  … waiting ({', '.join(procs) or 'no processes'})")
    print(warn(f"no session after {args.wait}s — check the login window"))
    return 1


def cmd_version(args: Any) -> int:
    print(f"atrust-cli {__version__}")
    ver = paths.client_version()
    if ver:
        print(f"aTrust client {ver} (electron {paths.electron_version()})")
    return 0


# ------------------------------------------------------------------ main ---
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="atrust-cli",
        description="Unofficial CLI for the Sangfor aTrust SDP client "
                    "(reverse-engineered local RPC).",
    )
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("status", help="show connection/tunnel status")
    p.add_argument("-a", "--all", action="store_true",
                   help="fetch the full status map (GetAllStatus)")
    p.add_argument("-j", "--json", action="store_true", help="JSON output")
    p.add_argument("--timeout", type=float, default=3.0)
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("logout", help="log out the current session")
    p.add_argument("--type", default="normal", help="logout type string")
    p.add_argument("--timeout", type=float, default=3.0)
    p.set_defaults(func=cmd_logout)

    p = sub.add_parser("spa", help="SPA (udp knock) state for a VPN url")
    p.add_argument("url", help="vpn server url, e.g. https://vpn.example.com")
    p.add_argument("-j", "--json", action="store_true", help="JSON output")
    p.add_argument("--timeout", type=float, default=3.0)
    p.set_defaults(func=cmd_spa)

    p = sub.add_parser("config", help="dump the SDP client config map")
    p.add_argument("-j", "--json", action="store_true", help="JSON output")
    p.add_argument("--timeout", type=float, default=3.0)
    p.set_defaults(func=cmd_config)

    p = sub.add_parser("service", help="control the aTrustDaemon systemd unit")
    p.add_argument("action", choices=["status", "start", "stop", "restart"])
    p.set_defaults(func=cmd_service)

    p = sub.add_parser("doctor", help="environment and health checks")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("logs", help="tail aTrust log files")
    p.add_argument("-f", "--follow", action="store_true")
    p.add_argument("-n", "--lines", type=int, default=50)
    p.add_argument("-l", "--list", action="store_true", help="list log files")
    p.add_argument("log", nargs="?", help="substring of a log file name")
    p.set_defaults(func=cmd_logs)

    p = sub.add_parser("server", help="probe a VPN controller address (/public/manifest)")
    p.add_argument("url", help="e.g. https://vpn.csu.edu.cn")
    p.add_argument("-j", "--json", action="store_true", help="JSON output")
    p.add_argument("-k", "--insecure", action="store_true",
                   help="skip TLS certificate verification")
    p.add_argument("--timeout", type=float, default=5.0)
    p.set_defaults(func=cmd_server)

    p = sub.add_parser("login", help="connect via the official client "
                                      "(session reuse; interactive only when needed)")
    p.add_argument("url", nargs="?", help="e.g. https://vpn.csu.edu.cn")
    p.add_argument("--wait", type=int, default=120,
                   help="seconds to wait for a session")
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(func=cmd_login)

    p = sub.add_parser("version", help="print versions")
    p.set_defaults(func=cmd_version)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print()
        return 130
