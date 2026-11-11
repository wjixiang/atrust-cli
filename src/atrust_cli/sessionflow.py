"""Capture and restore an official-agent session without the Electron tray."""

from __future__ import annotations

import time
import urllib.parse

from . import sessioncache
from .agent import AgentClient, AgentError, is_online
from .passport import PassportClient, PassportError


def _client(args, url: str) -> PassportClient:
    return PassportClient(url, insecure=args.insecure, timeout=args.timeout)


def _save(client: PassportClient, response: dict, username: str,
          agent_data: dict | None = None, issued_at: float | None = None) -> None:
    data = response.get("data") or {}
    ticket = data.get("sidTicket") or (agent_data or {}).get("sidTicket")
    cookies = client.export_cookies()
    if not ticket and not cookies:
        raise AgentError("no sidTicket or session cookie received; no capture saved")
    path = sessioncache.save({
        "url": client.base, "username": username,
        "sid_ticket": ticket,
        "ticket_saved_at": (issued_at if issued_at is not None else time.time()) if ticket else None,
        "cookies": cookies, "config": client.config,
        "device_id": client.device_id,
        "auth_response": response, "agent_init": agent_data or {},
    })
    # Only field names/counts are emitted, never ticket/cookie values.
    print(f"session captured ({path})")
    print(f"  sidTicket: {'present' if ticket else 'absent'}; cookies: {len(cookies)}")
    print("  reuse lifetime is controlled by the server; capture does not prove renewal")


def _wait_online(agent: AgentClient, wait: int) -> None:
    deadline = time.monotonic() + wait
    while True:
        if is_online(agent.status()):
            print("official agent tunnel is online")
            return
        if time.monotonic() >= deadline:
            raise AgentError(f"tunnel did not become online after {wait}s")
        time.sleep(min(1, max(0, deadline - time.monotonic())))


def connect(client: PassportClient, response: dict, args) -> int:
    """Persist the auth result before attempting the real agent handoff."""
    try:
        data = response.get("data") or {}
        next_service = data.get("nextService") or ""
        if next_service and next_service not in ("auth/accessCheck", "auth/authCheck"):
            raise AgentError("authentication is incomplete; additional service required: "
                             + next_service)
        if getattr(args, "auth_only", False) and getattr(args, "capture", False):
            # Retain password/MFA success even when a subsequent policy check
            # fails. The response records nextService, so this is not proof of
            # completed authentication.
            _save(client, response, args.user or "")
        if (data.get("env") or {}).get("need") and data.get("ticket"):
            print("reporting non-native browser environment to the controller…")
            client.report_browser_env(data["ticket"])
        if next_service == "auth/authCheck":
            response = client._request("GET", "/passport/v1/auth/authCheck")
        next_service = (response.get("data") or {}).get("nextService") or ""
        if next_service and next_service != "auth/accessCheck":
            raise AgentError("additional authentication is required: " + next_service)
        if getattr(args, "auth_only", False):
            # Deliberately before AgentClient construction: even service/init may
            # affect native-client state. Only the controller is contacted here.
            _save(client, response, args.user or "")
            print("authentication captured; local agent initialization and tunnel start skipped")
            if next_service:
                print("controller access check remains pending; full access is not established")
            print("existing official-client connections are not modified")
            return 0
        # Save immediately: failed agent initialization must not lose the ticket.
        if getattr(args, "capture", False):
            _save(client, response, args.user or "")
        agent = AgentClient(client.base, timeout=args.timeout)
        init = agent.init(client.config)
        if next_service == "auth/accessCheck":
            response = client._request("POST", "/passport/v1/auth/accessCheck", {})
            if (response.get("data") or {}).get("nextService"):
                raise AgentError("access check requires additional authentication")
        if getattr(args, "capture", False):
            _save(client, response, args.user or "", init)
        if not is_online(agent.status()):
            ticket = (response.get("data") or {}).get("sidTicket")
            if not ticket:
                ticket = (client.ticket_exchange().get("data") or {}).get("sidTicket")
            agent.start(ticket)
        _wait_online(agent, args.wait)
        return 0
    except (AgentError, PassportError, OSError, ValueError) as exc:
        print(f"session handoff failed: {exc}")
        return 1


def capture_existing(args) -> int:
    """Use the SDK's service/init to request a ticket from an existing session."""
    try:
        client = _client(args, args.url)
        client.auth_config()
        if args.pub_key:
            client.config["pubKey"] = args.pub_key
        agent = AgentClient(args.url, timeout=args.timeout)
        init = agent.init(client.config)
        if not is_online(agent.status()):
            raise AgentError("official agent is not online; finish the login first")
        response = {"code": 0, "data": {}}
        ticket = init.get("sidTicket")
        if ticket:
            try:
                # Same restoreSession sequence used by the official web SDK:
                # turn the native session ticket into a controller cookie.
                client.session_id_exchange(ticket)
                init = {k: v for k, v in init.items() if k != "sidTicket"}
                response = client.ticket_exchange()
            except PassportError:
                print("controller cookie exchange unavailable; capture may be short-lived")
        _save(client, response, init.get("username") or "", init)
        return 0
    except (AgentError, PassportError, OSError, ValueError) as exc:
        print(f"session capture failed: {exc}")
        return 1


def resume_auth_only(args) -> int:
    """Validate saved controller cookies without any native-agent calls."""
    saved = sessioncache.load()
    if not saved or not saved.get("cookies"):
        print("no captured controller cookies available")
        return 1
    try:
        url = saved.get("url")
        if not url or (args.url and _origin(args.url) != _origin(url)):
            raise AgentError("session server does not match the requested URL")
        client = _client(args, url)
        client.import_cookies(saved["cookies"])
        # The SDK's in-session authConfig omits mod=1 (OUT_OF_SESSION).
        client.auth_config(with_session=True)
        response = client.ticket_exchange()
        if not (response.get("data") or {}).get("sidTicket"):
            raise AgentError("controller did not issue a session ticket")
        _save(client, response, saved.get("username") or "")
        print("controller accepted saved cookies; no password or captcha submitted")
        print("local agent and tunnel were not initialized or started")
        return 0
    except (AgentError, PassportError, OSError, ValueError, TypeError) as exc:
        print(f"cookie session reuse failed: {exc}")
        print("saved capture was kept; no password login or local agent call was attempted")
        return 1


def resume(args) -> int:
    saved = sessioncache.load()
    if not saved:
        print("no readable session capture; run login URL --capture first")
        return 1
    url = saved.get("url")
    if not url or (args.url and _origin(args.url) != _origin(url)):
        print("session server does not match the requested URL")
        return 1
    try:
        client = _client(args, url)
        client.import_cookies(saved.get("cookies") or [])
        client.auth_config()  # fresh challenge and csrf, never replay old config
        agent = AgentClient(url, timeout=args.timeout)
        init = agent.init(client.config)
        if is_online(agent.status()):
            print("official agent session is already online")
            return 0
        # service/init may issue a fresh ticket from the agent's saved session.
        ticket = init.get("sidTicket")
        issued = time.time()
        if not ticket:
            try:
                ticket = (client.ticket_exchange().get("data") or {}).get("sidTicket")
            except PassportError:
                issued = saved.get("ticket_saved_at") or 0
                if 0 <= time.time() - issued < 80:
                    ticket = saved.get("sid_ticket")
        if not ticket:
            raise AgentError("saved session cannot issue a fresh ticket; "
                             "interactive authentication is required")
        # Save the fresh cookie state before the start call can consume the ticket.
        _save(client, {"code": 0, "data": {"sidTicket": ticket}},
              saved.get("username") or "", init, issued_at=issued)
        agent.start(ticket)
        _wait_online(agent, args.wait)
        return 0
    except (AgentError, PassportError, OSError, ValueError, TypeError) as exc:
        print(f"session restore failed: {exc}")
        return 1


def _origin(url: str) -> tuple:
    parsed = urllib.parse.urlsplit(url)
    return parsed.scheme, parsed.hostname, parsed.port


def info() -> int:
    saved = sessioncache.load()
    if not saved:
        print("no readable session capture")
        return 1
    # Explicit allowlist: do not print response/config/cookie contents.
    print(f"session file: {sessioncache.cache_path()}")
    print(f"server: {saved.get('url', '')}")
    print(f"saved at: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(saved['saved_at']))}")
    print(f"sidTicket: {'present' if saved.get('sid_ticket') else 'absent'}")
    print(f"cookies: {len(saved.get('cookies') or [])}")
    print("renewability: unverified (use login --resume to test)")
    return 0
