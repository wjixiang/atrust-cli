"""Browser smoke test. Run: uv run --with playwright python scripts/vm/check-ui.py.

Uses the live VM's static UI but intercepts every API request with synthetic
fixtures. It never sends a password/SMS or starts a real tunnel.
"""
import json
import argparse
import struct
import zlib

from playwright.sync_api import sync_playwright


def chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 272, 192, 8, 2, 0, 0, 0))
       + chunk(b"IDAT", zlib.compress((b"\0" + b"\xf0\xf5\xf4" * 272) * 192)) + chunk(b"IEND", b""))
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--base-url', default='http://127.0.0.1:8787')
args = parser.parse_args()
state = {"stage": "idle", "message": "测试会话", "username": "", "server": "https://vpn.example.com",
         "session_available": False, "cookie_count": 0, "tunnel": "offline", "isolated": True,
         "proxy_address": "127.0.0.1:10809", "csrf": "test-csrf", "events": [], "captcha_version": 0, "sms_retry_after": 0}
calls = []


def route_api(route):
    request = route.request
    path = request.url.split("/api/", 1)[1].split("?", 1)[0]
    if path == "captcha":
        return route.fulfill(status=200, content_type="image/png", body=png)
    if request.method == "POST":
        assert request.headers.get("x-csrf-token") == "test-csrf"
        body = request.post_data_json
        calls.append(path)
        if path == "auth/begin":
            assert body["password"] == "SYNTHETIC-PASSWORD"
            state.update(stage="captcha", username="test-user", captcha_version=1)
        elif path == "auth/captcha":
            assert body["width"] == 272 and body["height"] == 192
            assert len(body["coordinates"]) == 3
            for actual, expected in zip(body["coordinates"], [[40, 40], [140, 80], [220, 120]]):
                assert all(abs(a - b) <= 1 for a, b in zip(actual, expected))
            state.update(stage="sms")
        elif path == "auth/sms/send":
            state.update(sms_retry_after=60)
        elif path == "auth/sms/verify":
            assert body["code"] == "012345"
            state.update(stage="authenticated", session_available=True, cookie_count=1)
        elif path == "tunnel/connect":
            state.update(tunnel="online")
        elif path == "tunnel/disconnect":
            state.update(tunnel="offline")
        else:
            raise AssertionError(path)
    route.fulfill(status=200, content_type="application/json", body=json.dumps(state))


with sync_playwright() as p:
    browser = p.chromium.launch(executable_path="/usr/bin/chromium", headless=True)
    page = browser.new_page(viewport={"width": 1440, "height": 1000})
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.route("**/api/**", route_api)
    page.goto(args.base_url, wait_until="networkidle")
    assert page.locator("#proxy-address").inner_text() == "127.0.0.1:10809"
    page.locator("#username").fill("test-user")
    page.locator("#password").fill("SYNTHETIC-PASSWORD")
    page.locator("#login-button").click()
    page.locator("#captcha-panel").wait_for(state="visible")
    page.wait_for_function("() => document.querySelector('#captcha-image').complete && document.querySelector('#captcha-image').naturalWidth > 0")
    assert page.locator("#password").input_value() == ""
    bounds = page.locator("#captcha-image").bounding_box()
    for x, y in [[40, 40], [140, 80], [220, 120]]:
        page.mouse.click(bounds["x"] + x / 272 * bounds["width"], bounds["y"] + y / 192 * bounds["height"])
    assert page.locator("#captcha-markers span").count() == 3
    page.locator("#submit-captcha").click()
    page.locator("#sms-form").wait_for(state="visible")
    page.locator("#send-sms").click()
    page.locator("#send-sms:disabled").wait_for(state="visible")
    page.locator("#sms-code").fill("012345")
    page.locator("#verify-sms").click()
    page.locator("#success-panel").wait_for(state="visible")
    page.locator("#connect-button").click()
    page.locator("#disconnect-button").wait_for(state="visible")
    page.locator("#disconnect-button").click()
    page.locator("#connect-button").wait_for(state="visible")
    for width, height in [(1440, 1000), (390, 844)]:
        page.set_viewport_size({"width": width, "height": height})
        assert page.evaluate("() => document.documentElement.scrollWidth <= window.innerWidth")
    assert not errors, errors
    assert calls == ["auth/begin", "auth/captcha", "auth/sms/send", "auth/sms/verify", "tunnel/connect", "tunnel/disconnect"]
    browser.close()
    print("Browser password/click-captcha/SMS/connect/disconnect and responsive layout: PASS (synthetic APIs only)")
