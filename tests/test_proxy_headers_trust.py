"""
uvicorn's proxy headers are on, and the rate limiter still keys on the
visitor's real IP.

nginx appends $remote_addr (already set from CF-Connecting-IP by real_ip)
to X-Forwarded-For and connects from loopback. uvicorn trusts loopback
only, takes the rightmost untrusted address, and _get_client_ip returns
it. A client's own X-Forwarded-For entries sit to the left and are
ignored; a direct non-loopback connection gets no rewriting at all.
"""
import asyncio
import os
import re
import sys

from starlette.requests import Request
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import server as server_module  # noqa: E402

REPO = os.path.join(os.path.dirname(__file__), "..")
VISITOR = "198.51.100.23"
SPOOF = "203.0.113.99"


def _client_ip(peer, headers):
    seen = {}

    async def app(scope, receive, send):
        seen["ip"] = server_module._get_client_ip(Request(scope))

    scope = {
        "type": "http", "method": "GET", "path": "/", "raw_path": b"/",
        "query_string": b"", "scheme": "http", "server": ("127.0.0.1", 8000),
        "client": (peer, 40000), "root_path": "",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
    }
    mw = ProxyHeadersMiddleware(app, trusted_hosts="127.0.0.1")
    asyncio.run(mw(scope, None, None))
    return seen["ip"]


def test_nginx_request_resolves_to_the_visitor():
    assert _client_ip("127.0.0.1", {"X-Forwarded-For": VISITOR,
                                    "X-Real-IP": VISITOR}) == VISITOR


def test_a_spoofed_forwarded_for_entry_is_ignored():
    # The client sent "X-Forwarded-For: SPOOF"; nginx appended the real one.
    assert _client_ip("127.0.0.1", {"X-Forwarded-For": f"{SPOOF}, {VISITOR}",
                                    "X-Real-IP": VISITOR}) == VISITOR


def test_a_direct_connection_cannot_choose_its_address():
    assert _client_ip(VISITOR, {"X-Forwarded-For": SPOOF,
                                "X-Real-IP": SPOOF}) == VISITOR


def test_the_unit_names_loopback_as_the_only_trusted_proxy():
    with open(os.path.join(REPO, "deploy", "dns-auditor.service"), encoding="utf-8") as f:
        execstart = re.search(r"^ExecStart=(.*)$", f.read(), re.MULTILINE).group(1).split()
    assert "--proxy-headers" in execstart
    assert execstart[execstart.index("--forwarded-allow-ips") + 1] == "127.0.0.1"
