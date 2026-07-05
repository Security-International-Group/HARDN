#!/usr/bin/env python3
# Runtime test for the hardn-api CIDR allowlist middleware.
#
# Loads src/hardn-api.py as a module, then hits a small set of routes
# with the FastAPI TestClient while spoofing the client IP via
# fastapi.testclient's `headers={"x-forwarded-for": ...}` and a wrapping
# ASGI scope rewrite. We verify:
#
#   M1  Default allowlist (127.0.0.0/8 + ::1/128) allows 127.0.0.1.
#   M2  Default allowlist rejects 10.0.0.5 with HTTP 403.
#   M3  Setting HARDN_API_ALLOWED_CIDRS=10.0.0.0/24 lets 10.0.0.5 in
#       and still rejects 192.168.1.5.
#   M4  Malformed CIDR entries are discarded without crashing module
#       import.
#
# Output is TAP. If fastapi / starlette / httpx are not installed the
# whole suite SKIPs cleanly.

import os
import sys
import unittest
import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
API_PATH = REPO_ROOT / "src" / "hardn-api.py"

# TAP plumbing matching lib/tap.sh shape.
_count = 0
_pass = 0
_fail = 0
_skip = 0
NAME = "unit/api-cidr-allowlist"


def tap_plan(n):
    print(f"1..{n}")


def tap_ok(msg):
    global _count, _pass
    _count += 1
    _pass += 1
    print(f"ok {_count} - {msg}")


def tap_not_ok(msg, diag=None):
    global _count, _fail
    _count += 1
    _fail += 1
    print(f"not ok {_count} - {msg}")
    if diag:
        for line in str(diag).splitlines():
            print(f"# {line}")


def tap_skip(msg):
    global _count, _skip
    _count += 1
    _skip += 1
    print(f"ok {_count} - # SKIP {msg}")


def tap_summary():
    print(f"# {NAME} totals: total={_count} pass={_pass} fail={_fail} skip={_skip}")
    return 0 if _fail == 0 else 1


def skip_whole_suite(reason):
    tap_plan(1)
    tap_skip(reason)
    sys.exit(tap_summary())


try:
    import fastapi  # noqa: F401
    from fastapi.testclient import TestClient  # noqa: F401
    import httpx  # noqa: F401
    import psutil  # noqa: F401
except ImportError as e:
    skip_whole_suite(f"dependency not installed: {e.name}")


def load_api_module(env_overrides):
    """Reload hardn-api.py with the given env so module-time globals
    (ALLOWED_NETWORKS, default HARDN_API_HOST) re-evaluate.
    """
    saved = {}
    for k, v in env_overrides.items():
        saved[k] = os.environ.get(k)
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    try:
        spec = importlib.util.spec_from_file_location("hardn_api_under_test", API_PATH)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def request_with_client_ip(mod, path, client_ip):
    """Hit `path` via TestClient but rewrite the ASGI scope so request.client
    reports `client_ip` (which is what the middleware reads)."""
    from fastapi.testclient import TestClient

    real_app = mod.app

    async def wrapped(scope, receive, send):
        if scope.get("type") == "http":
            scope = dict(scope)
            scope["client"] = (client_ip, 0)
        return await real_app(scope, receive, send)

    return TestClient(wrapped).get(path)


tap_plan(6)

# M1: default allowlist + loopback client -> 200
mod = load_api_module(
    {
        "HARDN_API_ALLOWED_CIDRS": None,  # rely on default
        "HARDN_AUTHORIZED_KEYS": "/tmp/hardn-test-empty-keys-DOES-NOT-EXIST",
    }
)
try:
    r = request_with_client_ip(mod, "/health", "127.0.0.1")
    if r.status_code == 200:
        tap_ok("default allowlist permits 127.0.0.1 on /health")
    else:
        tap_not_ok(
            "default allowlist must permit 127.0.0.1 on /health",
            f"status={r.status_code} body={r.text[:200]}",
        )
except Exception as e:
    tap_not_ok("M1 raised", repr(e))

# M2: default allowlist + 10.0.0.5 -> 403
try:
    r = request_with_client_ip(mod, "/health", "10.0.0.5")
    if r.status_code == 403:
        tap_ok("default allowlist rejects 10.0.0.5 on /health with 403")
    else:
        tap_not_ok(
            "default allowlist must reject 10.0.0.5 on /health with 403",
            f"status={r.status_code} body={r.text[:200]}",
        )
except Exception as e:
    tap_not_ok("M2 raised", repr(e))

# M3a: custom allowlist permits configured CIDR
mod2 = load_api_module(
    {
        "HARDN_API_ALLOWED_CIDRS": "10.0.0.0/24",
        "HARDN_AUTHORIZED_KEYS": "/tmp/hardn-test-empty-keys-DOES-NOT-EXIST",
    }
)
try:
    r = request_with_client_ip(mod2, "/health", "10.0.0.5")
    if r.status_code == 200:
        tap_ok("HARDN_API_ALLOWED_CIDRS=10.0.0.0/24 permits 10.0.0.5")
    else:
        tap_not_ok(
            "HARDN_API_ALLOWED_CIDRS=10.0.0.0/24 must permit 10.0.0.5",
            f"status={r.status_code}",
        )
except Exception as e:
    tap_not_ok("M3a raised", repr(e))

# M3b: same custom allowlist rejects outside-range source
try:
    r = request_with_client_ip(mod2, "/health", "192.168.1.5")
    if r.status_code == 403:
        tap_ok("HARDN_API_ALLOWED_CIDRS=10.0.0.0/24 rejects 192.168.1.5")
    else:
        tap_not_ok(
            "HARDN_API_ALLOWED_CIDRS=10.0.0.0/24 must reject 192.168.1.5",
            f"status={r.status_code}",
        )
except Exception as e:
    tap_not_ok("M3b raised", repr(e))

# M3c: same custom allowlist also rejects loopback (since it is not in the list)
try:
    r = request_with_client_ip(mod2, "/health", "127.0.0.1")
    if r.status_code == 403:
        tap_ok("HARDN_API_ALLOWED_CIDRS=10.0.0.0/24 rejects 127.0.0.1 (not in list)")
    else:
        tap_not_ok(
            "HARDN_API_ALLOWED_CIDRS=10.0.0.0/24 must reject 127.0.0.1 when not listed",
            f"status={r.status_code}",
        )
except Exception as e:
    tap_not_ok("M3c raised", repr(e))

# M4: malformed CIDRs are skipped, valid ones still take effect.
try:
    mod3 = load_api_module(
        {
            "HARDN_API_ALLOWED_CIDRS": "not-a-cidr,10.0.0.0/24,still-bogus",
            "HARDN_AUTHORIZED_KEYS": "/tmp/hardn-test-empty-keys-DOES-NOT-EXIST",
        }
    )
    r = request_with_client_ip(mod3, "/health", "10.0.0.7")
    if r.status_code == 200:
        tap_ok("malformed CIDR entries are skipped, valid 10.0.0.0/24 still applies")
    else:
        tap_not_ok(
            "malformed CIDR entries must be skipped without breaking valid ones",
            f"status={r.status_code}",
        )
except Exception as e:
    tap_not_ok("M4 raised", repr(e))

sys.exit(tap_summary())
