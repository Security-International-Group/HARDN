#!/usr/bin/env python3
"""FastAPI TestClient sweep of src/hardn-api.py.

Skipped cleanly when fastapi / psutil / starlette aren't available.
The orchestrator picks up the trailing TAP summary line either way.
"""

import importlib.util
import os
import sys
import tempfile
import textwrap

SUITE = "integration/api-endpoints"


def emit(idx, ok, desc, diag=None):
    prefix = "ok" if ok else "not ok"
    print(f"{prefix} {idx} - {desc}")
    if diag:
        for line in str(diag).splitlines():
            print(f"# {line}")


def emit_summary(total, passed, failed, skipped):
    print(
        f"# {SUITE} totals: total={total} pass={passed} "
        f"fail={failed} skip={skipped}"
    )


def skip_all(reason):
    print("1..1")
    print(f"ok 1 - # SKIP {reason}")
    emit_summary(1, 0, 0, 1)
    sys.exit(0)


# Resolve repo root + import the api module by file path so the - in
# 'hardn-api.py' doesn't trip up regular import.
HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
API_PATH = os.path.join(REPO_ROOT, "src", "hardn-api.py")

if not os.path.exists(API_PATH):
    skip_all(f"{API_PATH} not found")

try:
    import fastapi  # noqa: F401
    from fastapi.testclient import TestClient
except ImportError:
    skip_all("fastapi not installed (pip install fastapi)")
except RuntimeError as e:
    # starlette.testclient raises RuntimeError when httpx is missing.
    # Treat that as a missing-prereq, not a test failure.
    skip_all(f"starlette TestClient unavailable: {e}")

try:
    import psutil  # noqa: F401
except ImportError:
    skip_all("psutil not installed (pip install psutil)")


def load_api_module():
    spec = importlib.util.spec_from_file_location("hardn_api_module", API_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# Plan: 8 checks (3 endpoints + auth contract + metrics + diagnostics + key file + bearer reject).
print("1..8")

passed = failed = skipped = 0
total = 0


def check(ok, desc, diag=None):
    global passed, failed, total
    total += 1
    emit(total, ok, desc, diag)
    if ok:
        passed += 1
    else:
        failed += 1


# Build a clean tempdir for the authorized_keys file + alerts.jsonl + cron summary.
tmp = tempfile.mkdtemp(prefix="hardn-test-")
keys_path = os.path.join(tmp, "authorized_keys")
with open(keys_path, "w") as f:
    f.write("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAATESTKEY hardn-api-test\n")

# Point the API at the temp keys file + temp alerts/cron sources before
# importing the module, so the module-level config reads our overrides.
os.environ["HARDN_AUTHORIZED_KEYS"] = keys_path

alerts_path = os.path.join(tmp, "alerts.jsonl")
with open(alerts_path, "w") as f:
    f.write(
        '{"ts":"t","severity":"critical","source":"sentry/sudoers",'
        '"message":"m","key":"sentry:sudoers:added:/x"}\n'
    )
    f.write(
        '{"ts":"t","severity":"warning","source":"hardn-monitor",'
        '"message":"m","key":"svc-down:hardn-api"}\n'
    )

cron_path = os.path.join(tmp, "cron_summary.json")
with open(cron_path, "w") as f:
    f.write(textwrap.dedent("""
        {"jobs":[{"name":"hardn-sentry","last_run":"2026-06-03T02:15:00+00:00",
                  "last_success":true,"last_duration_seconds":0.42}]}
    """).strip())

os.environ["HARDN_ALERTS_FILE"] = alerts_path
os.environ["HARDN_CRON_SUMMARY_FILE"] = cron_path
os.environ["HARDN_SENTRY_BASELINE_FILE"] = os.path.join(tmp, "baseline.json")
os.environ["HARDN_LEGION_DB_DIR"] = tmp

# 1. Module imports without error.
try:
    api = load_api_module()
    check(True, "hardn-api.py imports cleanly")
except Exception as e:
    check(False, "hardn-api.py imports cleanly", diag=e)
    emit_summary(total, passed, failed, skipped)
    sys.exit(failed != 0)


# The CIDR allowlist middleware in src/hardn-api.py rejects requests whose
# source IP is not inside HARDN_API_ALLOWED_CIDRS. fastapi.TestClient sets
# the ASGI scope's client tuple to ("testclient", 50000) by default, which
# is not a valid IP and would 403 every request. Wrap the app so the
# scope reports 127.0.0.1, which matches the default allowlist
# (127.0.0.0/8 + ::1/128).
real_app = api.app


async def app_with_loopback_client(scope, receive, send):
    if scope.get("type") == "http":
        scope = dict(scope)
        scope["client"] = ("127.0.0.1", 0)
    return await real_app(scope, receive, send)


client = TestClient(app_with_loopback_client)

# 2. /health is unauthenticated and returns healthy.
r = client.get("/health")
check(
    r.status_code == 200 and r.json().get("status") == "healthy",
    "/health returns 200 + status=healthy",
    diag=f"status={r.status_code} body={r.text[:200]}",
)

# 3. /overwatch/system without auth -> 401/403.
r = client.get("/overwatch/system")
check(
    r.status_code in (401, 403),
    "/overwatch/system rejects unauthenticated requests",
    diag=f"status={r.status_code}",
)

# 4. /overwatch/system with the registered bearer -> 200.
key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAATESTKEY hardn-api-test"
r = client.get("/overwatch/system", headers={"Authorization": f"Bearer {key}"})
check(
    r.status_code == 200,
    "/overwatch/system accepts the registered SSH key",
    diag=f"status={r.status_code} body={r.text[:200]}",
)

# 5. /overwatch/system with a different but format-valid key -> 401.
fake = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAUNREGISTERED notreg"
r = client.get("/overwatch/system", headers={"Authorization": f"Bearer {fake}"})
check(
    r.status_code in (401, 403),
    "/overwatch/system rejects an unregistered key",
    diag=f"status={r.status_code}",
)

# 6. /metrics is unauthenticated, returns Prometheus text-format.
r = client.get("/metrics")
ok = r.status_code == 200 and "hardn_info" in r.text and "# HELP " in r.text
check(
    ok,
    "/metrics returns Prometheus text exposition",
    diag=f"status={r.status_code} first 200 bytes: {r.text[:200]}",
)

# 7. /metrics reports the alert counts from our temp alerts.jsonl (PR-G).
r = client.get("/metrics")
has_sentry_drift = (
    'hardn_sentry_drift_total{verb="added",category="sudoers"} 1' in r.text
)
check(
    has_sentry_drift,
    "/metrics reflects SENTRY drift counts from alerts.jsonl",
    diag=f"text excerpt: {r.text[:1000]}",
)

# 8. /metrics reports the cron-job last-run from our temp cron_summary.json.
r = client.get("/metrics")
has_cron = (
    'hardn_cron_last_success{job="hardn-sentry"} 1' in r.text
    and 'hardn_cron_last_duration_seconds{job="hardn-sentry"}' in r.text
)
check(
    has_cron,
    "/metrics reflects cron summary state",
    diag=f"text excerpt: {r.text[:1500]}",
)

emit_summary(total, passed, failed, skipped)
sys.exit(failed != 0)
