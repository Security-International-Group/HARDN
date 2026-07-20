#!/bin/bash
# Integration guard for the compliance console's security-critical behavior.
#
# The console (`hardn serve`) is the product's trust surface: role-gated
# reads/mutations and a tamper-evident, hash-chained audit log. This test
# stands up a real server on a throwaway port + state dir and asserts:
#
#   - the auth matrix: /health is open, unauthenticated /api/v1 reads are
#     401, a viewer may read but not mutate (403), an operator may mutate;
#   - the audit-log hash chain reports verified=true for an untouched log
#     and flips to verified=false when a single field is edited.
#
# These properties were validated by hand; this locks them into CI so a
# regression in the auth gate or the hash chain fails the build.

set -u

HARDN_TEST_NAME="integration/console-security"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

require_cmd cargo "install rustup and cargo"
require_cmd curl "install curl"
require_cmd python3 "install python3"
require_cmd cc "install a C compiler for the audit engine"

cd "$REPO_ROOT"

if ! cargo build --bin hardn --quiet 2>/dev/null; then
    tap_plan 1
    tap_not_ok "cargo build --bin hardn failed"
    tap_summary
    exit 1
fi
BIN="$REPO_ROOT/target/debug/hardn"
AUDIT_BIN="$REPO_ROOT/target/debug/hardn-audit"
if ! cc -std=c11 -O2 "$REPO_ROOT/src/audit/hardn_audit.c" -o "$AUDIT_BIN" 2>/dev/null; then
    tap_plan 1
    tap_not_ok "cc build of hardn-audit failed"
    tap_summary
    exit 1
fi

# Throwaway state dir + port. Deriving the port from the PID keeps parallel
# or repeated runs from colliding on a fixed number.
STATE_DIR="$(mktemp -d)"
PORT=$(( 20000 + ($$ % 20000) ))
BASE="http://127.0.0.1:${PORT}"
SERVE_OUT="${STATE_DIR}/serve.out"
SRV_PID=""

cleanup() {
    [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
    rm -rf "$STATE_DIR"
}
trap cleanup EXIT

export HARDN_STATE_DIR="$STATE_DIR"
export HARDN_REPORT_PATH="${STATE_DIR}/report.json"
export HARDN_AUDIT_BIN="$AUDIT_BIN"

"$BIN" serve "$PORT" > "$SERVE_OUT" 2>&1 &
SRV_PID=$!

# HTTP status of a request (empty on connection failure).
http_code() { curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$@"; }
# Extract a top-level integrity field from the audit-log JSON.
integrity_verified() {
    curl -s --max-time 5 -H "Authorization: Bearer $1" "${BASE}/api/v1/audit-log" \
        | python3 -c 'import sys,json;print(json.load(sys.stdin).get("integrity",{}).get("verified"))' 2>/dev/null
}

# Wait for readiness by polling /health (server binds then prints tokens).
ready=""
for _ in $(seq 1 40); do
    if [ "$(http_code "${BASE}/api/v1/health")" = "200" ]; then ready="yes"; break; fi
    sleep 0.25
done

tap_plan 9

assert_file_exists "$BIN" "hardn binary present after build"

if [ "$ready" = "yes" ]; then
    tap_ok "console answered /health on ${BASE}"
else
    tap_not_ok "console did not become ready on ${BASE}"
    sed 's/^/# serve: /' "$SERVE_OUT" 2>/dev/null | head -5
    tap_summary
    exit 0
fi

OP=$(grep -oE 'operator: .*token=[A-Za-z0-9]+' "$SERVE_OUT" | sed 's/.*token=//')
VW=$(grep -oE 'viewer: .*token=[A-Za-z0-9]+' "$SERVE_OUT" | sed 's/.*token=//')

# Auth matrix.
assert_eq "200" "$(http_code "${BASE}/api/v1/health")" \
    "/health is reachable without auth"
assert_eq "401" "$(http_code "${BASE}/api/v1/compliance/summary")" \
    "unauthenticated /api/v1 read is refused (401)"
assert_eq "200" "$(http_code -H "Authorization: Bearer ${VW}" "${BASE}/api/v1/compliance/summary")" \
    "viewer token can read compliance summary (200)"
assert_eq "403" "$(http_code -X POST -H "Authorization: Bearer ${VW}" "${BASE}/api/v1/audit/run")" \
    "viewer token cannot mutate: POST audit/run is forbidden (403)"
assert_eq "200" "$(http_code -X POST -H "Authorization: Bearer ${OP}" "${BASE}/api/v1/audit/run")" \
    "operator token can mutate: POST audit/run succeeds (200)"

# The operator action above wrote at least one audit-log record. A clean
# chain must verify.
assert_eq "True" "$(integrity_verified "$OP")" \
    "audit-log hash chain verifies (verified=true) when untouched"

# Tamper with one field of the first record; the chain must break.
LOG="${STATE_DIR}/audit-log.jsonl"
python3 - "$LOG" <<'PY'
import sys, json
p = sys.argv[1]
lines = open(p).read().splitlines()
if lines:
    r = json.loads(lines[0])
    r["detail"] = str(r.get("detail", "")) + "-TAMPERED"
    lines[0] = json.dumps(r)
    open(p, "w").write("\n".join(lines) + "\n")
PY
assert_eq "False" "$(integrity_verified "$OP")" \
    "audit-log hash chain detects tampering (verified=false) after an edit"

tap_summary
