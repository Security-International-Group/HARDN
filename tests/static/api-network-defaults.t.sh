#!/bin/bash
# Pre-push regression guards for the P0 hardn-api network exposure fix.
#
# Invariants this suite locks in:
#
#   N1  src/hardn-api.py defaults HARDN_API_HOST to 127.0.0.1 (NOT
#       0.0.0.0). The bind default is the first line of defence; if
#       this regresses the API is reachable from the public internet
#       on default-config boxes.
#
#   N2  src/hardn-api.py registers a CIDR allowlist middleware that
#       reads HARDN_API_ALLOWED_CIDRS and uses stdlib ipaddress to
#       match request source IPs. This is the L7 backstop so a
#       misconfigured bind=0.0.0.0 still fails closed.
#
#   N3  systemd/hardn-api.service ships HARDN_API_HOST=127.0.0.1 AND
#       HARDN_API_ALLOWED_CIDRS=127.0.0.0/8,::1/128 as Environment=
#       defaults. The systemd-shipped defaults must agree with the
#       Python defaults; otherwise an operator who clears the env
#       only on one layer drops the other layer's protection.

set -u

HARDN_TEST_NAME="static/api-network-defaults"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

API_PY="$REPO_ROOT/src/hardn-api.py"
API_UNIT="$REPO_ROOT/systemd/hardn-api.service"

assert_file_exists "$API_PY"   "src/hardn-api.py ships"
assert_file_exists "$API_UNIT" "systemd/hardn-api.service ships"

tap_plan 9

# N1: bind default is 127.0.0.1, not 0.0.0.0.
if grep -qE 'HARDN_API_HOST"[[:space:]]*,[[:space:]]*"127\.0\.0\.1"' "$API_PY"; then
    tap_ok "src/hardn-api.py defaults HARDN_API_HOST to 127.0.0.1"
else
    tap_not_ok "src/hardn-api.py must default HARDN_API_HOST to 127.0.0.1"
    tap_diag "expected pattern: HARDN_API_HOST\", \"127.0.0.1\""
    grep -nE 'HARDN_API_HOST' "$API_PY" | sed 's/^/# /'
fi

if grep -qE 'HARDN_API_HOST"[[:space:]]*,[[:space:]]*"0\.0\.0\.0"' "$API_PY"; then
    tap_not_ok "src/hardn-api.py must not default HARDN_API_HOST to 0.0.0.0"
    grep -nE 'HARDN_API_HOST' "$API_PY" | sed 's/^/# /'
else
    tap_ok "src/hardn-api.py does not default HARDN_API_HOST to 0.0.0.0"
fi

# N2: middleware presence + import of ipaddress.
if grep -qE '^import[[:space:]]+ipaddress' "$API_PY"; then
    tap_ok "src/hardn-api.py imports stdlib ipaddress"
else
    tap_not_ok "src/hardn-api.py must import ipaddress for CIDR matching"
fi

if grep -qE '@app\.middleware\("http"\)' "$API_PY" \
   && grep -qE 'def[[:space:]]+cidr_allowlist' "$API_PY"; then
    tap_ok "src/hardn-api.py registers a cidr_allowlist HTTP middleware"
else
    tap_not_ok "src/hardn-api.py must register an @app.middleware('http') cidr_allowlist function"
fi

if grep -qE 'HARDN_API_ALLOWED_CIDRS' "$API_PY"; then
    tap_ok "src/hardn-api.py reads HARDN_API_ALLOWED_CIDRS"
else
    tap_not_ok "src/hardn-api.py must read HARDN_API_ALLOWED_CIDRS"
fi

# N3: systemd unit ships matching defaults.
if grep -qE '^Environment=HARDN_API_HOST=127\.0\.0\.1' "$API_UNIT"; then
    tap_ok "hardn-api.service ships HARDN_API_HOST=127.0.0.1"
else
    tap_not_ok "hardn-api.service must ship HARDN_API_HOST=127.0.0.1"
    grep -nE 'HARDN_API_HOST' "$API_UNIT" | sed 's/^/# /'
fi

if grep -qE '^Environment=HARDN_API_HOST=0\.0\.0\.0' "$API_UNIT"; then
    tap_not_ok "hardn-api.service must not ship HARDN_API_HOST=0.0.0.0"
else
    tap_ok "hardn-api.service does not ship HARDN_API_HOST=0.0.0.0"
fi

if grep -qE '^Environment=HARDN_API_ALLOWED_CIDRS=' "$API_UNIT"; then
    tap_ok "hardn-api.service ships a HARDN_API_ALLOWED_CIDRS default"
else
    tap_not_ok "hardn-api.service must ship HARDN_API_ALLOWED_CIDRS"
fi

tap_summary
