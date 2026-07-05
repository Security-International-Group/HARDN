#!/bin/bash
# Pre-push guard for the hardn-apid skeleton (PR-G, first step of
# replacing the Python hardn-api with a Rust axum service).
#
# The goal of the G-K arc is to remove the Python FastAPI runtime and
# its pip supply chain. PR-G stands up a Rust hardn-apid binary serving
# /health on a Unix socket, running in parallel with the Python API; the
# Python side is not removed until the endpoints are ported (later PRs).
#
# Invariants:
#
#   A1  src/hardn-apid.rs ships.
#   A2  Cargo.toml declares the hardn-apid binary and the axum dependency.
#   A3  hardn-apid binds a Unix socket (not a TCP port) and reads the
#       socket path from HARDN_APID_SOCKET.
#   A4  hardn-apid serves a /health route.

set -u

HARDN_TEST_NAME="static/apid-skeleton"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

APID="$REPO_ROOT/src/hardn-apid.rs"
CARGO="$REPO_ROOT/Cargo.toml"

assert_file_exists "$CARGO" "Cargo.toml ships"

tap_plan 5

# A1: the binary source exists.
if [ -f "$APID" ]; then
    tap_ok "src/hardn-apid.rs ships"
else
    tap_not_ok "src/hardn-apid.rs must ship"
    tap_summary
    exit 0
fi

# A2a: Cargo.toml declares the bin.
if grep -qE 'name[[:space:]]*=[[:space:]]*"hardn-apid"' "$CARGO"; then
    tap_ok "Cargo.toml declares the hardn-apid binary"
else
    tap_not_ok "Cargo.toml must declare a [[bin]] hardn-apid"
fi

# A2b: axum dependency present.
if grep -qE '^axum[[:space:]]*=' "$CARGO"; then
    tap_ok "Cargo.toml declares the axum dependency"
else
    tap_not_ok "Cargo.toml must declare axum"
fi

# A3: Unix socket bind + env override, and NOT a TCP bind.
if grep -qE 'UnixListener' "$APID" && grep -qE 'HARDN_APID_SOCKET' "$APID"; then
    tap_ok "hardn-apid binds a Unix socket via HARDN_APID_SOCKET"
else
    tap_not_ok "hardn-apid must bind a Unix socket and read HARDN_APID_SOCKET"
fi

# A4: /health route.
if grep -qE '"/health"' "$APID"; then
    tap_ok "hardn-apid serves a /health route"
else
    tap_not_ok "hardn-apid must serve a /health route"
fi

tap_summary
