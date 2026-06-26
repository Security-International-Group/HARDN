#!/bin/bash
# Pre-push regression guard for the P0 ufw.sh hardening.
#
# Invariants this suite locks in:
#
#   U1  usr/share/hardn/tools/ufw.sh must NOT carry an unconditional
#       'ufw allow in 8000/tcp' or 'ufw allow in 9002/tcp' line. The
#       previous version of the script did, which left the HARDN API
#       and Grafana dashboard open to any source the L3 firewall let
#       through.
#
#   U2  usr/share/hardn/tools/ufw.sh must consult HARDN_REMOTE_API_CIDRS
#       and HARDN_REMOTE_DASHBOARD_CIDRS for the opt-in remote-access
#       path, so 8000/tcp and 9002/tcp are loopback-only by default.
#
#   U3  When the operator does opt in by setting one of those env
#       vars, the script must use 'ufw allow from <cidr> to any port
#       <p>' (CIDR-scoped) and NOT the unrestricted form.

set -u

HARDN_TEST_NAME="static/ufw-localhost-only"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

UFW_SH="$REPO_ROOT/usr/share/hardn/tools/ufw.sh"

assert_file_exists "$UFW_SH" "usr/share/hardn/tools/ufw.sh ships"

tap_plan 6

# U1: no unconditional 'allow in <port>/tcp' for the API or dashboard.
# We use word-boundary grep to avoid matching the CIDR-scoped form
# 'allow from X.X.X.X to any port 8000'.
if grep -qE '^[[:space:]]*ufw[[:space:]]+allow[[:space:]]+in[[:space:]]+8000(/tcp)?\b' "$UFW_SH"; then
    tap_not_ok "ufw.sh must not unconditionally 'allow in 8000/tcp'"
    grep -nE 'ufw[[:space:]]+allow.*8000' "$UFW_SH" | sed 's/^/# /'
else
    tap_ok "ufw.sh has no unconditional 'allow in 8000/tcp'"
fi

if grep -qE '^[[:space:]]*ufw[[:space:]]+allow[[:space:]]+in[[:space:]]+9002(/tcp)?\b' "$UFW_SH"; then
    tap_not_ok "ufw.sh must not unconditionally 'allow in 9002/tcp'"
    grep -nE 'ufw[[:space:]]+allow.*9002' "$UFW_SH" | sed 's/^/# /'
else
    tap_ok "ufw.sh has no unconditional 'allow in 9002/tcp'"
fi

# U2: the opt-in env vars are read.
if grep -qE 'HARDN_REMOTE_API_CIDRS' "$UFW_SH"; then
    tap_ok "ufw.sh consults HARDN_REMOTE_API_CIDRS for opt-in remote API access"
else
    tap_not_ok "ufw.sh must read HARDN_REMOTE_API_CIDRS"
fi

if grep -qE 'HARDN_REMOTE_DASHBOARD_CIDRS' "$UFW_SH"; then
    tap_ok "ufw.sh consults HARDN_REMOTE_DASHBOARD_CIDRS for opt-in remote dashboard access"
else
    tap_not_ok "ufw.sh must read HARDN_REMOTE_DASHBOARD_CIDRS"
fi

# U3: the opt-in path uses CIDR-scoped 'allow from X to any port Y'.
if grep -qE 'ufw[[:space:]]+allow[[:space:]]+from[[:space:]].*to[[:space:]]+any[[:space:]]+port[[:space:]]+8000' "$UFW_SH"; then
    tap_ok "ufw.sh opt-in path uses CIDR-scoped 'allow from ... to any port 8000'"
else
    tap_not_ok "ufw.sh opt-in path must use 'ufw allow from <cidr> to any port 8000'"
fi

if grep -qE 'ufw[[:space:]]+allow[[:space:]]+from[[:space:]].*to[[:space:]]+any[[:space:]]+port[[:space:]]+9002' "$UFW_SH"; then
    tap_ok "ufw.sh opt-in path uses CIDR-scoped 'allow from ... to any port 9002'"
else
    tap_not_ok "ufw.sh opt-in path must use 'ufw allow from <cidr> to any port 9002'"
fi

tap_summary
