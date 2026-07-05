#!/bin/bash
# Pre-push regression guard: shipped units carry a hardening baseline.
#
# The audit found all four units at systemd-analyze exposure ~8.5
# ("EXPOSED") with only the floor directives (NoNewPrivileges,
# ProtectSystem=strict, ProtectHome, PrivateTmp). This guard locks in
# the ceiling directives and an exposure-score budget so a future edit
# cannot silently drop the hardening.
#
# Tuning rationale (why not identical across units):
#   - hardn.service and legion-daemon.service can run LEGION in
#     --response-enabled mode, which needs privileged syscalls
#     (firewall edits, killing processes). They therefore do NOT set a
#     SystemCallFilter that strips @privileged; their budget is looser.
#   - hardn-monitor.service and hardn-api.service take no privileged
#     response actions, so they add SystemCallFilter=@system-service and
#     reach a lower score.
#   - No unit sets ProtectProc=invisible / ProcSubset=pid: these daemons
#     inspect OTHER processes, and hiding /proc would blind them.
#
# Invariants:
#
#   H1  Every unit declares the read-safe ceiling directives:
#       ProtectKernelTunables, ProtectKernelModules, ProtectControlGroups,
#       RestrictNamespaces, RestrictRealtime, RestrictSUIDSGID,
#       LockPersonality, RestrictAddressFamilies.
#
#   H2  No unit sets ProtectProc=invisible or ProcSubset=pid (would
#       break process monitoring).
#
#   H3  Each unit's offline exposure score is at or below its budget.

set -u

HARDN_TEST_NAME="static/systemd-hardening"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

require_cmd systemd-analyze "install with: apt-get install systemd"

UNIT_DIR="$REPO_ROOT/systemd"

# Per-unit exposure budget (systemd-analyze security --offline). The
# response-capable daemons keep privileged syscalls so they sit higher.
declare -A BUDGET=(
    [hardn.service]=6.0
    [legion-daemon.service]=6.0
    [hardn-monitor.service]=5.0
    [hardn-api.service]=5.0
)

REQUIRED_DIRECTIVES=(
    ProtectKernelTunables
    ProtectKernelModules
    ProtectControlGroups
    RestrictNamespaces
    RestrictRealtime
    RestrictSUIDSGID
    LockPersonality
    RestrictAddressFamilies
)

mapfile -t units < <(find "$UNIT_DIR" -type f -name '*.service' | sort)

# Plan: for each unit -> 1 directives assertion + 1 no-ProtectProc +
# 1 score assertion.
tap_plan $(( ${#units[@]} * 3 ))

for u in "${units[@]}"; do
    base=$(basename "$u")

    # H1: required directives present.
    missing=""
    for d in "${REQUIRED_DIRECTIVES[@]}"; do
        if ! grep -qE "^${d}=" "$u"; then
            missing="$missing $d"
        fi
    done
    if [ -z "$missing" ]; then
        tap_ok "$base declares the read-safe ceiling directives"
    else
        tap_not_ok "$base is missing hardening directives:$missing"
    fi

    # H2: must not blind itself to other processes.
    if grep -qE '^(ProtectProc=invisible|ProcSubset=pid)' "$u"; then
        tap_not_ok "$base must not set ProtectProc=invisible / ProcSubset=pid (breaks process monitoring)"
    else
        tap_ok "$base does not hide /proc from itself"
    fi

    # H3: exposure budget.
    budget="${BUDGET[$base]:-6.0}"
    score=$(systemd-analyze security --offline=true "$u" 2>/dev/null \
        | grep -iE 'Overall exposure' \
        | grep -oE '[0-9]+\.[0-9]+' | head -1)
    if [ -z "$score" ]; then
        tap_not_ok "$base: could not read exposure score from systemd-analyze"
    elif awk -v s="$score" -v b="$budget" 'BEGIN{exit !(s+0 <= b+0)}'; then
        tap_ok "$base exposure $score is within budget $budget"
    else
        tap_not_ok "$base exposure $score exceeds budget $budget"
    fi
done

tap_summary
