#!/bin/bash
# Regression guards for systemd-unit stability invariants. Each test
# pins one specific posture-bug we have already shipped a fix for, so
# any future change that drifts back into it fails CI fast.
#
# Audit traceability (post-PR-183 stability sweep):
#   S2: legion-daemon.service must NOT chmod /var/lib/hardn back to 0755
#       (would strip the setgid bit postinst sets, breaking the hardn
#       group's write access)
#   S3: hardn-monitor.service must NOT list legion-daemon.service in
#       After= or Wants= (would trigger transient activation that
#       Conflicts= with hardn.service)
#
# These suites assume the tests/lib helpers and run under tests/run-all.sh.

set -u

HARDN_TEST_NAME="static/systemd-unit-safety"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"
UNIT_DIR="$REPO_ROOT/systemd"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

assert_file_exists "$UNIT_DIR/hardn-monitor.service" "hardn-monitor.service ships"
assert_file_exists "$UNIT_DIR/legion-daemon.service" "legion-daemon.service ships"
assert_file_exists "$UNIT_DIR/hardn.service" "hardn.service ships"
assert_file_exists "$UNIT_DIR/hardn-api.service" "hardn-api.service ships"

tap_plan 6

# S3: hardn-monitor.service must not list legion-daemon as a dep.
# Walk the [Unit] section only; comments and other sections are fine.
hm_unit_section=$(awk '/^\[Unit\]/{p=1;next} /^\[/{p=0} p' "$UNIT_DIR/hardn-monitor.service")
if printf '%s' "$hm_unit_section" | grep -qE '^(After|Wants|Requires|BindsTo)=.*legion-daemon'; then
    tap_not_ok "hardn-monitor.service [Unit] section must not depend on legion-daemon"
    tap_diag "Found a dep on legion-daemon in [Unit]. Transient activation will Conflicts= with hardn.service."
    printf '%s\n' "$hm_unit_section" | grep -nE '^(After|Wants|Requires|BindsTo)=' | while IFS= read -r line; do
        tap_diag "  $line"
    done
else
    tap_ok "hardn-monitor.service [Unit] does not depend on legion-daemon"
fi

# S2: legion-daemon.service ExecStartPre must not strip the setgid bit
# from /var/lib/hardn. Mode 2770 keeps it; 755 strips it.
if grep -E '^ExecStartPre=.*chmod[[:space:]]+(0?755|0?770|0?775)\b' "$UNIT_DIR/legion-daemon.service" >/dev/null 2>&1; then
    tap_not_ok "legion-daemon.service ExecStartPre must not chmod /var/lib/hardn to a non-setgid mode"
    grep -nE '^ExecStartPre=.*chmod' "$UNIT_DIR/legion-daemon.service" | while IFS= read -r line; do
        tap_diag "  $line"
    done
else
    tap_ok "legion-daemon.service preserves the setgid bit on /var/lib/hardn"
fi

# Sanity: hardn.service still declares the Conflicts= with legion-daemon.
# This is what keeps the two mutually exclusive; if it ever vanishes,
# both can run concurrently and the SQLite baseline DB races.
if grep -qE '^Conflicts=.*legion-daemon\.service' "$UNIT_DIR/hardn.service"; then
    tap_ok "hardn.service still declares Conflicts=legion-daemon.service"
else
    tap_not_ok "hardn.service must keep Conflicts=legion-daemon.service"
fi

# Sanity: hardn-api.service still gates start on /etc/hardn/authorized_keys
# (the ExecStartPre that PR-183's Makefile change relies on).
if grep -qE '^ExecStartPre=.*/etc/hardn/authorized_keys' "$UNIT_DIR/hardn-api.service"; then
    tap_ok "hardn-api.service still gates start on /etc/hardn/authorized_keys"
else
    tap_not_ok "hardn-api.service must gate start on /etc/hardn/authorized_keys"
fi

tap_summary
