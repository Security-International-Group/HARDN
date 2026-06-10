#!/bin/bash
# Regression guard for ISSUE-180 follow-up. The hardn-internal Makefile
# target used to do:
#
#   systemctl enable --now hardn.service hardn-api.service \
#                          legion-daemon.service hardn-monitor.service
#
# Two real bugs sat on that single line:
#
#   1. legion-daemon.service is the mutually-exclusive variant of
#      hardn.service (hardn.service has Conflicts=legion-daemon.service)
#      and debian/postinst explicitly disables it. The Makefile must NOT
#      re-enable it during a 'make hardn' run.
#
#   2. hardn-api.service refuses to start when /etc/hardn/authorized_keys
#      is empty (this is correct, by design). enable --now on a fresh
#      install prints a scary "Job for hardn-api failed" before the
#      operator has had a chance to register a key. The Makefile must
#      guard the start behind a key-presence check.
#
# This suite greps the Makefile to lock both invariants in.

set -u

HARDN_TEST_NAME="static/makefile-install-safety"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"
MAKEFILE="$REPO_ROOT/Makefile"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

assert_file_exists "$MAKEFILE" "Makefile ships at the repo root"

tap_plan 4

# 1. legion-daemon must NOT be a target of 'enable --now' in the Makefile.
#    The exact wording catches both the original buggy line and any
#    future variant that pulls legion-daemon into the same enable call.
if grep -nE 'systemctl[[:space:]]+enable[[:space:]]+--now[[:space:]]+[^|]*legion-daemon' "$MAKEFILE" >/tmp/.hardn_mf_lines 2>&1; then
    tap_not_ok "Makefile must not 'systemctl enable --now legion-daemon'"
    while IFS= read -r line; do tap_diag "$line"; done < /tmp/.hardn_mf_lines
else
    tap_ok "Makefile does not 'systemctl enable --now legion-daemon'"
fi
rm -f /tmp/.hardn_mf_lines

# 2. hardn-api start path must be gated on /etc/hardn/authorized_keys.
#    We don't pin the exact phrasing -- any check that mentions the file
#    near a hardn-api 'enable --now' counts as guarded.
if grep -c '/etc/hardn/authorized_keys' "$MAKEFILE" >/dev/null 2>&1; then
    tap_ok "Makefile references /etc/hardn/authorized_keys (start gate)"
else
    tap_not_ok "Makefile references /etc/hardn/authorized_keys (start gate)"
    tap_diag "Expected: the hardn-api enable+start block to mention the keys file"
fi

# 3. hardn.service and hardn-monitor.service are still enabled+started
#    on a normal install. Don't accidentally drop them along with the fix.
if grep -E 'systemctl[[:space:]]+enable[[:space:]]+--now[[:space:]]+hardn\.service' "$MAKEFILE" >/dev/null 2>&1; then
    tap_ok "Makefile still enables+starts hardn.service"
else
    tap_not_ok "Makefile still enables+starts hardn.service"
fi

if grep -E 'systemctl[[:space:]]+enable[[:space:]]+--now[[:space:]]+[^|]*hardn-monitor\.service' "$MAKEFILE" >/dev/null 2>&1; then
    tap_ok "Makefile still enables+starts hardn-monitor.service"
else
    tap_not_ok "Makefile still enables+starts hardn-monitor.service"
fi

tap_summary
