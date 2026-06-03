#!/bin/bash
# Verify hardn-uninstall.sh KNOWS about every cleanup path from PR-A
# and PR-E. We grep the script's source rather than running --dry-run
# because dry-run only emits actions for files that actually exist on
# the host, which makes a portable test brittle.
#
# A second, separate assertion runs --dry-run --yes (root) and just
# confirms the script exits 0.

set -u

HARDN_TEST_NAME="integration/uninstall-dryrun"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"
UNINSTALL="$REPO_ROOT/usr/share/hardn/scripts/hardn-uninstall.sh"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

assert_file_exists "$UNINSTALL" "uninstall script ships at the expected path"

tap_plan 10

# Source-grep: the script knows about each cleanup path.
expected_paths=(
    "/etc/profile.d/hardn-paths.sh"
    "hardn-gui.desktop"
    "/etc/audit/auditd.conf.d/99-hardn.conf"
    "/etc/fail2ban/jail.local"
    "/var/lib/hardn"
    "/var/log/hardn"
    "/etc/hardn"
    "/run/hardn"
    "99-hardn-hardening"
)
for p in "${expected_paths[@]}"; do
    if grep -qF -- "$p" "$UNINSTALL"; then
        tap_ok "uninstall.sh references $p"
    else
        tap_not_ok "uninstall.sh references $p"
    fi
done

# Runtime check: dry-run still exits 0. Needs root because the script
# refuses to run as non-root before printing anything else.
if [ "$(id -u)" -eq 0 ]; then
    if "$UNINSTALL" --dry-run --yes >/dev/null 2>&1; then
        tap_ok "dry-run exits 0"
    else
        tap_not_ok "dry-run exits 0"
    fi
else
    tap_skip "dry-run exit-code check needs root"
fi

tap_summary
