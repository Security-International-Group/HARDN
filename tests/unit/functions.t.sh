#!/bin/bash
# Unit tests for usr/share/hardn/tools/functions.sh.
#
# Focuses on the HARDN_STATUS no-color-on-non-TTY behaviour (PR-A),
# which has been a quiet source of "garbage in log file" bugs in the
# past. Also exercises the distro detection helpers.

set -u

HARDN_TEST_NAME="unit/functions"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"
FUNCTIONS_SH="$REPO_ROOT/usr/share/hardn/tools/functions.sh"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

assert_file_exists "$FUNCTIONS_SH" "functions.sh ships at the expected path"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Override HARDN_LOG_FILE so the test can't touch /var/log/hardn.
LOG="$TMP/test.log"

tap_plan 5

# 1. HARDN_STATUS writes to the log file when invoked from a non-TTY.
# functions.sh hard-codes HARDN_LOG_FILE at the top of the file, so the
# override has to happen AFTER the source.
bash -c "
    source '$FUNCTIONS_SH'
    HARDN_LOG_FILE='$LOG'
    HARDN_STATUS info 'hello from a pipe'
" >/dev/null 2>&1
assert_file_contains "$LOG" "hello from a pipe" "log line written through HARDN_STATUS"

# 2. The log line MUST NOT contain raw ANSI escape codes when stdout isn't
#    a TTY (PR-A invariant: log files stay clean).
if grep -qP '\x1b\[' "$LOG" 2>/dev/null; then
    tap_not_ok "log file is free of ANSI escape codes"
    tap_diag "found CSI sequence in: $LOG"
else
    tap_ok "log file is free of ANSI escape codes"
fi

# 3. detect_distro_id returns a non-empty string.
result=$(bash -c "source '$FUNCTIONS_SH'; detect_distro_id" 2>&1)
assert_ne "" "$result" "detect_distro_id returns non-empty"

# 4. detect_distro_version returns a non-empty string.
result=$(bash -c "source '$FUNCTIONS_SH'; detect_distro_version" 2>&1)
assert_ne "" "$result" "detect_distro_version returns non-empty"

# 5. is_package_installed for a clearly nonexistent package returns non-zero.
bash -c "source '$FUNCTIONS_SH'; is_package_installed hardn-no-such-package-XYZ123 && exit 0 || exit 99" >/dev/null 2>&1
assert_eq "99" "$?" "is_package_installed correctly returns false for a missing package"

tap_summary
