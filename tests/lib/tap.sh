#!/bin/bash
# TAP-style output helpers for HARDN tests.
#
# Each test file sources this and emits ok/not ok/skip lines. The
# orchestrator (tests/run-all.sh) parses each suite's output and rolls
# up totals into the markdown report under tests/reports/.

# Internal counters, scoped to the sourcing script.
__HARDN_TEST_COUNT=0
__HARDN_TEST_PASS=0
__HARDN_TEST_FAIL=0
__HARDN_TEST_SKIP=0
__HARDN_TEST_NAME="${HARDN_TEST_NAME:-$(basename "${BASH_SOURCE[1]:-}" .t.sh)}"

tap_plan() {
    local n="$1"
    printf '1..%d\n' "$n"
}

tap_ok() {
    __HARDN_TEST_COUNT=$((__HARDN_TEST_COUNT + 1))
    __HARDN_TEST_PASS=$((__HARDN_TEST_PASS + 1))
    printf 'ok %d - %s\n' "$__HARDN_TEST_COUNT" "$*"
}

tap_not_ok() {
    __HARDN_TEST_COUNT=$((__HARDN_TEST_COUNT + 1))
    __HARDN_TEST_FAIL=$((__HARDN_TEST_FAIL + 1))
    printf 'not ok %d - %s\n' "$__HARDN_TEST_COUNT" "$*"
}

tap_skip() {
    __HARDN_TEST_COUNT=$((__HARDN_TEST_COUNT + 1))
    __HARDN_TEST_SKIP=$((__HARDN_TEST_SKIP + 1))
    printf 'ok %d - # SKIP %s\n' "$__HARDN_TEST_COUNT" "$*"
}

tap_diag() {
    # Diagnostic output, prefixed with '# ' so TAP parsers ignore it.
    while IFS= read -r line; do
        printf '# %s\n' "$line"
    done <<< "$*"
}

tap_summary() {
    # Always print a footer with the counts so the orchestrator can grep.
    printf '# %s totals: total=%d pass=%d fail=%d skip=%d\n' \
        "$__HARDN_TEST_NAME" \
        "$__HARDN_TEST_COUNT" \
        "$__HARDN_TEST_PASS" \
        "$__HARDN_TEST_FAIL" \
        "$__HARDN_TEST_SKIP"
    if [ "$__HARDN_TEST_FAIL" -gt 0 ]; then
        return 1
    fi
    return 0
}
