#!/bin/bash
# parse_pwquality_line must populate every pam_pwquality option from a
# realistic PAM line, including the ones whose key contains a 't'
# (dcredit/ucredit/lcredit/ocredit/retry). Regression guard for the strtok
# delimiter bug that split tokens on 't' and dropped those options.

set -u

HARDN_TEST_NAME="unit/pwquality-parse"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

require_cmd cc "install a C compiler"

SRC="$REPO_ROOT/tests/unit/pwquality_parse_test.c"
if [ ! -f "$SRC" ]; then
    tap_plan 1
    tap_not_ok "pwquality_parse_test.c missing"
    tap_summary
    exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if ! cc -std=c11 -O1 -w "$SRC" -o "$WORK/t" 2>"$WORK/build.log"; then
    tap_plan 1
    tap_not_ok "pwquality parse test failed to compile"
    sed 's/^/# /' "$WORK/build.log" | head -20
    tap_summary
    exit 1
fi

out="$("$WORK/t")"
val() { printf '%s\n' "$out" | sed -n "s/^$1=//p"; }

tap_plan 8

assert_eq "1"  "$(val found)"    "line recognized as a pam_pwquality rule"
assert_eq "3"  "$(val retry)"    "retry parsed (key contains 't')"
assert_eq "12" "$(val minlen)"   "minlen parsed"
assert_eq "-1" "$(val dcredit)"  "dcredit parsed (key contains 't')"
assert_eq "-2" "$(val ucredit)"  "ucredit parsed (key contains 't')"
assert_eq "-1" "$(val lcredit)"  "lcredit parsed (key contains 't')"
assert_eq "-1" "$(val ocredit)"  "ocredit parsed (key contains 't')"
assert_eq "4"  "$(val minclass)" "minclass parsed"

tap_summary
