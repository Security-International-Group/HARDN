#!/bin/bash
# Assertion helpers built on top of lib/tap.sh.
#
# Convention: every assert_* takes a final argument describing the test;
# on failure the actual vs expected is printed as a TAP diagnostic.

# shellcheck source-path=.
source "$(dirname "${BASH_SOURCE[0]}")/tap.sh"

assert_eq() {
    local expected="$1" actual="$2" desc="$3"
    if [ "$expected" = "$actual" ]; then
        tap_ok "$desc"
    else
        tap_not_ok "$desc"
        tap_diag "expected: $expected"
        tap_diag "actual:   $actual"
    fi
}

assert_ne() {
    local left="$1" right="$2" desc="$3"
    if [ "$left" != "$right" ]; then
        tap_ok "$desc"
    else
        tap_not_ok "$desc"
        tap_diag "both values were: $left"
    fi
}

assert_exit() {
    local expected="$1"; shift
    local desc="$1"; shift
    local actual
    "$@" >/dev/null 2>&1
    actual=$?
    if [ "$expected" = "$actual" ]; then
        tap_ok "$desc"
    else
        tap_not_ok "$desc"
        tap_diag "expected exit: $expected"
        tap_diag "actual exit:   $actual"
        tap_diag "command:       $*"
    fi
}

assert_contains() {
    local haystack="$1" needle="$2" desc="$3"
    if printf '%s' "$haystack" | grep -qF -- "$needle"; then
        tap_ok "$desc"
    else
        tap_not_ok "$desc"
        tap_diag "expected substring: $needle"
        tap_diag "haystack (first 200 chars): ${haystack:0:200}"
    fi
}

assert_file_exists() {
    local path="$1" desc="$2"
    if [ -e "$path" ]; then
        tap_ok "$desc"
    else
        tap_not_ok "$desc"
        tap_diag "missing path: $path"
    fi
}

assert_file_contains() {
    local path="$1" needle="$2" desc="$3"
    if [ ! -e "$path" ]; then
        tap_not_ok "$desc"
        tap_diag "file does not exist: $path"
        return
    fi
    if grep -qF -- "$needle" "$path"; then
        tap_ok "$desc"
    else
        tap_not_ok "$desc"
        tap_diag "expected substring: $needle"
        tap_diag "file:               $path"
    fi
}

require_cmd() {
    # Use from the top of a test to mark the whole suite as skipped when a
    # prerequisite is missing.
    local cmd="$1" reason="${2:-required tool not available}"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        tap_skip "${HARDN_TEST_NAME:-suite}: $reason ($cmd not found)"
        tap_summary
        exit 0
    fi
}
