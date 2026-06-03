#!/bin/bash
# Compile-check every Python source under src/. Catches syntax regressions
# that 'python3 -m py_compile' would flag, without importing the modules
# (so missing third-party deps like fastapi don't false-fail the suite).

set -u

HARDN_TEST_NAME="static/python-syntax"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

require_cmd python3 "install python3"

mapfile -t pys < <(find "$REPO_ROOT/src" -type f -name '*.py' 2>/dev/null | sort)

if [ "${#pys[@]}" -eq 0 ]; then
    tap_plan 1
    tap_skip "no python files under src/"
    tap_summary
    exit 0
fi

tap_plan "${#pys[@]}"

for py in "${pys[@]}"; do
    rel="${py#"$REPO_ROOT"/}"
    if output=$(python3 -m py_compile "$py" 2>&1); then
        tap_ok "$rel"
    else
        tap_not_ok "$rel"
        while IFS= read -r line; do tap_diag "$line"; done <<< "$output"
    fi
done

tap_summary
