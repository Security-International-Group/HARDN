#!/bin/bash
# Shellcheck every HARDN shell script. Soft-fails on warnings (-S error)
# so we catch real bugs without arguing about style. Skips cleanly when
# the shellcheck binary is absent.

set -u

HARDN_TEST_NAME="static/shellcheck"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

require_cmd shellcheck "install with: apt-get install shellcheck"

mapfile -t scripts < <(find "$REPO_ROOT/usr/share/hardn" "$REPO_ROOT/tests" \
    -type f -name '*.sh' 2>/dev/null | sort)

tap_plan "${#scripts[@]}"

for script in "${scripts[@]}"; do
    rel="${script#"$REPO_ROOT"/}"
    # -S error: only fail on real errors. Style warnings stay informational.
    if output=$(shellcheck -S error -x "$script" 2>&1); then
        tap_ok "$rel"
    else
        tap_not_ok "$rel"
        while IFS= read -r line; do tap_diag "$line"; done <<< "$output"
    fi
done

tap_summary
