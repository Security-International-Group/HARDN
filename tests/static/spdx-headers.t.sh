#!/bin/bash
# Pre-push regression guard: every Rust source file carries an SPDX
# license identifier.
#
# The audit noted zero SPDX headers across the Rust tree, which makes
# per-file license provenance hard to track in forks and downstream
# redistribution. This guard requires each src/**/*.rs to declare its
# license on the first line so a new file without the header trips CI.
#
# Invariant:
#
#   X1  Every tracked src/**/*.rs file has
#       '// SPDX-License-Identifier: MIT' as its first line.

set -u

HARDN_TEST_NAME="static/spdx-headers"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/.." && pwd)"

# shellcheck source=../lib/assert.sh
source "$SUITE_DIR/lib/assert.sh"

SPDX_LINE='// SPDX-License-Identifier: MIT'

mapfile -t rs_files < <(find "$REPO_ROOT/src" -type f -name '*.rs' | sort)

# One assertion for the aggregate result keeps the plan stable as files
# are added; individual offenders are listed as diagnostics.
tap_plan 1

missing=()
for f in "${rs_files[@]}"; do
    first=$(head -n1 "$f")
    if [ "$first" != "$SPDX_LINE" ]; then
        missing+=("${f#"$REPO_ROOT"/}")
    fi
done

if [ "${#missing[@]}" -eq 0 ]; then
    tap_ok "all ${#rs_files[@]} src/**/*.rs files start with '$SPDX_LINE'"
else
    tap_not_ok "${#missing[@]} of ${#rs_files[@]} src/**/*.rs files lack the SPDX header on line 1"
    for m in "${missing[@]}"; do
        tap_diag "$m"
    done
fi

tap_summary
